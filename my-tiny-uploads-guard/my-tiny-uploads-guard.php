<?php

/**
 * Plugin Name:       My Tiny Uploads Guard
 * Plugin URI:        https://github.com/tonnychiulab/my-tiny-uploads-guard
 * Description:       A lightweight, non-intrusive security guard for your uploads directory. Detects hidden PHP files and suspicious directories using a smart async scanning engine.
 * Version:           1.0.28
 * Author:            Tonny Chiu Lab
 * Author URI:        https://github.com/tonnychiulab
 * Text Domain:       my-tiny-uploads-guard
 * Domain Path:       /languages
 * Requires at least: 6.0
 * Requires PHP:      7.4
 */

if (! defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/**
 * Main Plugin Class
 *
 * @package My_Tiny_Uploads_Guard
 */
final class My_Tiny_Uploads_Guard
{

    /**
     * Plugin Version
     *
     * @var string
     */
    const VERSION = '1.0.28';

    /**
     * Instance of this class.
     *
     * @var My_Tiny_Uploads_Guard
     */
    private static $instance;

    /**
     * Get the singleton instance.
     *
     * @return My_Tiny_Uploads_Guard
     */
    public static function get_instance()
    {
        if (! isset(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor.
     */
    private function __construct()
    {
        $this->define_constants();
        $this->init_hooks();
    }

    /**
     * Define Plugin Constants.
     */
    private function define_constants()
    {
        define('MTUG_VERSION', self::VERSION);
        define('MTUG_PLUGIN_DIR', plugin_dir_path(__FILE__));
        define('MTUG_PLUGIN_URL', plugin_dir_url(__FILE__));
        define('MTUG_PLUGIN_BASENAME', plugin_basename(__FILE__));
    }

    /**
     * Initialize Hooks.
     */
    private function init_hooks()
    {
        // Autoload Classes
        spl_autoload_register(array($this, 'autoload'));

        add_action('plugins_loaded', array($this, 'load_textdomain'));
        add_action('admin_menu', array($this, 'register_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));

        // AJAX Hooks
        add_action('wp_ajax_mtug_scan', array($this, 'ajax_handle_scan'));
        add_action('wp_ajax_mtug_delete_file', array($this, 'ajax_handle_delete'));
        add_action('wp_ajax_mtug_update_stats', array($this, 'ajax_handle_update_stats'));
    }

    /**
     * Autoloader for plugin classes.
     *
     * @param string $class Class name.
     */
    public function autoload($class)
    {
        if (strpos($class, 'My_Tiny_Uploads_Guard') === false) {
            return;
        }

        $file = str_replace(
            array('My_Tiny_Uploads_Guard\\', '\\'),
            array('', DIRECTORY_SEPARATOR),
            $class
        );

        $path = MTUG_PLUGIN_DIR . 'includes' . DIRECTORY_SEPARATOR . $file . '.php';

        if (file_exists($path)) {
            require_once $path;
        }
    }

    /**
     * Load Text Domain for i18n.
     */
    public function load_textdomain()
    {
        load_plugin_textdomain(
            'my-tiny-uploads-guard',
            false,
            dirname(plugin_basename(__FILE__)) . '/languages'
        );
    }

    /**
     * Register Admin Menu.
     */
    public function register_admin_menu()
    {
        add_menu_page(
            __('My Tiny Uploads Guard', 'my-tiny-uploads-guard'),
            __('My Tiny Uploads Guard', 'my-tiny-uploads-guard'),
            'manage_options',
            'my-tiny-uploads-guard',
            array($this, 'render_admin_page'),
            'dashicons-shield',
            99
        );
    }

    /**
     * Enqueue Admin Scripts.
     */
    public function enqueue_admin_scripts($hook)
    {
        if ('toplevel_page_my-tiny-uploads-guard' !== $hook) {
            return;
        }

        wp_enqueue_style('mtug-admin-css', MTUG_PLUGIN_URL . 'assets/css/admin.css', array(), MTUG_VERSION);
        wp_enqueue_script('mtug-admin-js', MTUG_PLUGIN_URL . 'assets/js/admin.js', array('jquery'), MTUG_VERSION, true);

        $upload_dir = wp_upload_dir();

        wp_localize_script('mtug-admin-js', 'mtugObj', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('mtug_scan_nonce'),
            'uploadBasedir' => $upload_dir['basedir'],
            'strings' => array(
                'scanning' => __('Scanning... ', 'my-tiny-uploads-guard'),
                'complete' => __('Scan Complete!', 'my-tiny-uploads-guard'),
                'error'    => __('Error occurred.', 'my-tiny-uploads-guard'),
                'delete'   => __('Delete', 'my-tiny-uploads-guard'),
                'confirm'  => __('Are you sure you want to delete this file?', 'my-tiny-uploads-guard'),
            ),
        ));
    }

    /**
     * AJAX Handler for Scanning.
     */
    public function ajax_handle_scan()
    {
        check_ajax_referer('mtug_scan_nonce', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(__('Unauthorized', 'my-tiny-uploads-guard'));
        }

        $offset = isset($_POST['offset']) ? absint($_POST['offset']) : 0;

        $scanner = new \My_Tiny_Uploads_Guard\Scanner\Async_Key_Scanner();
        $result  = $scanner->scan_batch($offset);

        wp_send_json_success($result);
    }

    /**
     * AJAX Handler for Deletion.
     */
    public function ajax_handle_delete()
    {
        check_ajax_referer('mtug_scan_nonce', 'nonce');

        $current_user = wp_get_current_user();
        if (! current_user_can('manage_options')) {
            $this->log_audit_trail('DELETE_ATTEMPT', 'Unauthorized access', false);
            wp_send_json_error(__('Unauthorized', 'my-tiny-uploads-guard'));
        }

        $file_path = isset($_POST['file']) ? sanitize_text_field($_POST['file']) : '';

        // Security Check: Must be in uploads directory
        $upload_dir = wp_upload_dir();
        $base_dir   = $upload_dir['basedir'];

        // [Security - 原理教學]
        // 1. 這裡非常重要！我們必須把路徑「標準化」。
        //    為什麼？因為駭客可能會用 "../../../wp-config.php" 這種技巧來騙我們去刪除系統檔案。
        //    realpath() 會把這些 "../" 全部解開，變成真正的絕對路徑，讓我們可以放心比對。
        $real_base = realpath($base_dir);
        $real_file = realpath($file_path);

        if (! $real_file || ! file_exists($real_file)) {
            $this->log_audit_trail('DELETE_FAIL', $file_path, false, 'File not found');
            wp_send_json_error(__('File not found.', 'my-tiny-uploads-guard'));
        }

        // [Security - 範圍檢查]
        // 2. 這是我們的第二道防線。我們檢查「檔案的真實路徑」是否「包含」了「上傳目錄的路徑」。
        //    如果 $real_file 不以 $real_base 開頭，就代表這個檔案跑到上傳目錄外面去了！
        if (strpos($real_file, $real_base) !== 0) {
            $this->log_audit_trail('DELETE_FAIL', $file_path, false, 'Security violation: Outside uploads dir');
            wp_send_json_error(__('Security Error: Cannot delete files outside uploads directory.', 'my-tiny-uploads-guard'));
        }

        // Proceed to delete
        // [PHP Trick] 前面加 @ 符號是用來「閉嘴」的，如果刪除失敗不要噴出 PHP 錯誤訊息，
        // 我們自己用 if/else 來處理錯誤就好。
        if (@unlink($real_file)) {
            $this->log_audit_trail('DELETE_SUCCESS', $real_file, true);
            wp_send_json_success(__('File deleted.', 'my-tiny-uploads-guard'));
        } else {
            $this->log_audit_trail('DELETE_FAIL', $real_file, false, 'Permission denied or IO error');
            wp_send_json_error(__('Could not delete file. Check permissions.', 'my-tiny-uploads-guard'));
        }
    }

    /**
     * AJAX Handler for Updating Stats.
     */
    public function ajax_handle_update_stats()
    {
        check_ajax_referer('mtug_scan_nonce', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error(__('Unauthorized', 'my-tiny-uploads-guard'));
        }

        $status = isset($_POST['status']) ? sanitize_text_field($_POST['status']) : 'safe';
        $count  = isset($_POST['count']) ? absint($_POST['count']) : 0;
        $timestamp = current_time('mysql');

        update_option('mtug_option_scan_status', $status);
        update_option('mtug_option_scan_count', $count);
        update_option('mtug_option_last_scan', $timestamp);

        wp_send_json_success(array('timestamp' => $timestamp));
    }

    /**
     * Log Audit Trail.
     * 
     * @param string $action   The action performed (e.g., DELETE_SUCCESS).
     * @param string $target   The target file or path.
     * @param bool   $success  Whether the action was successful.
     * @param string $note     Optional extra details.
     */
    private function log_audit_trail($action, $target, $success = true, $note = '')
    {
        $upload_dir = wp_upload_dir();
        $log_dir    = $upload_dir['basedir'] . '/mtug-logs';
        $log_file   = $log_dir . '/my-tiny-uploads-guard-audit.log';

        // 1. Ensure Log Directory Exists
        if (! file_exists($log_dir)) {
            wp_mkdir_p($log_dir);

            // [Security - Apache 防護]
            // 2. 這裡我們新增了 .htaccess 檔案。
            //    它的作用是告訴 Apache 伺服器：「不管是誰，都不准從瀏覽器直接讀取這個資料夾裡的檔案！」
            //    為了相容舊版 (2.2) 和新版 (2.4) Apache，我們兩著寫法都加上去。
            $htaccess_file = $log_dir . '/.htaccess';
            if (! file_exists($htaccess_file)) {
                $rules = "# Apache 2.2\n<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>\n\n# Apache 2.4\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>";
                file_put_contents($htaccess_file, $rules);
            }

            // [Security - 沉默是金]
            // 如果有人試圖列出目錄 (Directory Listing)，這個空的 index.php 會讓他們只看到一片空白，
            // 而不是滿滿的 Log 檔案列表。
            if (! file_exists($log_dir . '/index.php')) {
                file_put_contents($log_dir . '/index.php', '<?php // Silence is golden.');
            }
        }

        // 3. Prepare Log Entry
        $current_user = wp_get_current_user();
        $user_login   = $current_user->exists() ? $current_user->user_login : 'unknown_user';
        $user_id      = $current_user->exists() ? $current_user->ID : 0;

        // [Security - 抓出藏鏡人]
        // 很多駭客會用 Proxy (代理伺服器) 來隱藏自己。
        // REMOTE_ADDR 是直接連線的 IP (可能是 Proxy)。
        // HTTP_X_FORWARDED_FOR 是 Proxy 幫忙傳送的「原始 IP」。
        // 我們兩個都記下來，這樣就算他用跳板，也可能露出馬腳。
        $direct_ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '0.0.0.0';
        $proxy_ip  = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? sanitize_text_field($_SERVER['HTTP_X_FORWARDED_FOR']) : '';

        $ip_info = $direct_ip;
        if (!empty($proxy_ip)) {
            $ip_info .= " (Forwarded: $proxy_ip)";
        }

        $timestamp = current_time('mysql'); // Local WP time
        $status    = $success ? 'SUCCESS' : 'FAILED';

        // Format: [Time] [IP] [User(ID)] [Action] [Status] [Target] [Note]
        $entry = sprintf(
            "[%s] IP:%s | User:%s(ID:%d) | Action:%s | Status:%s | Target:%s | Note:%s" . PHP_EOL,
            $timestamp,
            $ip_info,
            $user_login,
            $user_id,
            $action,
            $status,
            $target,
            $note
        );

        // 4. Append to Log
        // [Performance/Stability]
        // FILE_APPEND: 寫在檔案最後面，不要覆蓋舊的。
        // LOCK_EX: 「獨佔鎖定」。想像如果兩個人同時寫入 Log，字可能會混在一起變亂碼。
        // 這個鎖可以確保「我寫完，換你寫」，避免資料錯亂。
        @file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Get Log File Path for Display.
     * 
     * @return string
     */
    public function get_log_path()
    {
        $upload_dir = wp_upload_dir();
        return $upload_dir['basedir'] . '/mtug-logs/my-tiny-uploads-guard-audit.log';
    }

    /**
     * Render Admin Page.
     */
    public function render_admin_page()
    {
?>
        <div class="wrap mtug-wrapper">
            <div class="mtug-title-section">
                <h1><?php echo esc_html__('My Tiny Uploads Guard', 'my-tiny-uploads-guard'); ?></h1>
                <p><?php echo esc_html__('Lightweight protection for your uploads directory.', 'my-tiny-uploads-guard'); ?></p>
            </div>

            <div class="mtug-dashboard-grid">
                <!-- Left Column: Controls & Stats -->
                <div class="mtug-card mtug-controls-card">
                    <div class="mtug-header">
                        <h2><?php echo esc_html__('Scanner Control', 'my-tiny-uploads-guard'); ?></h2>
                        <?php
                        $last_status = get_option('mtug_option_scan_status', 'safe');
                        $status_class = ($last_status === 'threat_found') ? 'status-error' : 'status-ready';
                        $status_text  = ($last_status === 'threat_found') ? __('Action Needed', 'my-tiny-uploads-guard') : __('Protected', 'my-tiny-uploads-guard');
                        ?>
                        <div class="mtug-status">
                            <span id="mtug-status-text" class="<?php echo esc_attr($status_class); ?>"><?php echo esc_html($status_text); ?></span>
                        </div>
                    </div>

                    <!-- 3 Circles Dashboard -->
                    <div class="mtug-circles-grid">
                        <!-- 1. Status -->
                        <div class="mtug-circle-item">
                            <div class="mtug-circle mtug-circle-status <?php echo ($last_status === 'threat_found') ? 'threat' : 'safe'; ?>">
                                <span class="dashicons dashicons-shield"></span>
                            </div>
                            <div class="mtug-circle-label"><?php echo esc_html__('Status', 'my-tiny-uploads-guard'); ?></div>
                            <div class="mtug-circle-val" id="mtug-dash-status"><?php echo esc_html($status_text); ?></div>
                        </div>

                        <!-- 2. Scope -->
                        <?php $total_scanned = get_option('mtug_option_scan_count', 0); ?>
                        <div class="mtug-circle-item">
                            <div class="mtug-circle mtug-circle-scope">
                                <span class="dashicons dashicons-search"></span>
                            </div>
                            <div class="mtug-circle-label"><?php echo esc_html__('Monitored', 'my-tiny-uploads-guard'); ?></div>
                            <div class="mtug-circle-val" id="mtug-dash-count"><?php echo esc_html(number_format_i18n($total_scanned)); ?> Files</div>
                        </div>

                        <!-- 3. Recency -->
                        <?php
                        $last_scan = get_option('mtug_option_last_scan', '');
                        $time_diff = $last_scan ? human_time_diff(strtotime($last_scan), current_time('timestamp')) . ' ago' : 'Never';
                        ?>
                        <div class="mtug-circle-item">
                            <div class="mtug-circle mtug-circle-recency">
                                <span class="dashicons dashicons-clock"></span>
                            </div>
                            <div class="mtug-circle-label"><?php echo esc_html__('Last Scan', 'my-tiny-uploads-guard'); ?></div>
                            <div class="mtug-circle-val" id="mtug-dash-time"><?php echo esc_html($time_diff); ?></div>
                        </div>
                    </div>

                    <!-- Progress Bar (Hidden by default, shown during scan) -->
                    <div class="mtug-progress-area" style="display:none; margin-top:20px;">
                        <div class="mtug-progress-container">
                            <div id="mtug-progress-bar" style="width: 0%;"></div>
                        </div>
                        <div class="mtug-progress-stats">
                            <span id="mtug-scanned-count">0</span> <?php echo esc_html__('files scanned', 'my-tiny-uploads-guard'); ?>
                        </div>
                    </div>

                    <div class="mtug-actions" style="margin-top:20px; text-align:center;">
                        <button class="button button-primary button-large" id="mtug-start-scan">
                            <?php echo esc_html__('Start New Scan', 'my-tiny-uploads-guard'); ?>
                        </button>
                    </div>
                </div>

                <!-- Right Column: Live Stats -->
                <div class="mtug-stats-grid">
                    <!-- Info Card -->
                    <div class="mtug-card mtug-info-card" style="border-left: 4px solid #2271b1; background: #fff;">
                        <h3 style="margin-top:0; font-size:1.1em;"><?php echo esc_html__('Quick Guide', 'my-tiny-uploads-guard'); ?></h3>
                        <p style="margin-bottom:10px; color:#646970;">
                            <?php echo esc_html__('Click "Start New Scan" to detect threats in your uploads directory.', 'my-tiny-uploads-guard'); ?>
                        </p>
                        <hr style="border:0; border-top:1px solid #f0f0f1; margin: 10px 0;">
                        <h3 style="margin-top:0; font-size:1.1em;"><?php echo esc_html__('Audit Log', 'my-tiny-uploads-guard'); ?></h3>
                        <code style="display:block; background:#f0f0f1; padding:8px; border-radius:4px; font-size:0.9em; word-break:break-all; color:#2c3338;">
                            <?php echo esc_html($this->get_log_path()); ?>
                        </code>
                        <p style="margin-top:5px; font-size:0.85em; color:#646970;">
                            <?php echo esc_html__('Provide this file to your administrator for review.', 'my-tiny-uploads-guard'); ?>
                        </p>
                    </div>

                    <div class="mtug-stat-card card-suspicious-files">
                        <span class="stat-label"><?php echo esc_html__('Suspicious Files', 'my-tiny-uploads-guard'); ?></span>
                        <span class="stat-number" id="mtug-stat-files">0</span>
                    </div>
                    <div class="mtug-stat-card card-suspicious-dirs">
                        <span class="stat-label"><?php echo esc_html__('Suspicious Dirs', 'my-tiny-uploads-guard'); ?></span>
                        <span class="stat-number" id="mtug-stat-dirs">0</span>
                    </div>
                    <div class="mtug-stat-card card-safe">
                        <span class="stat-label"><?php echo esc_html__('Safe Files', 'my-tiny-uploads-guard'); ?></span>
                        <span class="stat-number" id="mtug-stat-safe">0</span>
                    </div>
                </div>
            </div>

            <div class="mtug-results-area" style="display:none;">
                <div class="mtug-results-header">
                    <div class="mtug-header-left">
                        <h3><?php echo esc_html__('Scan Results', 'my-tiny-uploads-guard'); ?></h3>
                    </div>
                    <div class="mtug-header-right" style="display:flex; gap:15px; align-items:center;">
                        <div class="mtug-search-wrapper">
                            <span class="dashicons dashicons-search"></span>
                            <input type="text" id="mtug-search-input" placeholder="<?php echo esc_attr__('Search results...', 'my-tiny-uploads-guard'); ?>">
                        </div>
                        <div class="mtug-pagination" style="display:none;">
                            <button class="button" id="mtug-page-prev">&laquo; <?php echo esc_html__('Prev', 'my-tiny-uploads-guard'); ?></button>
                            <span class="mtug-page-info">
                                <?php echo esc_html__('Page', 'my-tiny-uploads-guard'); ?> <span id="mtug-current-page">1</span> / <span id="mtug-total-pages">1</span>
                            </span>
                            <button class="button" id="mtug-page-next"><?php echo esc_html__('Next', 'my-tiny-uploads-guard'); ?> &raquo;</button>
                        </div>
                    </div>
                </div>
                <table class="widefat fixed striped" id="mtug-results-table">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="severity" style="width: 80px;"><?php echo esc_html__('Severity', 'my-tiny-uploads-guard'); ?></th>
                            <th class="sortable" data-sort="type" style="width: 150px;"><?php echo esc_html__('Type', 'my-tiny-uploads-guard'); ?></th>
                            <th class="sortable" data-sort="file"><?php echo esc_html__('Location (Relative Path)', 'my-tiny-uploads-guard'); ?></th>
                            <th class="sortable" data-sort="mtime" style="width: 160px;"><?php echo esc_html__('Date Modified', 'my-tiny-uploads-guard'); ?></th>
                            <th><?php echo esc_html__('Details', 'my-tiny-uploads-guard'); ?></th>
                            <th style="width: 80px;"><?php echo esc_html__('Action', 'my-tiny-uploads-guard'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Results will be injected here -->
                    </tbody>
                </table>
            </div>

            <!-- Debug Console -->
            <div class="mtug-debug-section" style="margin-top: 30px; border-top: 1px solid #dcdcde; padding-top: 20px;">
                <details>
                    <summary style="cursor: pointer; font-weight: 600; color: #50575e;">
                        <?php echo esc_html__('Show Activity Log (Debug)', 'my-tiny-uploads-guard'); ?>
                    </summary>
                    <div id="mtug-debug-log" style="
                        background: #f6f7f7; 
                        border: 1px solid #c3c4c7; 
                        padding: 10px; 
                        margin-top: 10px; 
                        height: 200px; 
                        overflow-y: auto; 
                        font-family: monospace; 
                        font-size: 12px; 
                        white-space: pre-wrap;
                        color: #2c3338;"></div>
                </details>
            </div>

            <div class="mtug-footer" style="text-align: right; margin-top: 20px; color: #646970; font-size: 12px;">
                <p>My Tiny Uploads Guard v<?php echo esc_html(self::VERSION); ?></p>
            </div>
        </div>
<?php
    }
}

// Initialize the plugin.
My_Tiny_Uploads_Guard::get_instance();
