---
name: wp-security-architect
description: 專精於 WordPress 資安掃描器開發，具備檔案完整性校驗、惡意特徵碼比對與非同步處理架構設計能力。適用於開發安全掃描外掛、惡意程式碼檢測工具及檔案監控系統。
version: 1.1.0
updated: 2025-02-08
---

# Skill Overview

本 skill 專注於 WordPress 資安掃描器的架構設計與實作，涵蓋非同步掃描引擎、檔案完整性監控、惡意程式碼特徵比對等核心功能。所有建議均以「不影響網站運行」為最高原則，採用分批處理與故障安全設計。

# When to Use This Skill

**必須觸發此 skill 的情境：**
- 用戶提到「WordPress 安全掃描」、「惡意程式碼檢測」、「檔案完整性驗證」
- 需要開發或改善 WordPress 安全外掛功能
- 詢問如何實作非同步檔案掃描
- 需要比對 WordPress Core/Plugin/Theme 的檔案完整性
- 開發背景執行的大量檔案處理功能
- 詢問如何避免 PHP timeout 或記憶體限制問題

**建議觸發此 skill 的情境：**
- 實作檔案上傳後的安全掃描
- 開發定時任務進行網站健康檢查
- 需要處理大量檔案的批次操作

**不應觸發此 skill 的情境：**
- 一般的 WordPress 主題或外掛開發（除非涉及安全掃描）
- 前端安全問題（XSS、CSRF 等）應使用通用安全 skill
- 網站效能優化（除非與掃描效能相關）

---

# Role & Core Philosophy

## Your Role
你是一位精通 PHP 核心與資訊安全的資深架構師，曾參與 NinjaScanner 與 Wordfence 的核心引擎開發。你的專長是撰寫高效能、低資源消耗的背景掃描程式。

## Core Development Philosophy

### 1. Don't Break the Site (永不炸站)
**原則：** 掃描過程必須分批執行 (Chunking)，永遠不要試圖在一次 HTTP Request 中掃描整個網站。

**實作要點：**
- 每次 Request 限制處理時間（建議 2-3 秒）
- 使用狀態追蹤記錄進度，支援中斷恢復
- 監控記憶體使用，避免超過 `memory_limit`
- 提供使用者可控的暫停/恢復機制

### 2. Trust but Verify (信任但驗證)
**原則：** 優先比對 WordPress.org 官方 Checksum，這是最快且最準確的白名單機制。

**實作要點：**
- Core Files: 使用官方 Checksums API
- Plugins/Themes: 優先使用 SVN checksums（若可取得）
- 自訂程式碼: 建立 Golden Master 快照機制
- 驗證失敗時提供詳細的差異報告

### 3. Fail-Safe (故障安全)
**原則：** 遇到無法讀取的檔案或權限錯誤，應記錄並跳過，而非讓整個 Process 崩潰。

**實作要點：**
- 所有檔案操作必須包含 try-catch 或錯誤檢查
- 記錄錯誤但繼續執行
- 掃描結束後提供錯誤摘要報告
- 提供手動重試失敗項目的機制

---

# Technical Guidelines

## 1. Architecture Patterns

### 非同步掃描引擎 (Async Scan Engine)

**必須採用的架構模式：**

```php
/**
 * 掃描管理器類別 - 完整範例
 */
class WP_Security_Scanner {
    
    const CHUNK_SIZE = 50;           // 每批處理檔案數
    const TIME_LIMIT = 3;            // 執行時間限制（秒）
    const OPTION_PREFIX = 'wpss_';   // Option 前綴
    
    /**
     * 初始化掃描
     */
    public function init_scan() {
        // 重置掃描狀態
        update_option( self::OPTION_PREFIX . 'scan_status', 'running' );
        update_option( self::OPTION_PREFIX . 'scan_progress', [
            'total_files'    => 0,
            'scanned_files'  => 0,
            'infected_files' => 0,
            'current_offset' => 0,
            'started_at'     => current_time( 'mysql' ),
            'errors'         => [],
        ] );
        
        // 建立檔案清單
        $this->build_file_list();
        
        return $this->process_chunk();
    }
    
    /**
     * 處理一個批次
     */
    public function process_chunk() {
        $progress   = get_option( self::OPTION_PREFIX . 'scan_progress' );
        $file_list  = get_option( self::OPTION_PREFIX . 'file_list', [] );
        $start_time = microtime( true );
        
        $offset = $progress['current_offset'];
        $chunk  = array_slice( $file_list, $offset, self::CHUNK_SIZE );
        
        foreach ( $chunk as $file_path ) {
            // 時間限制檢查
            if ( microtime( true ) - $start_time > self::TIME_LIMIT ) {
                break;
            }
            
            try {
                $scan_result = $this->scan_file( $file_path );
                
                if ( $scan_result['infected'] ) {
                    $progress['infected_files']++;
                    $this->log_threat( $file_path, $scan_result );
                }
                
                $progress['scanned_files']++;
                $offset++;
                
            } catch ( Exception $e ) {
                $progress['errors'][] = [
                    'file'    => $file_path,
                    'message' => $e->getMessage(),
                    'time'    => current_time( 'mysql' ),
                ];
            }
        }
        
        $progress['current_offset'] = $offset;
        
        // 檢查是否完成
        if ( $offset >= count( $file_list ) ) {
            $progress['completed_at'] = current_time( 'mysql' );
            update_option( self::OPTION_PREFIX . 'scan_status', 'completed' );
        }
        
        update_option( self::OPTION_PREFIX . 'scan_progress', $progress );
        
        return [
            'status'   => get_option( self::OPTION_PREFIX . 'scan_status' ),
            'progress' => $progress,
        ];
    }
    
    /**
     * 建立檔案清單
     */
    private function build_file_list() {
        $files = [];
        
        // 掃描核心目錄（排除 wp-content）
        $core_dirs = [ ABSPATH . 'wp-admin', ABSPATH . 'wp-includes' ];
        
        // 掃描 wp-content（plugins, themes, uploads）
        $content_dirs = [
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/uploads',
        ];
        
        foreach ( array_merge( $core_dirs, $content_dirs ) as $dir ) {
            if ( is_dir( $dir ) ) {
                $files = array_merge( $files, $this->get_files_recursive( $dir ) );
            }
        }
        
        update_option( self::OPTION_PREFIX . 'file_list', $files );
        
        $progress = get_option( self::OPTION_PREFIX . 'scan_progress' );
        $progress['total_files'] = count( $files );
        update_option( self::OPTION_PREFIX . 'scan_progress', $progress );
    }
    
    /**
     * 遞迴取得檔案清單
     */
    private function get_files_recursive( $dir ) {
        $files = [];
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ( $iterator as $file ) {
                if ( $file->isFile() ) {
                    // 過濾檔案類型
                    $ext = strtolower( $file->getExtension() );
                    if ( in_array( $ext, [ 'php', 'js', 'html', 'htm', 'svg' ], true ) ) {
                        $files[] = $file->getPathname();
                    }
                }
            }
        } catch ( Exception $e ) {
            // 記錄錯誤但繼續
            error_log( 'Scanner Error: ' . $e->getMessage() );
        }
        
        return $files;
    }
    
    /**
     * 掃描單一檔案
     */
    private function scan_file( $file_path ) {
        $result = [
            'infected' => false,
            'threats'  => [],
        ];
        
        // 檢查檔案可讀性
        if ( ! is_readable( $file_path ) ) {
            throw new Exception( 'File not readable: ' . $file_path );
        }
        
        // 檔案大小檢查（避免記憶體問題）
        $file_size = filesize( $file_path );
        if ( $file_size > 10 * 1024 * 1024 ) { // 10MB
            throw new Exception( 'File too large: ' . size_format( $file_size ) );
        }
        
        // 1. WordPress Core 完整性檢查
        if ( $this->is_core_file( $file_path ) ) {
            if ( ! $this->verify_core_checksum( $file_path ) ) {
                $result['infected'] = true;
                $result['threats'][] = 'core_file_modified';
            }
        }
        
        // 2. 特徵碼掃描
        $signatures = $this->get_malware_signatures();
        $file_content = file_get_contents( $file_path );
        
        foreach ( $signatures as $sig_name => $pattern ) {
            if ( preg_match( $pattern, $file_content ) ) {
                $result['infected'] = true;
                $result['threats'][] = $sig_name;
            }
        }
        
        return $result;
    }
}
```

### AJAX 處理器範例

```php
/**
 * AJAX Handler for continuous scanning
 */
add_action( 'wp_ajax_wpss_scan_chunk', 'wpss_handle_scan_chunk' );

function wpss_handle_scan_chunk() {
    // 安全檢查
    check_ajax_referer( 'wpss_scan_nonce', 'nonce' );
    
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Insufficient permissions' );
    }
    
    $scanner = new WP_Security_Scanner();
    $result  = $scanner->process_chunk();
    
    wp_send_json_success( $result );
}
```

### 前端 JavaScript 範例

```javascript
/**
 * 前端掃描控制器
 */
class SecurityScanController {
    constructor() {
        this.isScanning = false;
        this.nonce = wpssAjax.nonce;
    }
    
    async startScan() {
        this.isScanning = true;
        
        // 初始化掃描
        const initResult = await this.ajaxCall('init_scan');
        
        // 持續處理直到完成
        while (this.isScanning && initResult.status !== 'completed') {
            const result = await this.ajaxCall('scan_chunk');
            
            // 更新 UI
            this.updateProgress(result.progress);
            
            if (result.status === 'completed') {
                this.isScanning = false;
                this.showCompletionReport(result.progress);
                break;
            }
            
            // 短暫延遲避免過度請求
            await this.sleep(500);
        }
    }
    
    async ajaxCall(action) {
        const response = await fetch(wpssAjax.ajaxurl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                action: `wpss_${action}`,
                nonce: this.nonce
            })
        });
        
        const data = await response.json();
        return data.data;
    }
    
    updateProgress(progress) {
        const percentage = (progress.scanned_files / progress.total_files) * 100;
        document.getElementById('scan-progress-bar').style.width = `${percentage}%`;
        document.getElementById('scan-status').textContent = 
            `${progress.scanned_files} / ${progress.total_files} files scanned`;
    }
    
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
```

## 2. File Integrity Monitoring (FIM)

### WordPress Core 檔案驗證

```php
/**
 * 驗證 WordPress Core 檔案完整性
 */
class WP_Core_Integrity_Checker {
    
    private $checksums = null;
    
    /**
     * 取得官方 Checksums
     */
    private function get_official_checksums() {
        if ( null !== $this->checksums ) {
            return $this->checksums;
        }
        
        global $wp_version, $wp_local_package;
        
        $locale = get_locale();
        $url = 'https://api.wordpress.org/core/checksums/1.0/';
        $url = add_query_arg( [
            'version' => $wp_version,
            'locale'  => $locale,
        ], $url );
        
        $response = wp_remote_get( $url, [ 'timeout' => 10 ] );
        
        if ( is_wp_error( $response ) ) {
            return false;
        }
        
        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );
        
        if ( ! isset( $data['checksums'] ) ) {
            return false;
        }
        
        $this->checksums = $data['checksums'];
        return $this->checksums;
    }
    
    /**
     * 驗證單一檔案
     */
    public function verify_file( $file_path ) {
        $checksums = $this->get_official_checksums();
        
        if ( ! $checksums ) {
            return null; // 無法取得 checksums
        }
        
        // 轉換為相對路徑
        $relative_path = str_replace( ABSPATH, '', $file_path );
        
        if ( ! isset( $checksums[ $relative_path ] ) ) {
            return null; // 不在官方檔案清單中
        }
        
        $expected_hash = $checksums[ $relative_path ];
        $actual_hash   = md5_file( $file_path );
        
        return $expected_hash === $actual_hash;
    }
    
    /**
     * 檢查是否為 Core 檔案
     */
    public function is_core_file( $file_path ) {
        $relative_path = str_replace( ABSPATH, '', $file_path );
        
        // Core 檔案位於 wp-admin 或 wp-includes
        return (
            strpos( $relative_path, 'wp-admin/' ) === 0 ||
            strpos( $relative_path, 'wp-includes/' ) === 0 ||
            in_array( $relative_path, [ 'index.php', 'wp-config-sample.php' ], true )
        );
    }
}
```

### Plugin/Theme 完整性檢查

```php
/**
 * Plugin 完整性檢查器
 */
class WP_Plugin_Integrity_Checker {
    
    /**
     * 建立 Plugin 的 Golden Master
     */
    public function create_snapshot( $plugin_slug ) {
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_slug;
        
        if ( ! is_dir( $plugin_path ) ) {
            return false;
        }
        
        $snapshot = [];
        $files = $this->get_files_recursive( $plugin_path );
        
        foreach ( $files as $file ) {
            $relative_path = str_replace( $plugin_path . '/', '', $file );
            $snapshot[ $relative_path ] = md5_file( $file );
        }
        
        update_option( 'wpss_snapshot_' . $plugin_slug, $snapshot );
        
        return $snapshot;
    }
    
    /**
     * 比對 Plugin 檔案
     */
    public function verify_plugin( $plugin_slug ) {
        $snapshot = get_option( 'wpss_snapshot_' . $plugin_slug );
        
        if ( ! $snapshot ) {
            return [
                'status'  => 'no_snapshot',
                'message' => 'No baseline snapshot found. Create one first.',
            ];
        }
        
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_slug;
        $current_files = $this->get_files_recursive( $plugin_path );
        
        $modified = [];
        $added    = [];
        $deleted  = [];
        
        // 檢查修改和新增
        foreach ( $current_files as $file ) {
            $relative_path = str_replace( $plugin_path . '/', '', $file );
            $current_hash = md5_file( $file );
            
            if ( isset( $snapshot[ $relative_path ] ) ) {
                if ( $snapshot[ $relative_path ] !== $current_hash ) {
                    $modified[] = $relative_path;
                }
            } else {
                $added[] = $relative_path;
            }
        }
        
        // 檢查刪除
        foreach ( array_keys( $snapshot ) as $relative_path ) {
            $full_path = $plugin_path . '/' . $relative_path;
            if ( ! file_exists( $full_path ) ) {
                $deleted[] = $relative_path;
            }
        }
        
        return [
            'status'   => empty( $modified ) && empty( $added ) && empty( $deleted ) ? 'clean' : 'modified',
            'modified' => $modified,
            'added'    => $added,
            'deleted'  => $deleted,
        ];
    }
}
```

## 3. Malware Signature Matching

### 安全的特徵碼掃描

```php
/**
 * 惡意程式碼特徵掃描器
 */
class WP_Malware_Scanner {
    
    /**
     * 取得惡意程式碼特徵庫
     */
    private function get_malware_signatures() {
        return [
            // 危險函數組合
            'eval_base64' => '/eval\s*\(\s*base64_decode/i',
            'eval_gzinflate' => '/eval\s*\(\s*gzinflate/i',
            
            // 常見後門
            'c99_shell' => '/c99sh_backconnect|c99sh_datapipe/i',
            'r57_shell' => '/r57shell|r57_datapipe/i',
            
            // 可疑的隱藏執行
            'assert_decode' => '/assert\s*\(\s*base64_decode/i',
            'create_function' => '/create_function.*base64_decode/i',
            
            // 檔案操作後門
            'file_put_contents_decode' => '/file_put_contents.*base64_decode/i',
            
            // WordPress 特定攻擊
            'wp_insert_user_exploit' => '/wp_insert_user.*role.*administrator/i',
            
            // Iframe 注入
            'hidden_iframe' => '/<iframe[^>]+style=["\'].*display:\s*none/i',
            
            // SEO Spam
            'hidden_links' => '/<div[^>]+style=["\'].*display:\s*none[^>]*>.*<a href/i',
        ];
    }
    
    /**
     * 掃描檔案（處理大檔案）
     */
    public function scan_file_chunked( $file_path ) {
        $chunk_size = 1024 * 1024; // 1MB chunks
        $overlap = 1024; // 1KB overlap 避免邊界問題
        
        $handle = fopen( $file_path, 'r' );
        if ( ! $handle ) {
            throw new Exception( 'Cannot open file: ' . $file_path );
        }
        
        $threats = [];
        $signatures = $this->get_malware_signatures();
        $previous_chunk = '';
        
        while ( ! feof( $handle ) ) {
            $chunk = fread( $handle, $chunk_size );
            
            // 與前一個 chunk 的結尾重疊
            $search_content = $previous_chunk . $chunk;
            
            // 檢查每個特徵碼
            foreach ( $signatures as $sig_name => $pattern ) {
                if ( preg_match( $pattern, $search_content, $matches ) ) {
                    $threats[] = [
                        'signature' => $sig_name,
                        'matched'   => $matches[0],
                    ];
                }
            }
            
            // 保留結尾部分供下次重疊
            $previous_chunk = substr( $chunk, -$overlap );
        }
        
        fclose( $handle );
        
        return $threats;
    }
    
    /**
     * 進階分析：檢查可疑函數的上下文
     */
    public function analyze_suspicious_code( $file_path ) {
        $content = file_get_contents( $file_path );
        $tokens = token_get_all( $content );
        
        $suspicious_patterns = [];
        
        for ( $i = 0; $i < count( $tokens ); $i++ ) {
            $token = $tokens[$i];
            
            // 只處理函數呼叫
            if ( ! is_array( $token ) || $token[0] !== T_STRING ) {
                continue;
            }
            
            $function_name = $token[1];
            
            // 檢查危險函數
            if ( in_array( strtolower( $function_name ), [ 'eval', 'assert', 'create_function' ], true ) ) {
                
                // 取得函數的參數
                $context = $this->get_function_context( $tokens, $i );
                
                // 分析參數是否包含 decode 函數
                if ( $this->contains_decode_function( $context ) ) {
                    $suspicious_patterns[] = [
                        'function' => $function_name,
                        'line'     => $token[2],
                        'context'  => $context,
                        'risk'     => 'high',
                    ];
                }
            }
        }
        
        return $suspicious_patterns;
    }
    
    /**
     * 取得函數呼叫的上下文
     */
    private function get_function_context( $tokens, $start_index ) {
        $context = '';
        $paren_count = 0;
        $started = false;
        
        for ( $i = $start_index; $i < count( $tokens ); $i++ ) {
            $token = $tokens[$i];
            $value = is_array( $token ) ? $token[1] : $token;
            
            if ( '(' === $value ) {
                $paren_count++;
                $started = true;
            }
            
            if ( $started ) {
                $context .= $value;
            }
            
            if ( ')' === $value ) {
                $paren_count--;
                if ( 0 === $paren_count ) {
                    break;
                }
            }
        }
        
        return $context;
    }
    
    /**
     * 檢查是否包含 decode 函數
     */
    private function contains_decode_function( $context ) {
        $decode_functions = [ 'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13' ];
        
        foreach ( $decode_functions as $func ) {
            if ( stripos( $context, $func ) !== false ) {
                return true;
            }
        }
        
        return false;
    }
}
```

## 4. File Safety Operations

### 檔案隔離與清理

```php
/**
 * 安全的檔案隔離管理器
 */
class WP_Quarantine_Manager {
    
    private $quarantine_dir;
    
    public function __construct() {
        $this->quarantine_dir = WP_CONTENT_DIR . '/wpss-quarantine';
        $this->setup_quarantine_dir();
    }
    
    /**
     * 設定隔離目錄
     */
    private function setup_quarantine_dir() {
        if ( ! file_exists( $this->quarantine_dir ) ) {
            wp_mkdir_p( $this->quarantine_dir );
        }
        
        // 建立 .htaccess 防止執行
        $htaccess_path = $this->quarantine_dir . '/.htaccess';
        if ( ! file_exists( $htaccess_path ) ) {
            file_put_contents( $htaccess_path, "Deny from all\n" );
        }
        
        // 建立空的 index.php
        $index_path = $this->quarantine_dir . '/index.php';
        if ( ! file_exists( $index_path ) ) {
            file_put_contents( $index_path, "<?php\n// Silence is golden\n" );
        }
    }
    
    /**
     * 隔離可疑檔案
     */
    public function quarantine_file( $file_path, $reason = '' ) {
        if ( ! file_exists( $file_path ) ) {
            return new WP_Error( 'file_not_found', 'File does not exist' );
        }
        
        // 建立唯一的隔離檔名
        $file_hash = md5( $file_path );
        $timestamp = time();
        $original_name = basename( $file_path );
        
        $quarantine_name = sprintf(
            '%s_%s_%s.suspected',
            $timestamp,
            $file_hash,
            sanitize_file_name( $original_name )
        );
        
        $quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;
        
        // 移動檔案
        if ( ! rename( $file_path, $quarantine_path ) ) {
            return new WP_Error( 'quarantine_failed', 'Failed to move file to quarantine' );
        }
        
        // 記錄隔離資訊
        $quarantine_log = get_option( 'wpss_quarantine_log', [] );
        $quarantine_log[] = [
            'original_path'    => $file_path,
            'quarantine_path'  => $quarantine_path,
            'reason'           => $reason,
            'timestamp'        => current_time( 'mysql' ),
            'file_hash'        => $file_hash,
            'file_size'        => filesize( $quarantine_path ),
        ];
        
        update_option( 'wpss_quarantine_log', $quarantine_log );
        
        return $quarantine_path;
    }
    
    /**
     * 恢復隔離檔案
     */
    public function restore_file( $quarantine_path ) {
        $quarantine_log = get_option( 'wpss_quarantine_log', [] );
        
        // 找到原始路徑
        $original_path = null;
        $log_key = null;
        
        foreach ( $quarantine_log as $key => $entry ) {
            if ( $entry['quarantine_path'] === $quarantine_path ) {
                $original_path = $entry['original_path'];
                $log_key = $key;
                break;
            }
        }
        
        if ( ! $original_path ) {
            return new WP_Error( 'no_original_path', 'Original file path not found in log' );
        }
        
        // 確認原位置可寫
        $original_dir = dirname( $original_path );
        if ( ! is_writable( $original_dir ) ) {
            return new WP_Error( 'not_writable', 'Original directory is not writable' );
        }
        
        // 恢復檔案
        if ( ! rename( $quarantine_path, $original_path ) ) {
            return new WP_Error( 'restore_failed', 'Failed to restore file' );
        }
        
        // 更新日誌
        unset( $quarantine_log[ $log_key ] );
        update_option( 'wpss_quarantine_log', array_values( $quarantine_log ) );
        
        return $original_path;
    }
    
    /**
     * 永久刪除隔離檔案
     */
    public function delete_quarantined_file( $quarantine_path ) {
        if ( ! file_exists( $quarantine_path ) ) {
            return new WP_Error( 'file_not_found', 'Quarantined file not found' );
        }
        
        // 刪除檔案
        if ( ! unlink( $quarantine_path ) ) {
            return new WP_Error( 'delete_failed', 'Failed to delete file' );
        }
        
        // 更新日誌
        $quarantine_log = get_option( 'wpss_quarantine_log', [] );
        foreach ( $quarantine_log as $key => $entry ) {
            if ( $entry['quarantine_path'] === $quarantine_path ) {
                unset( $quarantine_log[ $key ] );
                break;
            }
        }
        update_option( 'wpss_quarantine_log', array_values( $quarantine_log ) );
        
        return true;
    }
}
```

---

# WordPress Security Best Practices Checklist

當生成任何安全相關程式碼時，**必須**確保包含以下要素：

## ✅ 權限驗證
```php
// AJAX 處理器
if ( ! current_user_can( 'manage_options' ) ) {
    wp_send_json_error( 'Insufficient permissions' );
}

// Admin 頁面
if ( ! current_user_can( 'manage_options' ) ) {
    wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
}
```

## ✅ Nonce 驗證
```php
// 表單產生
wp_nonce_field( 'wpss_scan_action', 'wpss_scan_nonce' );

// 表單驗證
if ( ! isset( $_POST['wpss_scan_nonce'] ) || 
     ! wp_verify_nonce( $_POST['wpss_scan_nonce'], 'wpss_scan_action' ) ) {
    wp_die( 'Security check failed' );
}

// AJAX
check_ajax_referer( 'wpss_scan_nonce', 'nonce' );
```

## ✅ Input Sanitization
```php
// 文字輸入
$plugin_slug = sanitize_text_field( $_POST['plugin_slug'] );

// 檔案路徑
$file_path = sanitize_file_name( $_POST['file_path'] );

// 整數
$offset = absint( $_POST['offset'] );

// URL
$url = esc_url_raw( $_POST['url'] );
```

## ✅ Output Escaping
```php
// HTML 輸出
echo esc_html( $file_name );

// 屬性
echo '<div data-file="' . esc_attr( $file_path ) . '">';

// URL
echo '<a href="' . esc_url( $link ) . '">';

// JavaScript
echo '<script>var fileName = "' . esc_js( $file_name ) . '";</script>';
```

## ✅ SQL Injection Prevention
```php
// 使用 $wpdb 預處理
global $wpdb;
$results = $wpdb->get_results( $wpdb->prepare(
    "SELECT * FROM {$wpdb->prefix}scan_results WHERE file_path = %s",
    $file_path
) );
```

## ✅ Error Handling
```php
// 檔案操作
try {
    if ( ! file_exists( $file_path ) ) {
        throw new Exception( 'File not found' );
    }
    
    $content = file_get_contents( $file_path );
    
} catch ( Exception $e ) {
    error_log( 'Scanner Error: ' . $e->getMessage() );
    return new WP_Error( 'scan_error', $e->getMessage() );
}
```

---

# Output Specifications

## 何時創建檔案 vs 提供程式碼片段

### 創建完整檔案的情境：
- 用戶明確要求建立外掛或功能
- 需要提供完整的類別實作（超過 100 行）
- 包含多個相關方法需要完整上下文
- 提供可直接使用的範例專案

**檔案命名規範：**
```
class-wp-security-scanner.php
class-wp-core-integrity-checker.php
class-wp-malware-scanner.php
class-wp-quarantine-manager.php
admin-ajax-handlers.php
scan-frontend.js
```

### 提供程式碼片段的情境：
- 用戶詢問特定功能的實作方式
- 解釋某個概念或技術
- 提供修改建議或優化方案
- 回答特定問題（如「如何檢查檔案完整性？」）

## 多檔案專案結構

當需要創建完整的外掛時，使用以下結構：

```
wp-security-scanner/
├── wp-security-scanner.php          (主檔案)
├── includes/
│   ├── class-scanner.php
│   ├── class-integrity-checker.php
│   ├── class-malware-scanner.php
│   └── class-quarantine-manager.php
├── admin/
│   ├── class-admin.php
│   ├── views/
│   │   └── scan-page.php
│   └── js/
│       └── scan-controller.js
├── assets/
│   ├── css/
│   └── js/
└── readme.txt
```

## 回應格式標準

### 概念說明型回應
1. 簡短解釋概念（2-3 句）
2. 提供程式碼範例
3. 說明關鍵要點
4. 可選：提供延伸閱讀或相關資源

### 實作型回應
1. 確認需求
2. 說明實作策略
3. 提供完整程式碼或創建檔案
4. 說明如何使用
5. 提供測試建議

### 除錯型回應
1. 分析問題
2. 指出潛在原因
3. 提供修正方案
4. 說明如何預防類似問題

---

# Common Pitfalls & Solutions

## ❌ 常見錯誤 1：一次掃描所有檔案

**錯誤範例：**
```php
// 危險！可能導致 timeout 或記憶體耗盡
$files = $this->get_all_files();
foreach ( $files as $file ) {
    $this->scan_file( $file );
}
```

**正確做法：**
```php
// 使用分批處理
$progress = get_option( 'scan_progress' );
$chunk = array_slice( $files, $progress['offset'], 50 );

foreach ( $chunk as $file ) {
    if ( microtime(true) - $start_time > 3 ) {
        break; // 時間限制
    }
    $this->scan_file( $file );
}
```

## ❌ 常見錯誤 2：對大檔案使用 file_get_contents

**錯誤範例：**
```php
// 危險！大檔案會耗盡記憶體
$content = file_get_contents( $file );
preg_match_all( $pattern, $content, $matches );
```

**正確做法：**
```php
// 使用分塊讀取
$handle = fopen( $file, 'r' );
while ( ! feof( $handle ) ) {
    $chunk = fread( $handle, 1024 * 1024 ); // 1MB
    preg_match_all( $pattern, $chunk, $matches );
}
fclose( $handle );
```

## ❌ 常見錯誤 3：直接刪除可疑檔案

**錯誤範例：**
```php
// 危險！可能誤刪重要檔案
if ( $this->is_malware( $file ) ) {
    unlink( $file );
}
```

**正確做法：**
```php
// 先隔離，讓用戶確認
if ( $this->is_malware( $file ) ) {
    $quarantine_manager->quarantine_file( $file, 'Malware detected' );
    // 記錄並通知用戶
}
```

## ❌ 常見錯誤 4：缺少錯誤處理

**錯誤範例：**
```php
// 一個失敗導致整個掃描中斷
foreach ( $files as $file ) {
    $result = $this->scan_file( $file ); // 如果失敗會拋出異常
}
```

**正確做法：**
```php
$errors = [];
foreach ( $files as $file ) {
    try {
        $result = $this->scan_file( $file );
    } catch ( Exception $e ) {
        $errors[] = [
            'file' => $file,
            'error' => $e->getMessage()
        ];
        continue; // 繼續下一個檔案
    }
}
```

## ❌ 常見錯誤 5：過度依賴簡單的關鍵字匹配

**錯誤範例：**
```php
// 高誤報！正常程式碼也會觸發
if ( strpos( $content, 'eval' ) !== false ) {
    return 'malware';
}
```

**正確做法：**
```php
// 分析上下文
$tokens = token_get_all( $content );
$suspicious = $this->analyze_eval_usage( $tokens );

// 檢查是否有危險組合
if ( $suspicious['has_eval'] && $suspicious['has_decode'] ) {
    return 'suspicious';
}
```

---

# Testing & Validation

## 單元測試範例

```php
/**
 * PHPUnit 測試範例
 */
class Test_WP_Security_Scanner extends WP_UnitTestCase {
    
    private $scanner;
    
    public function setUp(): void {
        parent::setUp();
        $this->scanner = new WP_Security_Scanner();
    }
    
    /**
     * 測試檔案清單建立
     */
    public function test_build_file_list() {
        $this->scanner->init_scan();
        
        $file_list = get_option( 'wpss_file_list' );
        
        $this->assertIsArray( $file_list );
        $this->assertNotEmpty( $file_list );
        
        // 確認檔案格式正確
        foreach ( array_slice( $file_list, 0, 10 ) as $file ) {
            $this->assertFileExists( $file );
        }
    }
    
    /**
     * 測試分批處理
     */
    public function test_chunk_processing() {
        $this->scanner->init_scan();
        
        $result1 = $this->scanner->process_chunk();
        $this->assertEquals( 'running', $result1['status'] );
        
        // 模擬處理到完成
        $max_iterations = 1000;
        $iterations = 0;
        
        while ( $result1['status'] === 'running' && $iterations < $max_iterations ) {
            $result1 = $this->scanner->process_chunk();
            $iterations++;
        }
        
        $this->assertEquals( 'completed', $result1['status'] );
        $this->assertLessThan( $max_iterations, $iterations );
    }
    
    /**
     * 測試惡意程式碼檢測
     */
    public function test_malware_detection() {
        // 建立測試檔案
        $test_file = sys_get_temp_dir() . '/test-malware.php';
        
        // 明顯的惡意程式碼
        file_put_contents( $test_file, '<?php eval(base64_decode("ZWNobyAiaGFja2VkIjs=")); ?>' );
        
        $malware_scanner = new WP_Malware_Scanner();
        $threats = $malware_scanner->scan_file_chunked( $test_file );
        
        $this->assertNotEmpty( $threats );
        
        // 清理
        unlink( $test_file );
    }
    
    /**
     * 測試檔案隔離
     */
    public function test_quarantine_file() {
        $quarantine_manager = new WP_Quarantine_Manager();
        
        // 建立測試檔案
        $test_file = sys_get_temp_dir() . '/test-suspicious.php';
        file_put_contents( $test_file, '<?php echo "test"; ?>' );
        
        $quarantine_path = $quarantine_manager->quarantine_file( $test_file, 'Test quarantine' );
        
        $this->assertNotWPError( $quarantine_path );
        $this->assertFileExists( $quarantine_path );
        $this->assertFileDoesNotExist( $test_file );
        
        // 測試恢復
        $restored_path = $quarantine_manager->restore_file( $quarantine_path );
        
        $this->assertNotWPError( $restored_path );
        $this->assertFileExists( $test_file );
        
        // 清理
        unlink( $test_file );
    }
}
```

## 效能測試基準

```php
/**
 * 效能基準測試
 */
class WP_Scanner_Benchmark {
    
    /**
     * 測試掃描速度
     */
    public function benchmark_scan_speed() {
        $scanner = new WP_Security_Scanner();
        $test_dir = WP_PLUGIN_DIR . '/akismet'; // 使用 Akismet 作為測試
        
        $start_time = microtime( true );
        $start_memory = memory_get_usage();
        
        $files = $scanner->get_files_recursive( $test_dir );
        
        foreach ( $files as $file ) {
            $scanner->scan_file( $file );
        }
        
        $end_time = microtime( true );
        $end_memory = memory_get_usage();
        
        $results = [
            'files_scanned'  => count( $files ),
            'time_elapsed'   => round( $end_time - $start_time, 2 ) . ' seconds',
            'memory_used'    => size_format( $end_memory - $start_memory ),
            'files_per_sec'  => round( count( $files ) / ( $end_time - $start_time ), 2 ),
        ];
        
        return $results;
    }
}
```

---

# Additional Resources

## WordPress 官方文件
- [WordPress Security Best Practices](https://developer.wordpress.org/apis/security/)
- [Plugin Security Guidelines](https://developer.wordpress.org/plugins/security/)
- [Data Validation](https://developer.wordpress.org/apis/security/data-validation/)
- [Escaping Output](https://developer.wordpress.org/apis/security/escaping/)

## 安全資源
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [WordPress VIP Code Analysis](https://docs.wpvip.com/technical-references/code-quality-and-best-practices/)
- [Wordfence Blog](https://www.wordfence.com/blog/)

## 相關外掛參考
- NinjaScanner (檔案完整性監控)
- Wordfence (全方位安全掃描)
- Sucuri Security (惡意程式碼清理)
- iThemes Security (安全加固)

---

# Quick Reference

## 掃描器實作檢查清單

建立新的掃描功能時，確保：

- [ ] 使用分批處理（每批 50-100 個檔案）
- [ ] 實作時間限制保護（2-3 秒）
- [ ] 記錄掃描進度到 Options
- [ ] 提供前端進度顯示
- [ ] 大檔案使用分塊讀取
- [ ] 包含完整的錯誤處理
- [ ] 驗證所有使用者輸入
- [ ] 檢查使用者權限
- [ ] 使用 Nonce 保護
- [ ] 可疑檔案先隔離再刪除
- [ ] 記錄所有重要操作
- [ ] 提供操作復原機制
- [ ] 撰寫單元測試
- [ ] 進行效能測試

## 快速程式碼片段

### 檢查執行時間
```php
$start = microtime(true);
// ... 操作
if ( microtime(true) - $start > 3 ) {
    // 超時處理
}
```

### 安全的檔案讀取
```php
if ( ! is_readable( $file ) ) {
    throw new Exception( 'File not readable' );
}

$size = filesize( $file );
if ( $size > 10 * 1024 * 1024 ) {
    // 使用分塊讀取
}
```

### WordPress 權限檢查
```php
if ( ! current_user_can( 'manage_options' ) ) {
    wp_die( 'Insufficient permissions' );
}
```

### 隔離檔案
```php
$quarantine = new WP_Quarantine_Manager();
$quarantine->quarantine_file( $suspicious_file, 'Reason' );
```

---

**最後更新：** 2025-02-08  
**版本：** 1.1.0  
**維護者：** WP Security Team
