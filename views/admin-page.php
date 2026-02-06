<?php
if (! defined('ABSPATH')) {
    exit;
}
// Initialize Service
$wpscan_service = new \WPSA\Services\WPScanService();
$api_key_set    = $wpscan_service->has_api_key();
$vulnerabilities = [];

if ($api_key_set) {
    $vulnerabilities = $wpscan_service->get_plugin_vulnerabilities();
}

// Initialize Result Service (Malware)
$result_service = new \WPSA\Services\ResultService();
$malware_issues = $result_service->get_issues();
?>

<div class="wrap wpsa-wrap">
    <h1 class="wp-heading-inline">Security Architect Dashboard</h1>

    <!-- Action Bar -->
    <div class="wpsa-card wpsa-actions">
        <h2>🛠️ Core Engine (The Architect)</h2>
        <p>Run a non-blocking background scan of your filesystem.</p>
        <button id="wpsa-start-scan" class="button button-primary button-hero">
            <span class="dashicons dashicons-shield-alt"></span> Start Async Scan
        </button>
        <div id="wpsa-scan-progress" style="display:none; margin-top: 15px;">
            <div class="wpsa-progress-bar">
                <div class="wpsa-progress-fill" style="width: 0%"></div>
            </div>
            <p class="description">Scanning: <span id="wpsa-current-file">Initializing...</span></p>
        </div>
    </div>

    <!-- CVE Dashboard (Phase 1.5) -->
    <div class="wpsa-card wpsa-cve-monitor">
        <h2>📊 Plugin Vulnerabilities (The Auditor)</h2>

        <?php
        if ($api_key_set) {
            $api_status = $wpscan_service->get_api_status();
            if ($api_status && isset($api_status['requests_remaining'])) : ?>
                <div class="wpsa-api-status" style="background:#f0f6fc; border:1px solid #cce5ff; padding:10px; border-radius:4px; margin-bottom:15px; display:flex; justify-content:space-between; align-items:center;">
                    <span><span class="dashicons dashicons-admin-network" style="color:#2271b1"></span> <strong>API Plan:</strong> <?php echo esc_html(ucfirst($api_status['plan'] ?? 'Free')); ?></span>
                    <span><span class="dashicons dashicons-chart-pie" style="color:#2271b1"></span> <strong>Requests Remaining:</strong> <?php echo esc_html($api_status['requests_remaining']); ?></span>
                </div>
        <?php endif;
        }
        ?>

        <?php if (! $api_key_set) : ?>
            <div class="notice notice-warning inline">
                <p>
                    <strong>API Key Missing:</strong> The Auditor cannot check for plugin vulnerabilities without a WPScan API Key.
                    <a href="<?php echo esc_url(admin_url('admin.php?page=wpsa-settings')); ?>">Configure it here</a>.
                </p>
            </div>
        <?php elseif (isset($vulnerabilities['error'])) : ?>
            <div class="notice notice-error inline">
                <p>Error fetching data: <?php echo esc_html($vulnerabilities['error']); ?></p>
            </div>
        <?php elseif (empty($vulnerabilities)) : ?>
            <div class="wpsa-success-state">
                <span class="dashicons dashicons-yes-alt"></span>
                <h3>All Clear!</h3>
                <p>No known vulnerabilities found in your installed plugins.</p>
            </div>
        <?php else : ?>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Version</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($vulnerabilities as $slug => $data) : ?>
                        <?php foreach ($data['issues'] as $issue) : ?>
                            <tr>
                                <td><strong><?php echo esc_html($data['name']); ?></strong></td>
                                <td><?php echo esc_html($data['version']); ?></td>
                                <td>
                                    <a href="https://wpscan.com/vulnerability/<?php echo esc_attr($issue['id']); ?>" target="_blank">
                                        <?php echo esc_html($issue['title']); ?>
                                    </a>
                                </td>
                                <td><span class="wpsa-badge wpsa-badge-high">High</span></td> <!-- TODO: map severity -->
                            </tr>
                        <?php endforeach; ?>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Malware Report (Phase 2) -->
    <div class="wpsa-card wpsa-malware-report">
        <h2>🏹 Malware Hunt Report (The Hunter)</h2>
        <?php if (empty($malware_issues)) : ?>
            <p>No suspicious files found yet. Run a scan to let the Hunter loose.</p>
        <?php else : ?>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Issue Type</th>
                        <th>Score</th>
                        <th>Details</th>
                        <th>Found At</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($malware_issues as $issue) : ?>
                        <tr>
                            <td><code><?php echo esc_html($issue['file_path']); ?></code></td>
                            <td><span class="wpsa-badge wpsa-badge-medium"><?php echo esc_html($issue['issue_type']); ?></span></td>
                            <td><?php echo esc_html(number_format($issue['score'], 2)); ?></td>
                            <td><?php echo esc_html($issue['details']); ?></td>
                            <td><?php echo esc_html($issue['created_at']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <div style="margin-top:10px; text-align:right;">
                <p class="description">Showing last 100 results.</p>
            </div>
        <?php endif; ?>
    </div>
</div>