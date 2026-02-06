<?php

namespace WPSA\Controllers;

class ScanController
{

    public function __construct()
    {
        add_action('wp_ajax_wpsa_scan', [$this, 'handle_ajax_scan']);
    }

    public function handle_ajax_scan()
    {
        // 1. Security Checks
        check_ajax_referer('wpsa_scan_nonce', 'nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        // 2. Get Input
        $offset = isset($_POST['offset']) ? intval($_POST['offset']) : 0;

        // 3. Run Scan
        $scanner = new \WPSA\Core\Scanner();
        $result = $scanner->scan($offset);

        // 4. Return Result
        if (isset($result['status']) && $result['status'] === 'error') {
            wp_send_json_error($result['message']);
        } else {
            wp_send_json_success($result);
        }
    }
}
