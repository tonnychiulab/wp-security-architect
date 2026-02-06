<?php

namespace WPSA\Controllers;

if (! defined('ABSPATH')) {
    exit;
}

class SettingsController
{

    public function __construct()
    {
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function register_settings()
    {
        register_setting('wpsa_settings_group', 'wpsa_wpscan_api_key', [
            'sanitize_callback' => [$this, 'sanitize_api_key']
        ]);

        add_settings_section(
            'wpsa_general_settings',
            'General Settings',
            null,
            'wpsa-settings'
        );

        add_settings_field(
            'wpsa_wpscan_api_key',
            'WPScan API Key',
            [$this, 'render_api_key_field'],
            'wpsa-settings',
            'wpsa_general_settings'
        );
    }

    public function render_api_key_field()
    {
        $api_key = get_option('wpsa_wpscan_api_key');
        echo '<input type="password" name="wpsa_wpscan_api_key" value="' . esc_attr($api_key) . '" class="regular-text">';
        echo '<p class="description">Get your free API key from <a href="https://wpscan.com/api" target="_blank">wpscan.com</a>.</p>';
    }

    /**
     * Sanitize and Validate API Key
     */
    public function sanitize_api_key($input)
    {
        $new_key = sanitize_text_field($input);

        if (empty($new_key)) {
            return $new_key;
        }

        // Flush cache regardless to force fresh check next time usage works
        delete_transient('wpsa_api_status');
        delete_transient('wpsa_cve_cache');

        // Validate immediately
        // We use full path or use statement if added. Let's use full path.
        $service = new \WPSA\Services\WPScanService();
        $service->set_api_key($new_key);
        $status = $service->get_api_status();

        if (isset($status['error'])) {
            add_settings_error(
                'wpsa_wpscan_api_key',
                'wpsa_api_error',
                'Invalid API Key: ' . $status['error'],
                'error'
            );
        } else {
            add_settings_error(
                'wpsa_wpscan_api_key',
                'wpsa_api_success',
                'API Key Validated! Plan: ' . ucfirst($status['plan'] ?? 'Unknown'),
                'success'
            );
        }

        return $new_key;
    }
}
