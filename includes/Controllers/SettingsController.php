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
            'sanitize_callback' => 'sanitize_text_field'
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
}
