<?php

namespace WPSA\Controllers;

if (! defined('ABSPATH')) {
    exit;
}

class AdminController
{

    public function __construct()
    {
        add_action('admin_menu', [$this, 'add_menu_page']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
    }

    /**
     * Register the main menu page
     */
    public function add_menu_page()
    {
        add_menu_page(
            'Security Architect',          // Page Title
            'Security Architect',          // Menu Title
            'manage_options',              // Capability
            'wpsa-dashboard',              // Menu Slug
            [$this, 'render_dashboard'], // Callback
            'dashicons-shield',            // Icon
            100                            // Position
        );

        // Add settings page as submenu
        add_submenu_page(
            'wpsa-dashboard',
            'Settings',
            'Settings',
            'manage_options',
            'wpsa-settings',
            [$this, 'render_settings']
        );
    }

    /**
     * Load CSS/JS
     */
    public function enqueue_assets($hook)
    {
        if (strpos($hook, 'wpsa') === false) {
            return;
        }

        wp_enqueue_style('wpsa-admin-css', WPSA_URL . 'assets/css/admin.css', [], WPSA_VERSION);
        wp_enqueue_script('wpsa-admin-js', WPSA_URL . 'assets/js/admin.js', ['jquery'], WPSA_VERSION, true);

        // Pass localized data to JS
        wp_localize_script('wpsa-admin-js', 'wpsaParams', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('wpsa_scan_nonce')
        ]);
    }

    /**
     * Render the Dashboard
     */
    public function render_dashboard()
    {
        require_once WPSA_PATH . 'views/admin-page.php';
    }

    /**
     * Render the Settings Page (Placeholder for now)
     */
    public function render_settings()
    {
        // Will be handled by SettingsController, or simple include
        echo '<div class="wrap"><h1>WP Security Architect Settings</h1><form method="post" action="options.php">';
        settings_fields('wpsa_settings_group');
        do_settings_sections('wpsa-settings');
        submit_button();
        echo '</form></div>';
    }
}
