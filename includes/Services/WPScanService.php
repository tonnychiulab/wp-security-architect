<?php

namespace WPSA\Services;

if (! defined('ABSPATH')) {
    exit;
}

class WPScanService
{

    private $api_url = 'https://wpscan.com/api/v3/';
    private $api_key;

    public function __construct()
    {
        $this->api_key = get_option('wpsa_wpscan_api_key');
    }

    /**
     * Check if API key is configured
     */
    public function has_api_key()
    {
        return ! empty($this->api_key);
    }

    /**
     * Get vulnerabilities for installed plugins
     */
    public function get_plugin_vulnerabilities()
    {
        if (! $this->has_api_key()) {
            return ['error' => 'API Key missing'];
        }

        // Check Cache
        $cached = get_transient('wpsa_cve_cache');
        if (false !== $cached) {
            return $cached;
        }

        if (! function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = get_plugins();
        $vulnerabilities = [];

        foreach ($all_plugins as $path => $plugin_data) {
            $slug = dirname($path);
            if ('.' === $slug || empty($slug)) {
                // Single file plugin or something weird, try filename
                $slug = basename($path, '.php');
            }
            $version = $plugin_data['Version'];

            $vulns = $this->check_single_plugin($slug, $version);
            if (! empty($vulns)) {
                $vulnerabilities[$slug] = [
                    'name' => $plugin_data['Name'],
                    'version' => $version,
                    'issues' => $vulns
                ];
            }
        }

        // Set Cache for 12 hours
        set_transient('wpsa_cve_cache', $vulnerabilities, 12 * HOUR_IN_SECONDS);

        return $vulnerabilities;
    }

    /**
     * Query API for a single plugin
     * Note: In a real production environment with many plugins, 
     * we should look for a batch API or throttle requests to avoid timeout.
     * WPScan API usually requires one request per slug.
     */
    private function check_single_plugin($slug, $version)
    {
        $endpoint = $this->api_url . 'plugins/' . $slug;

        $response = wp_remote_get($endpoint, [
            'headers' => [
                'Authorization' => 'Token ' . $this->api_key,
                'User-Agent'    => 'WP-Security-Architect/1.0.0'
            ],
            'timeout' => 5
        ]);

        if (is_wp_error($response)) {
            return [];
        }

        $code = wp_remote_retrieve_response_code($response);
        if (200 !== $code) {
            return [];
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (empty($data) || empty($data[$slug]['vulnerabilities'])) {
            return [];
        }

        // Filter vulnerabilities affecting the current version
        $affecting_vulns = [];
        foreach ($data[$slug]['vulnerabilities'] as $vuln) {
            // Simplified version check logic 
            // In reality, we need to parse "fixed_in"
            if (empty($vuln['fixed_in'])) {
                // Not fixed yet? assume vulnerable
                $affecting_vulns[] = $vuln;
            } else {
                if (version_compare($version, $vuln['fixed_in'], '<')) {
                    $affecting_vulns[] = $vuln;
                }
            }
        }

        return $affecting_vulns;
    }
}
