<?php

namespace WPSA\Services;

if (! defined('ABSPATH')) {
    exit;
}

class ResultService
{

    private $table_name;

    public function __construct()
    {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'wpsa_scan_results';
    }

    /**
     * Create custom database table
     * Should be called on plugin activation
     */
    public function create_table()
    {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $this->table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            issue_type varchar(50) NOT NULL,
            score float DEFAULT 0,
            details text,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    /**
     * Add a new security issue
     */
    public function add_issue($file_path, $type, $score = 0, $details = '')
    {
        global $wpdb;

        // Check duplicates (optional: prevent spamming same file)
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $this->table_name WHERE file_path = %s AND issue_type = %s",
            $file_path,
            $type
        ));

        if ($exists) {
            return; // Already recorded
        }

        $wpdb->insert(
            $this->table_name,
            [
                'file_path'  => $file_path,
                'issue_type' => $type,
                'score'      => $score,
                'details'    => $details
            ],
            ['%s', '%s', '%f', '%s']
        );
    }

    /**
     * Get all issues
     */
    public function get_issues($limit = 100)
    {
        global $wpdb;
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $this->table_name ORDER BY created_at DESC LIMIT %d",
            $limit
        ), ARRAY_A);
    }

    /**
     * Count total issues
     */
    public function count_issues()
    {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM $this->table_name");
    }

    /**
     * Clear all results
     */
    public function truncate()
    {
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE $this->table_name");
    }
}
