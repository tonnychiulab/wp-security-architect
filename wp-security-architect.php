<?php
/**
 * Plugin Name: WP Security Architect
 * Description: A "Don't Break the Site" security scanner built with an Async Incremental Engine and AI-powered detection.
 * Version: 1.0.0
 * Author: AI Security Team
 * Text Domain: wp-security-architect
 * License: GPLv3
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Define Constants
define( 'WPSA_VERSION', '1.0.0' );
define( 'WPSA_PATH', plugin_dir_path( __FILE__ ) );
define( 'WPSA_URL', plugin_dir_url( __FILE__ ) );

/**
 * Autoloader for WPSA classes
 * Follows PSR-4 naming convention: \WPSA\ClassName -> includes/ClassName.php
 */
spl_autoload_register( function ( $class ) {
    $prefix = 'WPSA\\';
    $base_dir = WPSA_PATH . 'includes/';

    $len = strlen( $prefix );
    if ( strncmp( $prefix, $class, $len ) !== 0 ) {
        return;
    }

    $relative_class = substr( $class, $len );
    $file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

    if ( file_exists( $file ) ) {
        require $file;
    }
} );

/**
 * Main Plugin Class
 */
final class WP_Security_Architect {

    private static $instance = null;

    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init_hooks();
    }

    private function init_hooks() {
        // Initialize Controllers
        add_action( 'plugins_loaded', [ $this, 'init_controllers' ] );
    }

    public function init_controllers() {
        // Phase 1: Admin Dashboard & Scan Logic
        new \WPSA\Controllers\AdminController();
        new \WPSA\Controllers\ScanController();
        
        // Phase 1.5: Settings & CVE Monitor
        new \WPSA\Controllers\SettingsController();
    }
}

// Wake up the Architect
WP_Security_Architect::get_instance();
