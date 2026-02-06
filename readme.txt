=== WP Security Architect ===
Contributors: aisecurityteam
Tags: security, malware, scanner, async, firewall
Requires at least: 5.8
Tested up to: 6.4
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

A "Don't Break the Site" security scanner built with an Async Incremental Engine and AI-powered detection.

== Description ==

Why build another security plugin? Because most existing scanners have a fundamental flaw: **They try to do too much at once.**

When you run a scan on a large site categories (GBs of uploads, thousands of files), traditional scanners often hit the **PHP Time Limit (30s)** or **Memory Limit**, causing the "White Screen of Death" or partial, unreliable scans.

**WP Security Architect** is different. It behaves like an army of ants:

*   **Async Incremental Scan**: Divides the "mountain" of files into thousands of micro-tasks.
*   **3-Second Rule**: Each request runs for only 2-3 seconds, then pauses and saves state.
*   **Limitless Scanning**: Can scan sites with 100GB+ of data without stressing the server.

### Powered by AI Agents

This project is unique because it is designed and built by a specialized team of AI Agents, each with a specific "Soul" and "Skillset".

*   **The Architect**: Ensures core stability and prevents timeouts.
*   **The Hunter**: Uses Deobfuscation & Entropy analysis to find hidden backdoors.
*   **The Auditor**: Finds SQL Injection & XSS vulnerabilities in custom code.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/wp-security-architect` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Use the Settings->Security Architect screen to configure the plugin (add your WPScan API Key).
4. Go to the Dashboard to start scanning.

== Frequently Asked Questions ==

= Do I need a WPScan API Key? =

The Async File Scanner works without any keys. However, to see the "CVE Monitor" (Plugin Vulnerabilities) dashboard, you need a free API key from wpscan.com.

= Will this slow down my site? =

No. The Async Engine is designed to run in the background with minimal impact. It pauses between requests to let normal visitor traffic pass through.

== Screenshots ==

1. The Security Architect Dashboard with Async Scan in progress.
2. The CVE Monitor showing vulnerable plugins.

== Changelog ==

= 1.0.0 =
* Initial Release.
* Added Async Incremental Scan Engine.
* Added CVE Monitor Dashboard (WPScan API integration).
