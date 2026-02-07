<?php

namespace My_Tiny_Uploads_Guard\Scanner;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Class Rules
 * Defines the security rules for the scanner.
 */
class Rules
{

    /**
     * Allowed file extensions (Allowlist).
     *
     * @var array
     */
    const ALLOWED_EXTENSIONS = array(
        'jpg',
        'jpeg',
        'png',
        'gif',
        'webp',
        'svg',
        'mp3',
        'mp4',
        'mov',
        'avi',
        'pdf',
        'doc',
        'docx',
        'ppt',
        'pptx',
        'xls',
        'xlsx',
        'zip',
        'rar',
        'txt',
        'csv',
        'css', // Sometimes used in uploads, but debatable. Keeping for now.
    );

    /**
     * Blocked file extensions (Blocklist).
     * Strictly forbidden in uploads for security.
     *
     * @var array
     */
    const BLOCKED_EXTENSIONS = array(
        'php',
        'php5',
        'php7',
        'phtml',
        'phar',
        'pl',
        'py',
        'cgi',
        'asp',
        'aspx',
        'exe',
        'sh',
        'bat',
        'cmd',
    );

    /**
     * Suspicious directory patterns.
     *
     * @var array
     */
    const SUSPICIOUS_DIR_PATTERNS = array(
        '/^\./',          // Hidden directories (.git, .secret)
        '/^cache$/i',     // Fake cache folders
        '/^tmp$/i',       // Fake tmp folders
        '/^temp$/i',
        '/^backup$/i',
    );

    /**
     * Check a file for threats.
     *
     * @param \SplFileInfo $file The file object.
     * @return array|null The threat details or null if safe.
     */
    public static function check_file($file)
    {
        $filename  = $file->getFilename();
        $path      = $file->getPathname();
        $extension = strtolower($file->getExtension());

        // 1. Check Directory
        if ($file->isDir()) {
            foreach (self::SUSPICIOUS_DIR_PATTERNS as $pattern) {
                if (preg_match($pattern, $filename)) {
                    return array(
                        'type'        => 'suspicious_directory',
                        'file'        => $path,
                        'description' => __('Suspicious hidden or fake system directory found.', 'my-tiny-uploads-guard'),
                        'severity'    => 'medium',
                    );
                }
            }
            return null;
        }

        // 2. Check Extension (Blocklist - High Priority)
        if (in_array($extension, self::BLOCKED_EXTENSIONS, true)) {
            return array(
                'type'        => 'blocked_extension',
                'file'        => $path,
                'description' => sprintf(__('Executable file type (%s) found in uploads.', 'my-tiny-uploads-guard'), $extension),
                'severity'    => 'critical',
            );
        }

        // 3. Check Extension (Allowlist - Medium Priority)
        if (! empty($extension) && ! in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            // Double check for complex extensions (e.g., .php.jpg)
            if (strpos($filename, '.php') !== false) {
                return array(
                    'type'        => 'double_extension',
                    'file'        => $path,
                    'description' => __('Suspicious double extension (potential camouflage).', 'my-tiny-uploads-guard'),
                    'severity'    => 'high',
                );
            }

            return array(
                'type'        => 'unknown_extension',
                'file'        => $path,
                'description' => sprintf(__('Unknown file type (%s). Not in allowlist.', 'my-tiny-uploads-guard'), $extension),
                'severity'    => 'low',
            );
        }

        return null; // Safe
    }
}
