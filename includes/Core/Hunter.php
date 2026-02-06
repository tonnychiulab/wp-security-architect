<?php

namespace WPSA\Core;

if (! defined('ABSPATH')) {
    exit;
}

class Hunter
{

    /**
     * Analyze a file for malware
     * 
     * @param string $file_path Absolute path to file
     * @return array|false False if clean, Array with reason if suspicious
     */
    public function analyze($file_path)
    {
        // Only scan PHP, HTML, JS files
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        if (! in_array($ext, ['php', 'html', 'htm', 'js'])) {
            return false;
        }

        $content = file_get_contents($file_path);
        if (false === $content) {
            return false; // Skip unreadable files
        }

        // Layer 1: Checksum (Whitelist) - TODO in Phase 2.1
        // if ( $this->is_checksum_valid( $file_path ) ) { return false; }

        // Layer 1: Entropy (High Randomness)
        $entropy = $this->calculate_entropy($content);
        if ($entropy > 5.5) {
            return [
                'type' => 'SUSPICIOUS_HIGH_ENTROPY',
                'score' => $entropy,
                'message' => 'High entropy detected (Score: ' . number_format($entropy, 2) . '). Possible obfuscated code.'
            ];
        }

        // Layer 2: Signatures (YARA-like)
        // If entropy is moderately high (> 4.8) OR file is small (< 50KB), check signatures
        // This optimizes performance by not regexing every single large file
        $filesize = filesize($file_path);
        if (($entropy > 4.5) || ($filesize < 51200)) {
            $sig_match = $this->scan_signatures($content);
            if ($sig_match) {
                return $sig_match;
            }
        }

        return false; // Clean
    }

    /**
     * Calculate Shannon Entropy
     * H(X) = -sum( P(xi) * log2(P(xi)) )
     */
    private function calculate_entropy($string)
    {
        $h = 0;
        $size = strlen($string);

        if ($size == 0) {
            return 0;
        }

        $data = count_chars($string, 1);

        foreach ($data as $frequency) {
            $p = $frequency / $size;
            $h -= $p * log($p) / log(2);
        }

        return $h;
    }

    /**
     * Layer 2: Signature Scanning
     */
    private function scan_signatures($content)
    {
        $signatures = [
            'eval_base64' => '/eval\s*\(\s*base64_decode\s*\(/i',
            'gzinflate_base64' => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
            'shell_exec_hidden' => '/shell_exec\s*\(\s*[\'"]/',
            'globals_obfuscation' => '/\$GLOBALS\s*\[\s*[\'"]\w+[\'"]\s*\]\s*=/'
        ];

        foreach ($signatures as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                return [
                    'type' => 'MALWARE_SIGNATURE',
                    'score' => 10.0, // Confirmed hit
                    'message' => 'Malware signature detected: ' . $name
                ];
            }
        }

        return false;
    }
}
