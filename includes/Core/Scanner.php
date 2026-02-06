<?php

namespace WPSA\Core;

if (! defined('ABSPATH')) {
    exit;
}

class Scanner
{

    private $root_dir;
    private $time_limit = 2.5; // Seconds (Safety buffer for 30s limit)

    public function __construct($root_dir = ABSPATH)
    {
        $this->root_dir = $root_dir;
    }

    /**
     * Run the scan for a brief slice of time
     * 
     * @param int $offset How many files to skip (where we left off)
     * @return array Status and new offset
     */
    public function scan($offset = 0)
    {
        $files_processed = 0;
        $start_time = microtime(true);

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($this->root_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore permission deny
            );
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => 'Failed to initialize iterator: ' . $e->getMessage()
            ];
        }

        foreach ($iterator as $path => $file) {
            // 1. Skip previously scanned files (The Fast Forward)
            // Note: In Phase 2 optimization, we should use a file index instead of iterating to skip.
            if ($files_processed < $offset) {
                $files_processed++;
                continue;
            }

            // 2. Time Check (The Watchdog)
            if ((microtime(true) - $start_time) > $this->time_limit) {
                return [
                    'status' => 'partial',
                    'offset' => $files_processed,
                    'current_file' => $path,
                    'progress' => 50 // TODO: calculate real percentage
                ];
            }

            // 3. The actual work (will be delegated to Hunter/Auditor later)
            // For now, we just touch user provided callback or log
            $this->inspect_file($file);

            $files_processed++;
        }

        return [
            'status' => 'complete',
            'offset' => $files_processed,
            'message' => 'Scan finished successfully.'
        ];
    }

    private function inspect_file($file)
    {
        // Placeholder for Hunter/Auditor Logic
        // In the future: $hunter->analyze($file);
    }
}
