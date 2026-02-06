<?php

namespace WPSA\Core;

if (! defined('ABSPATH')) {
    exit;
}

class Scanner
{

    private $root_dir;
    private $time_limit = 2.5; // Seconds (Safety buffer for 30s limit)
    private $hunter;
    private $result_service;

    public function __construct($root_dir = ABSPATH)
    {
        $this->root_dir = $root_dir;
        $this->hunter   = new Hunter();
        $this->result_service = new \WPSA\Services\ResultService();
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
        if ($file->isFile()) {
            $result = $this->hunter->analyze($file->getPathname());
            if ($result) {
                // Suspicious!
                // Save to DB
                $this->result_service->add_issue(
                    $file->getPathname(),
                    $result['type'],
                    $result['score'],
                    $result['message']
                );
            }
        }
    }
}
