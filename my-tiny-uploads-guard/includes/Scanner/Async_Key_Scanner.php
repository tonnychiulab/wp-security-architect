<?php

namespace My_Tiny_Uploads_Guard\Scanner;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Class Async_Key_Scanner
 * Handles the async scanning logic.
 */
class Async_Key_Scanner
{

    /**
     * Scan limit per batch.
     *
     * @var int
     */
    const BATCH_SIZE = 50;

    /**
     * Run a scan batch.
     *
     * @param int $offset The offset to start scanning from.
     * @return array The scan results and next offset.
     */
    public function scan_batch($offset = 0)
    {
        $start_time = microtime(true);
        $time_limit = 15; // Max 15 seconds per batch to prevent timeouts

        $upload_dir = \wp_upload_dir();
        $base_dir   = $upload_dir['basedir'];

        if (! is_dir($base_dir)) {
            return array(
                'status'  => 'error',
                'message' => 'Uploads directory not found.',
            );
        }

        try {
            // [PHP Knowledge] 遞迴迭代器 (Recursive Directory Iterator)
            // 這是一個 PHP 內建的強大工具，它可以幫我們「鑽進去」每一個子資料夾。
            // 想像它是一個全自動的機器人，會把所有檔案一個一個拿給我們檢查。
            // SKIP_DOTS: 叫它不要理會 "." 和 ".." 這種系統虛擬目錄。
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($base_dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );
        } catch (\Exception $e) {
            return array(
                'status'  => 'error',
                'message' => 'Iterator Error: ' . $e->getMessage(),
            );
        }

        $count   = 0;
        $scanned = 0;
        $results = array();

        // [Algorithm - Offset 的秘密與代價]
        // 我們的 AJAX 掃描就像「翻書」一樣，一次只讀 50 頁 (BATCH_SIZE)。
        // $offset 就是告訴我們「上次讀到第幾頁了」。
        // 
        // ⚠️ 這裡有個效能小代價 (Trade-off)：
        // PHP 的迭代器沒有「瞬間移動」的功能。所以如果我們要讀第 1000 頁，
        // 它還是得從第 1 頁快速翻過 999 頁才能到達。
        // 當檔案有幾萬個的時候，越後面翻頁會越慢。
        // 但為了保持這個外掛「Tiny (輕量)」，不寫複雜的資料庫紀錄，這是我們可以接受的犧牲。
        foreach ($iterator as $path => $file) {
            // [Timeout Protection]
            // 如果這一次跑太久 (超過 15 秒)，我們就先暫停，
            // 讓伺服器喘口氣 (回傳結果給前端)，下次再繼續。這樣才不會讓網站卡死。
            if ((microtime(true) - $start_time) > $time_limit) {
                break;
            }

            if ($count < $offset) {
                $count++;
                continue;
            }

            if ($scanned >= self::BATCH_SIZE) {
                break;
            }

            try {
                // Core Scanning Logic
                $threat = Rules::check_file($file);
                if ($threat) {
                    $threat['mtime'] = filemtime($file->getPathname());
                    // Add SHA-256 Hash for VirusTotal
                    $threat['hash']  = hash_file('sha256', $file->getPathname());
                    $results[] = $threat;
                }
            } catch (\Exception $e) {
                // Log/Ignore single file error
                error_log('MTUG File Error: ' . $e->getMessage());
            }

            $count++;
            $scanned++;
        }

        // Finished if we didn't hit batch size AND didn't time out
        // If we timed out, we consider it NOT finished so JS requests next batch (at current count)
        $msg_suffix = '';
        $is_timeout = (microtime(true) - $start_time) > $time_limit;

        if ($is_timeout) {
            $is_finished = false;
        } else {
            // 如果本次掃描數量少於 BATCH_SIZE，代表檔案已經掃光光了，沒有下一頁了。
            $is_finished = ($scanned < self::BATCH_SIZE);
        }

        return array(
            'status'      => 'success',
            'offset'      => $count,
            'scanned'     => $scanned,
            'is_finished' => $is_finished,
            'results'     => $results,
            'debug_time'  => round(microtime(true) - $start_time, 4)
        );
    }
}
