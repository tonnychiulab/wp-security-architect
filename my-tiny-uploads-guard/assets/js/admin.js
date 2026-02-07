jQuery(document).ready(function ($) {
    const $startBtn = $('#mtug-start-scan');
    const $progressBar = $('#mtug-progress-bar');
    const $progressContainer = $('.mtug-progress-container');
    const $statusText = $('#mtug-status-text');
    const $scannedCount = $('#mtug-scanned-count');
    const $resultsArea = $('.mtug-results-area');
    const $resultsTableBody = $('#mtug-results-table tbody');

    // Stats Elements
    const $statFiles = $('#mtug-stat-files');
    const $statDirs = $('#mtug-stat-dirs');
    const $statSafe = $('#mtug-stat-safe');

    // Debug: Confirm JS Version
    console.log('MTUG Admin JS v1.0.28 loaded');
    $statusText.append(' (v1.0.28)');

    // Sorting & Filtering State
    let currentSort = {
        column: 'severity', // Default
        order: 'desc'
    };
    let currentFilter = 'all'; // 'all', 'file', 'dir'

    // Pagination Elements
    const $pagination = $('.mtug-pagination');
    const $prevBtn = $('#mtug-page-prev');
    const $nextBtn = $('#mtug-page-next');
    const $currentPageSpan = $('#mtug-current-page');
    const $totalPagesSpan = $('#mtug-total-pages');

    // Stats Card Interactions
    $('.mtug-stat-card').on('click', function () {
        const $card = $(this);

        // Remove active class from all first
        $('.mtug-stat-card').removeClass('active');

        if ($card.hasClass('card-suspicious-files')) {
            if (currentFilter === 'file') {
                currentFilter = 'all'; // Toggle off
            } else {
                currentFilter = 'file';
                $card.addClass('active');
                // Auto-sort by severity desc when filter applied
                currentSort.column = 'severity';
                currentSort.order = 'desc';
            }
        } else if ($card.hasClass('card-suspicious-dirs')) {
            if (currentFilter === 'dir') {
                currentFilter = 'all'; // Toggle off
            } else {
                currentFilter = 'dir';
                $card.addClass('active');
                // Auto-sort by severity desc when filter applied
                currentSort.column = 'severity';
                currentSort.order = 'desc';
            }
        } else if ($card.hasClass('card-safe')) {
            alert('Safe files are clean and not listed here. Good job!');
            return;
        }

        currentPage = 1;
        renderResultsTable();
    });

    // Sort Headers
    $('th.sortable').on('click', function () {
        const column = $(this).data('sort');
        if (currentSort.column === column) {
            // Toggle order
            currentSort.order = (currentSort.order === 'asc') ? 'desc' : 'asc';
        } else {
            currentSort.column = column;
            currentSort.order = 'asc'; // Default new col to asc
        }
        renderResultsTable();
    });

    function getSeverityWeight(sev) {
        if (!sev) return 0;
        switch (sev.toLowerCase()) {
            case 'critical': return 3;
            case 'high': return 2;
            case 'medium': return 1;
            default: return 0;
        }
    }

    function sortThreats(threats) {
        return threats.sort((a, b) => {
            let valA, valB;

            try {
                if (currentSort.column === 'severity') {
                    valA = getSeverityWeight(a.severity);
                    valB = getSeverityWeight(b.severity);
                } else if (currentSort.column === 'file') {
                    valA = (a.file || '').toLowerCase();
                    valB = (b.file || '').toLowerCase();
                } else if (currentSort.column === 'mtime') {
                    valA = a.mtime || 0;
                    valB = b.mtime || 0;
                } else {
                    valA = (a[currentSort.column] || '').toLowerCase();
                    valB = (b[currentSort.column] || '').toLowerCase();
                }
            } catch (e) {
                console.warn('Error comparing items:', e);
                return 0;
            }

            if (valA < valB) return currentSort.order === 'asc' ? -1 : 1;
            if (valA > valB) return currentSort.order === 'asc' ? 1 : -1;
            return 0;
        });
    }

    let currentOffset = 0;
    let isScanning = false;
    let totalScanned = 0;

    // Results Storage
    let allThreats = [];
    let countSuspiciousFiles = 0;
    let countSuspiciousDirs = 0;

    // Pagination State
    const itemsPerPage = 10;
    let currentPage = 1;

    $startBtn.on('click', function () {
        if (isScanning) return;

        // Init Scan
        isScanning = true;
        currentOffset = 0;
        totalScanned = 0;
        countSuspiciousFiles = 0;
        countSuspiciousDirs = 0;
        allThreats = []; // Clear previous results
        currentPage = 1;
        currentFilter = 'all'; // Reset filter on new scan
        $('.mtug-stat-card').removeClass('active');

        // Reset UI
        $startBtn.prop('disabled', true);
        $progressContainer.parent().show(); // Show progress area
        $progressContainer.addClass('scanning');
        $statusText.text(mtugObj.strings.scanning).removeClass().addClass('status-scanning');
        $progressBar.css('width', '5%');
        $resultsArea.hide();
        $resultsTableBody.empty();
        $scannedCount.text('0');
        $pagination.hide();

        // Reset Stats Cards
        $statFiles.text('0');
        $statDirs.text('0');
        $statSafe.text('0');

        // Clear Log
        $('#mtug-debug-log').empty();
        logMessage('Starting scan...');

        scanBatch();
    });

    function scanBatch() {
        logMessage('Requesting batch at offset: ' + currentOffset);
        $.ajax({
            url: mtugObj.ajaxUrl,
            type: 'POST',
            data: {
                action: 'mtug_scan',
                nonce: mtugObj.nonce,
                offset: currentOffset
            },
            success: function (response) {
                logMessage('AJAX Response received. Success: ' + response.success);
                if (response.success) {
                    handleScanSuccess(response.data);
                } else {
                    handleScanError(response.data);
                }
            },
            error: function (xhr, status, error) {
                logMessage('AJAX Network Error: ' + status + ' - ' + error);
                handleScanError('Network error: ' + error);
            }
        });
    }

    function handleScanSuccess(data) {
        logMessage('Processing batch data...');
        try {
            // Update stats
            totalScanned += data.scanned;
            currentOffset = data.offset;
            $scannedCount.text(totalScanned);

            // Update Progress Bar
            let currentWidth = parseFloat($progressBar[0].style.width) || 0;
            if (currentWidth < 90) {
                $progressBar.css('width', (currentWidth + 2) + '%');
            }

            // Handle Results
            if (data.results && Array.isArray(data.results) && data.results.length > 0) {
                logMessage('Found ' + data.results.length + ' threats in this batch.');
                data.results.forEach(threat => {
                    allThreats.push(threat);

                    // Logic based counters
                    if (threat.type === 'suspicious_directory') {
                        countSuspiciousDirs++;
                    } else {
                        countSuspiciousFiles++;
                    }
                });
                // Update Stats Display
                $statDirs.text(countSuspiciousDirs);
                $statFiles.text(countSuspiciousFiles);
            }

            // Update Safe Count
            let safeCount = totalScanned - (countSuspiciousFiles + countSuspiciousDirs);
            if (safeCount < 0) safeCount = 0;
            $statSafe.text(safeCount);

            // Render Current Page
            logMessage('Rendering results table...');
            renderResultsTable();

            // Check if finished
            if (data.is_finished) {
                logMessage('Scan finished. Total checked: ' + totalScanned);
                finishScan();
            } else {
                // Next Batch
                logMessage('Batch complete. Next offset: ' + data.offset);
                scanBatch();
            }
        } catch (e) {
            console.error(e);
            logMessage('CRITICAL JS Error: ' + e.message);
            logMessage('Stack: ' + e.stack);
            handleScanError('JS Error: ' + e.message);
        }
    }

    function handleScanError(message) {
        logMessage('Error Handler Triggered: ' + message);
        $statusText.text(mtugObj.strings.error + ': ' + message).removeClass().addClass('status-error');
        isScanning = false;
        $startBtn.prop('disabled', false);
        $progressContainer.removeClass('scanning');
        $progressBar.css('background-color', '#d63638');
    }

    function finishScan() {
        isScanning = false;
        $statusText.text(mtugObj.strings.complete).removeClass().addClass('status-complete');
        $startBtn.prop('disabled', false);
        $progressContainer.removeClass('scanning');
        $progressBar.css('width', '100%');

        // Update Backend Stats
        const hasThreats = (allThreats.length > 0);
        const status = hasThreats ? 'threat_found' : 'safe';

        // Log to console for debug
        console.log('Sending stats update:', { status, count: totalScanned });

        $.post(mtugObj.ajaxUrl, {
            action: 'mtug_update_stats',
            nonce: mtugObj.nonce,
            status: status,
            count: totalScanned
        }, function (response) {
            if (response.success) {
                console.log('Stats updated successfully', response);
                updateDashboardCards(status, totalScanned, 'Just now');
            } else {
                console.error('Failed to update stats', response);
            }
        }).fail(function (xhr, status, error) {
            console.error('Stats update failed', error);
        });
    }

    function updateDashboardCards(status, count, timeLabel) {
        // 1. Status
        const $statusCircle = $('.mtug-circle-status');
        const $statusText = $('#mtug-dash-status');

        $statusCircle.removeClass('safe threat');
        if (status === 'threat_found') {
            $statusCircle.addClass('threat');
            $statusText.text('Action Needed'); // Or localize if passed from PHP
        } else {
            $statusCircle.addClass('safe');
            $statusText.text('Protected');
        }

        // 2. Count
        $('#mtug-dash-count').text(new Intl.NumberFormat().format(count) + ' Files');

        // 3. Time
        $('#mtug-dash-time').text(timeLabel); // 'Just now' or timestamp
    }

    function logMessage(msg) {
        const time = new Date().toLocaleTimeString();
        const $log = $('#mtug-debug-log');
        $log.append(`[${time}] ${msg}\n`);
        $log.scrollTop($log[0].scrollHeight);
    }

    // --- Pagination Logic ---
    $('#mtug-search-input').on('keyup', function () {
        currentPage = 1; // Reset to page 1 on search
        renderResultsTable();
    });

    function renderResultsTable() {
        // 1. Filter Data (Search + Category)
        const searchTerm = $('#mtug-search-input').val().toLowerCase().trim();
        let filteredThreats = allThreats;

        // Apply Search Filter
        if (searchTerm) {
            filteredThreats = filteredThreats.filter(t => {
                return (t.file && t.file.toLowerCase().includes(searchTerm)) ||
                    (t.severity && t.severity.toLowerCase().includes(searchTerm)) ||
                    (t.type && t.type.toLowerCase().includes(searchTerm)) ||
                    (t.description && t.description.toLowerCase().includes(searchTerm));
            });
        }

        // Apply Category Filter
        if (currentFilter === 'file') {
            filteredThreats = filteredThreats.filter(t => t.type !== 'suspicious_directory');
        } else if (currentFilter === 'dir') {
            filteredThreats = filteredThreats.filter(t => t.type === 'suspicious_directory');
        }

        if (filteredThreats.length === 0) {
            $resultsArea.show(); // Keep area visible
            $resultsTableBody.html('<tr><td colspan="6" style="text-align:center; padding: 20px;">No results found matching your criteria.</td></tr>');
            $pagination.hide();
            return;
        }

        $resultsArea.show();
        $resultsTableBody.empty();

        // Update Sort Headers classes
        $('th.sortable').removeClass('sorted-asc sorted-desc');
        $('th[data-sort="' + currentSort.column + '"]').addClass('sorted-' + currentSort.order);

        // Sorting
        let sortedThreats = sortThreats([...filteredThreats]);

        const totalPages = Math.ceil(sortedThreats.length / itemsPerPage);

        // Adjust current page if out of bounds
        if (currentPage > totalPages) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;

        // Update Pagination Controls
        if (totalPages > 1) {
            $pagination.show();
            $currentPageSpan.text(currentPage);
            $totalPagesSpan.text(totalPages);
            $prevBtn.prop('disabled', currentPage === 1);
            $nextBtn.prop('disabled', currentPage === totalPages);
        } else {
            $pagination.hide();
        }

        // Slice data
        const start = (currentPage - 1) * itemsPerPage;
        const end = start + itemsPerPage;
        const pageItems = sortedThreats.slice(start, end);

        pageItems.forEach(threat => {
            addThreatRow(threat);
        });
    }

    $prevBtn.on('click', function () {
        if (currentPage > 1) {
            currentPage--;
            renderResultsTable();
        }
    });

    $nextBtn.on('click', function () {
        const totalPages = Math.ceil(allThreats.length / itemsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            renderResultsTable();
        }
    });

    // Handle Delete
    $(document).on('click', '.mtug-delete-btn', function (e) {
        e.preventDefault();

        const $btn = $(this);
        const $row = $btn.closest('tr');
        const filePath = $row.data('file');

        // Get visual filename for better UX
        const visualName = $row.find('.mtug-path-file').text() || filePath;

        // Custom confirm message with filename
        // Using a template literal for better readability
        const confirmMsg = mtugObj.strings.confirm.replace('%s', visualName);

        if (!confirm(confirmMsg)) {
            return;
        }

        $btn.prop('disabled', true).text('...');

        $.ajax({
            url: mtugObj.ajaxUrl,
            type: 'POST',
            data: {
                action: 'mtug_delete',
                nonce: mtugObj.nonce,
                file: filePath
            },
            success: function (response) {
                if (response.success) {
                    // Remove from data source
                    allThreats = allThreats.filter(t => t.file !== filePath);

                    // Re-calculate stats - brute force or incremental? 
                    // Incremental is risky if array desyncs, let's just decrement.
                    // But we don't know type easily here without lookup.
                    // Let's look it up
                    // Actually simpler to just re-render page. 

                    renderResultsTable();
                } else {
                    alert(response.data);
                    $btn.prop('disabled', false).text(mtugObj.strings.delete);
                }
            },
            error: function () {
                alert('Network error');
                $btn.prop('disabled', false).text(mtugObj.strings.delete);
            }
        });
    });

    // Handle Hash Copy
    $(document).on('click', '.mtug-copy-hash', function (e) {
        e.preventDefault();
        const $btn = $(this);
        const hash = $btn.data('hash');
        const originalIcon = '<span class="dashicons dashicons-admin-page" style="line-height:24px;"></span>';

        navigator.clipboard.writeText(hash).then(() => {
            $btn.html('<span class="dashicons dashicons-yes" style="line-height:24px; color:#00a32a;"></span>');
            setTimeout(() => {
                $btn.html(originalIcon);
            }, 1500);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            // Fallback for older browsers? Not needed for modern WP admin usually, but good practice.
            // Simplified fallback:
            const textArea = document.createElement("textarea");
            textArea.value = hash;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                $btn.html('<span class="dashicons dashicons-yes" style="line-height:24px; color:#00a32a;"></span>');
            } catch (err) {
                console.error('Fallback copy fail', err);
                alert('Could not copy hash automatically: ' + hash);
            }
            document.body.removeChild(textArea);
            setTimeout(() => {
                $btn.html(originalIcon);
            }, 1500);
        });
    });

    function formatDate(timestamp) {
        if (!timestamp) return '-';
        return new Date(timestamp * 1000).toLocaleString();
    }

    function addThreatRow(threat) {
        if (!threat || !threat.file) {
            logMessage('Warning: Invalid threat object encountered.');
            return;
        }
        // Calculate Relative Path Logic
        let fullPath = (threat.file || '').replace(/\\/g, '/'); // Normalize slashes
        let baseDir = (mtugObj.uploadBasedir || '').replace(/\\/g, '/');

        let relativePath = fullPath;

        // Try strict replacement
        if (fullPath.startsWith(baseDir)) {
            relativePath = fullPath.replace(baseDir, '');
        } else {
            // Fallback: Try to find '/wp-content/uploads/'
            const uploadMarker = '/wp-content/uploads/';
            const idx = fullPath.indexOf(uploadMarker);
            if (idx !== -1) {
                relativePath = fullPath.substring(idx + uploadMarker.length);
            }
        }

        // Remove leading slash
        if (relativePath.startsWith('/')) {
            relativePath = relativePath.substring(1);
        }

        // Split folder and filename for styling
        let lastSlash = relativePath.lastIndexOf('/');
        let folderPart = '';
        let filePart = relativePath;

        if (lastSlash !== -1) {
            folderPart = relativePath.substring(0, lastSlash + 1);
            filePart = relativePath.substring(lastSlash + 1);
        } else {
            // No folder, just file in root of uploads
            folderPart = '(root)/';
        }

        // Use description if available, fallback to details (legacy)
        const description = threat.description || threat.details || '';

        let typeClass = '';
        if (threat.type === 'suspicious_directory') {
            typeClass = 'mtug-path-folder';
        } else {
            typeClass = 'mtug-path-file';
        }

        const severityClass = (threat.severity || 'low').toLowerCase();

        // Hash Actions
        let hashActions = '';
        if (threat.hash) {
            // VirusTotal Link
            hashActions += `<a href="https://www.virustotal.com/gui/file/${threat.hash}" target="_blank" class="button button-small mtug-action-btn mtug-vt-btn" title="Check on VirusTotal"><span class="dashicons dashicons-shield"></span></a>`;

            // Copy Hash Button
            hashActions += `<button type="button" class="button button-small mtug-action-btn mtug-copy-hash" data-hash="${threat.hash}" title="Copy SHA-256 Hash"><span class="dashicons dashicons-admin-page"></span></button>`;
        }

        const row = `
            <tr class="mtug-row-${severityClass}" data-file="${escapeHtml(fullPath)}">
                <td><span class="mtug-severity-${severityClass}">${(threat.severity || '').toUpperCase()}</span></td>
                <td>${escapeHtml(threat.type)}</td>
                <td class="mtug-path-cell" title="${escapeHtml(fullPath)}">
                    <span class="mtug-path-folder">${escapeHtml(folderPart)}</span><span class="${typeClass}">${escapeHtml(filePart)}</span>
                </td>
                <td style="color: #50575e; font-size: 0.9em;">${formatDate(threat.mtime)}</td>
                <td>${escapeHtml(description)}</td>
                <td class="mtug-action-cell">
                    <div class="mtug-action-group">
                        ${hashActions}
                        <button class="button button-small button-link-delete mtug-delete-btn" title="${mtugObj.strings.delete}"><span class="dashicons dashicons-trash" style="line-height:24px;"></span></button>
                    </div>
                </td>
            </tr>
        `;
        $resultsTableBody.append(row);
    }
    function escapeHtml(text) {
        if (!text) return '';
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
