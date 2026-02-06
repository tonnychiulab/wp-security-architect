jQuery(document).ready(function($) {
    const $startBtn = $('#wpsa-start-scan');
    const $progressSection = $('#wpsa-scan-progress');
    const $progressBar = $('.wpsa-progress-fill');
    const $statusText = $('#wpsa-current-file');

    $startBtn.on('click', function(e) {
        e.preventDefault();
        
        // Reset UI
        $startBtn.addClass('disabled').prop('disabled', true).text('Scanning...');
        $progressSection.show();
        $progressBar.css('width', '1%');
        updateStatus('Initializing scan engine...');

        // Start the loop
        runScanStep(0);
    });

    function runScanStep(offset) {
        $.ajax({
            url: wpsaParams.ajaxUrl,
            type: 'POST',
            data: {
                action: 'wpsa_scan',
                nonce: wpsaParams.nonce,
                offset: offset
            },
            success: function(response) {
                if (!response.success) {
                    handleError(response.data || 'Unknown error');
                    return;
                }

                const data = response.data;
                const progress = Math.min(data.progress || 0, 99); // Fake progress for now if backend doesn't calculate
                
                // Update UI
                updateStatus('Scanning: ' + (data.current_file || 'Processing...'));
                $progressBar.css('width', progress + '%');

                if (data.status === 'complete') {
                    handleComplete();
                } else if (data.status === 'partial') {
                    // Recursive call - The Ant moves to the next stone
                    // Small delay to let browser breathe (optional, but good for UI responsiveness)
                    setTimeout(function() {
                        runScanStep(data.offset);
                    }, 50); 
                }
            },
            error: function(xhr, status, error) {
                handleError('Server Error: ' + error);
            }
        });
    }

    function updateStatus(msg) {
        $statusText.text(msg);
    }

    function handleComplete() {
        $progressBar.css('width', '100%');
        updateStatus('Scan Complete! The Architect is satisfied.');
        $startBtn.removeClass('disabled').prop('disabled', false).text('Scan Again');
        
        // Maybe trigger a reload or show report button
        alert('Scan Finished Successfully!');
    }

    function handleError(msg) {
        updateStatus('Error: ' + msg);
        $startBtn.removeClass('disabled').prop('disabled', false).text('Retry Scan');
        $progressSection.find('.wpsa-progress-bar').css('background', '#f8d7da'); // Red background
    }
});
