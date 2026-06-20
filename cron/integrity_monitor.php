<?php
/**
 * ============================================================
 * Scheduled Integrity Check  (comment #2)
 * ============================================================
 * Run by Hostinger's cron scheduler. Two ways to invoke:
 *
 *   1. CLI (preferred):
 *        php /home/USER/public_html/cron/integrity_monitor.php
 *        php /home/USER/public_html/cron/integrity_monitor.php --full
 *
 *   2. URL with a secret token (if only URL cron is available):
 *        https://yourdomain/cron/integrity_monitor.php?token=YOURTOKEN
 *        https://yourdomain/cron/integrity_monitor.php?token=YOURTOKEN&full=1
 *      Set the token first:  export CRON_TOKEN=...  (hPanel env var)
 *
 * Suggested schedule (crontab):
 *   - Incremental, every 15 minutes:   slash-15 in the minute field, no --full
 *   - Full sweep, daily at 03:00:      0 3 * * *  with --full
 *
 * Example crontab lines (the minute field uses step syntax, written in words
 * below so this PHP comment block stays valid):
 *     every-15-min  ->  minute field "[asterisk][slash]15", rest "* * * *"
 *                       php .../cron/integrity_monitor.php
 *     daily-3am     ->  "0 3 * * *"
 *                       php .../cron/integrity_monitor.php --full
 * ============================================================
 */

require_once __DIR__ . '/../includes/integrity_monitor.php';

$isCli = (PHP_SAPI === 'cli');

// Decide full vs incremental
$full = false;
if ($isCli) {
    $full = in_array('--full', $argv ?? [], true);
} else {
    // URL invocation MUST present the secret token.
    $expected = getenv('CRON_TOKEN') ?: '';
    $given    = $_GET['token'] ?? '';
    if ($expected === '' || !hash_equals($expected, (string) $given)) {
        http_response_code(403);
        header('Content-Type: text/plain');
        echo "Forbidden\n";
        exit;
    }
    $full = !empty($_GET['full']);
}

$result = $full
    ? IntegrityMonitor::runFull('full')
    : IntegrityMonitor::runIncremental();

$line = sprintf(
    "[%s] %s check: status=%s rows=%d %s (%dms)\n",
    date('Y-m-d H:i:s'),
    $full ? 'FULL' : 'INCREMENTAL',
    strtoupper($result['status']),
    $result['rows_scanned'],
    $result['first_bad_id'] ? ('first_bad=#' . $result['first_bad_id']) : '',
    $result['duration_ms']
);

if (!$isCli) header('Content-Type: text/plain');
echo $line;

// Non-zero exit on tamper/error so cron mail / monitoring catches it.
exit($result['status'] === 'ok' ? 0 : 1);
