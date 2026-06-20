<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/integrity_monitor.php';
require_once __DIR__ . '/../includes/session.php';

security_headers();
$user = Auth::requireConsole();

$ranCheck = false;
$result = null;

// Manual run still available — but now goes through IntegrityMonitor so it is
// recorded in history and notifies on failure, exactly like the cron job.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (SessionManager::csrfCheck($_POST['csrf'] ?? null)) {
        $ranCheck = true;
        $result = IntegrityMonitor::runFull('manual');
    }
}

$last = IntegrityMonitor::lastCheck();
$history = IntegrityMonitor::history(15);
$csrf = SessionManager::csrfToken();
$current = 'integrity';

function check_badge(string $status): string {
    if ($status === 'ok')       return '<span class="badge" style="background:rgba(16,185,129,.2);color:#86efac">OK</span>';
    if ($status === 'tampered') return '<span class="badge" style="background:rgba(239,68,68,.2);color:#fca5a5">TAMPERED</span>';
    return '<span class="badge" style="background:rgba(245,158,11,.2);color:#fcd34d">ERROR</span>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Integrity · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>
    <main class="main">
        <div class="topbar">
            <h2>🔐 Log Integrity Verification</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <?php if ($last): ?>
            <div class="alert-box <?= $last['status'] === 'ok' ? 'success' : 'error' ?>" style="font-size:14px">
                <?php if ($last['status'] === 'ok'): ?>
                    <strong>✓ Chain intact.</strong>
                    Last automated <?= h($last['check_type']) ?> check
                    <?= h(relative_time($last['created_at'])) ?>
                    verified <?= number_format((int) $last['rows_scanned']) ?> entries in <?= number_format((int) $last['duration_ms']) ?>ms.
                <?php else: ?>
                    <strong>⚠ INTEGRITY VIOLATION.</strong>
                    Last <?= h($last['check_type']) ?> check (<?= h(relative_time($last['created_at'])) ?>)
                    failed at log #<?= (int) $last['first_bad_id'] ?>. A critical alert has been raised
                    and administrators notified by email.
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="alert-box info" style="font-size:14px">
                No automated check has run yet. Confirm the cron job is configured (see <code>docs/DEPLOY.md</code>).
            </div>
        <?php endif; ?>

        <div class="panel">
            <h3>Automated Monitoring</h3>
            <p style="color:var(--text-dim);margin-bottom:12px">
                Verification runs automatically on a fixed schedule, not on demand:
            </p>
            <ul style="line-height:1.8;color:var(--text-dim);padding-left:20px;margin-bottom:12px">
                <li><strong>Incremental check — every 15 minutes.</strong> Verifies only log rows added since the last successful check (fast).</li>
                <li><strong>Full sweep — once daily (03:00 server time).</strong> Re-verifies the entire chain from the genesis row to catch tampering of older entries.</li>
            </ul>
            <p style="color:var(--text-dim);margin-bottom:12px">
                <?php if ($last): ?>
                    Last run: <strong><?= h($last['check_type']) ?></strong> check, <strong><?= h(relative_time($last['created_at'])) ?></strong>
                    (<?= h($last['created_at']) ?>).
                <?php else: ?>
                    No automated run has been recorded yet.
                <?php endif; ?>
                Any failure writes a critical alert and emails administrators automatically — no one has to remember to click a button.
            </p>
            <form method="post" style="margin-top:8px">
                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                <button class="btn primary" type="submit">▶ Run Full Verification Now</button>
                <small style="color:var(--text-faint);margin-left:8px">Optional — the schedule already does this.</small>
            </form>
        </div>

        <?php if ($ranCheck && $result): ?>
            <div class="alert-box <?= $result['status'] === 'ok' ? 'success' : 'error' ?>" style="font-size:14px">
                <strong><?= $result['status'] === 'ok' ? '✓' : '⚠' ?> Manual check complete.</strong>
                <?= h($result['message']) ?> (<?= number_format((int) $result['duration_ms']) ?>ms)
            </div>
        <?php endif; ?>

        <div class="panel">
            <h3>Recent Checks</h3>
            <table>
                <thead>
                    <tr><th>When</th><th>Type</th><th>Status</th><th>Rows</th><th>Duration</th><th>Detail</th></tr>
                </thead>
                <tbody>
                    <?php if (empty($history)): ?>
                        <tr><td colspan="6" style="color:var(--text-faint)">No checks recorded yet.</td></tr>
                    <?php else: foreach ($history as $c): ?>
                        <tr>
                            <td style="font-size:12px;color:var(--text-dim)"><?= h(relative_time($c['created_at'])) ?></td>
                            <td><?= h($c['check_type']) ?></td>
                            <td><?= check_badge($c['status']) ?></td>
                            <td><?= number_format((int) $c['rows_scanned']) ?></td>
                            <td><?= number_format((int) $c['duration_ms']) ?>ms</td>
                            <td style="font-size:12px;color:var(--text-dim)"><?= h($c['message'] ?? '') ?></td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>

        <div class="panel">
            <h3>How it works</h3>
            <ul style="line-height:1.8;color:var(--text-dim);padding-left:20px">
                <li>Each log row stores <code>integrity_hash</code> and <code>prev_hash</code>; the first row uses a genesis hash of 64 zeros.</li>
                <li><code>integrity_hash = BLAKE3-keyed(K, prev_hash || canonical_row)</code> with the server secret <code>BLAKE3_CTX_KEY_HEX</code>.</li>
                <li><strong>Incremental</strong> checks verify only rows after the last good checkpoint — fast, run often.</li>
                <li><strong>Full</strong> sweeps re-verify from genesis to catch tampering of older rows — run daily off-peak.</li>
                <li>Any mismatch cascades: the first failing row pinpoints where tampering occurred.</li>
            </ul>
        </div>
    </main>
</div>
</body>
</html>
