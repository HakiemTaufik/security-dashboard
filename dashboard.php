<?php
// Error display is controlled centrally by config.php based on APP_ENV.
// Do NOT enable display_errors here — sensitive paths and database
// details may leak to attackers in production.
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/crypto.php';

security_headers();
$user = Auth::requireLogin();

// Pull user's own recent activity
$logs = DB::query(
    "SELECT event_type, ip_address, device_info, threat_flag, created_at
     FROM auth_logs
     WHERE user_id = :uid
     ORDER BY id DESC LIMIT 20",
    ['uid' => $user['id']]
);

// Decrypt own PII for self-view (allowed: own data)
$emailPlain = $user['email_encrypted'] ? Crypto::decrypt($user['email_encrypted'], 'user-email') : null;
$icPlain    = $user['ic_encrypted']    ? Crypto::decrypt($user['ic_encrypted'], 'user-ic')      : null;

// Stats: own counts
$loginCount = DB::one("SELECT COUNT(*) c FROM auth_logs WHERE user_id=:u AND event_type='login_success'", ['u' => $user['id']]);
$failCount  = DB::one("SELECT COUNT(*) c FROM auth_logs WHERE user_id=:u AND event_type='login_failed'", ['u' => $user['id']]);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Dashboard · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <aside class="sidebar">
        <div class="brand">
            <h1><span class="logo">🛡️</span> Security</h1>
            <small>Employee Portal</small>
        </div>
        <nav>
            <a class="active" href="/dashboard.php">📊 My Dashboard</a>
            <a href="/change-password.php">🔑 Change Password</a>
            <a href="/logout.php">🚪 Sign out</a>
        </nav>
    </aside>

    <main class="main">
        <div class="topbar">
            <h2>Welcome, <?= h($user['full_name'] ?: $user['username']) ?></h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <div class="cards">
            <div class="card success">
                <div class="label">Successful Logins</div>
                <div class="value"><?= (int) $loginCount['c'] ?></div>
            </div>
            <div class="card warning">
                <div class="label">Failed Attempts</div>
                <div class="value"><?= (int) $failCount['c'] ?></div>
            </div>
            <div class="card info">
                <div class="label">Last Login</div>
                <div class="value" style="font-size: 16px;">
                    <?= $user['last_login_at'] ? h(relative_time($user['last_login_at'])) : 'First time!' ?>
                </div>
                <div class="delta">From <?= h($user['last_login_ip'] ?? 'unknown') ?></div>
            </div>
        </div>

        <div class="panel">
            <h3>My Profile <small>(PII protected by AES-256-GCM)</small></h3>
            <table>
                <tr><th style="width:200px">Username</th><td><?= h($user['username']) ?></td></tr>
                <tr><th>Full Name</th><td><?= h($user['full_name']) ?></td></tr>
                <tr><th>Email <small style="color:var(--text-faint)">(decrypted)</small></th>
                    <td><?= h($emailPlain ?? '—') ?></td></tr>
                <tr><th>IC / ID <small style="color:var(--text-faint)">(masked)</small></th>
                    <td><?= h(Crypto::maskIC($icPlain)) ?></td></tr>
                <tr><th>Account Status</th><td><?= status_badge($user['status']) ?></td></tr>
            </table>
        </div>

        <div class="panel">
            <h3>My Recent Activity <small>(<?= count($logs) ?> latest events)</small></h3>
            <table>
                <thead>
                    <tr>
                        <th>When</th>
                        <th>Event</th>
                        <th>IP Address</th>
                        <th>Device</th>
                        <th>Flag</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $r): ?>
                        <tr>
                            <td><?= h(relative_time($r['created_at'])) ?></td>
                            <td><?= h($r['event_type']) ?></td>
                            <td><code><?= h($r['ip_address']) ?></code></td>
                            <td style="color:var(--text-dim)"><?= h($r['device_info']) ?></td>
                            <td><span class="tag threat-<?= h($r['threat_flag']) ?>"><?= h($r['threat_flag']) ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (!$logs): ?>
                        <tr><td colspan="5" style="text-align:center;color:var(--text-faint);padding:32px">No activity yet.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
</body>
</html>
