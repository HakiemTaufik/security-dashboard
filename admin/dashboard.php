<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';

security_headers();
$user = Auth::requireConsole();

// --- Stats ---
$totalUsers = (int) (DB::one("SELECT COUNT(*) c FROM users")['c'] ?? 0);
$activeSessions = (int) (DB::one("SELECT COUNT(*) c FROM active_sessions WHERE expires_at > NOW()")['c'] ?? 0);
$openAlerts = (int) (DB::one("SELECT COUNT(*) c FROM alerts WHERE status='open'")['c'] ?? 0);
$failed24h = (int) (DB::one("SELECT COUNT(*) c FROM auth_logs WHERE event_type='login_failed' AND created_at >= NOW() - INTERVAL 24 HOUR")['c'] ?? 0);
$success24h = (int) (DB::one("SELECT COUNT(*) c FROM auth_logs WHERE event_type='login_success' AND created_at >= NOW() - INTERVAL 24 HOUR")['c'] ?? 0);
$criticalAlerts = (int) (DB::one("SELECT COUNT(*) c FROM alerts WHERE severity='critical' AND status='open'")['c'] ?? 0);

// Recent alerts
$recentAlerts = DB::query(
    "SELECT a.*, u.username AS target_user
     FROM alerts a
     LEFT JOIN users u ON u.id = a.target_user_id
     ORDER BY a.id DESC LIMIT 8"
);

// Recent auth logs
$recentLogs = DB::query(
    "SELECT al.*, u.username
     FROM auth_logs al
     LEFT JOIN users u ON u.id = al.user_id
     ORDER BY al.id DESC LIMIT 12"
);

$current = 'dashboard';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Dashboard · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>

    <main class="main">
        <div class="topbar">
            <h2><span class="dot live"></span>Security Operations Center</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <!-- Stat cards -->
        <div class="cards">
            <div class="card info">
                <div class="label">Total Users</div>
                <div class="value"><?= $totalUsers ?></div>
                <div class="delta">All registered accounts</div>
            </div>
            <div class="card success">
                <div class="label">Active Sessions</div>
                <div class="value"><?= $activeSessions ?></div>
                <div class="delta">Currently signed in</div>
            </div>
            <div class="card <?= $openAlerts ? 'danger' : 'success' ?>">
                <div class="label">Open Alerts</div>
                <div class="value"><?= $openAlerts ?></div>
                <div class="delta"><?= $criticalAlerts ?> critical</div>
            </div>
            <div class="card warning">
                <div class="label">Failed Logins (24h)</div>
                <div class="value"><?= $failed24h ?></div>
                <div class="delta"><?= $success24h ?> successful</div>
            </div>
        </div>

        <!-- Charts row 1 -->
        <div class="grid-2">
            <div class="panel">
                <h3>Authentication Activity (24h) <small>Live</small></h3>
                <div class="chart-wrap"><canvas id="chartTimeline"></canvas></div>
            </div>
            <div class="panel">
                <h3>Event Type Breakdown <small>Last 24h</small></h3>
                <div class="chart-wrap"><canvas id="chartEvents"></canvas></div>
            </div>
        </div>

        <!-- Charts row 2 -->
        <div class="grid-2">
            <div class="panel">
                <h3>Top Source IPs <small>Most active</small></h3>
                <div class="chart-wrap"><canvas id="chartIps"></canvas></div>
            </div>
            <div class="panel">
                <h3>Threat Distribution <small>Detected anomalies</small></h3>
                <div class="chart-wrap"><canvas id="chartThreats"></canvas></div>
            </div>
        </div>

        <!-- Recent activity tables -->
        <div class="grid-2">
            <div class="panel">
                <h3>Recent Alerts <small><a href="/admin/alerts.php">View all →</a></small></h3>
                <table>
                    <thead>
                        <tr><th>When</th><th>Severity</th><th>Rule</th><th>Target</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentAlerts as $a): ?>
                            <tr>
                                <td><?= h(relative_time($a['created_at'])) ?></td>
                                <td><span class="badge" style="background:<?= severity_color($a['severity']) ?>20;color:<?= severity_color($a['severity']) ?>"><?= h($a['severity']) ?></span></td>
                                <td><code><?= h($a['rule_name']) ?></code></td>
                                <td><?= h($a['target_user'] ?? $a['target_username'] ?? '—') ?></td>
                                <td><?= status_badge($a['status']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                        <?php if (!$recentAlerts): ?>
                            <tr><td colspan="5" style="text-align:center;color:var(--text-faint);padding:24px">No alerts yet — system clean ✓</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <div class="panel">
                <h3>Recent Auth Events <small><a href="/admin/logs.php">View all →</a></small></h3>
                <table>
                    <thead>
                        <tr><th>When</th><th>Event</th><th>User</th><th>IP</th><th>Flag</th></tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentLogs as $r): ?>
                            <tr>
                                <td><?= h(relative_time($r['created_at'])) ?></td>
                                <td><?= h($r['event_type']) ?></td>
                                <td><?= h($r['username'] ?? $r['username_attempt']) ?></td>
                                <td><code><?= h($r['ip_address']) ?></code></td>
                                <td><span class="tag threat-<?= h($r['threat_flag']) ?>"><?= h($r['threat_flag']) ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="/assets/js/dashboard.js"></script>
</body>
</html>
