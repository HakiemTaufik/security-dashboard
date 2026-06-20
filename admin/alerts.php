<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/session.php';

security_headers();
// Read access for the whole console (admin + read-only auditor). The write
// actions below (Ack / Resolve) are additionally gated on the manage_alerts
// capability so an auditor sees the queue but cannot mutate it.
$user = Auth::requireConsole();
$canManageAlerts = RBAC::can($user['role'], 'manage_alerts');

// Allowlist the filter parameter — only these four values are ever accepted.
// Any other value (or no value) falls back to 'all'. This is a defence-in-
// depth measure on top of h() escaping when the value is reflected.
$allowedFilters = ['all', 'open', 'critical', 'resolved'];
$filter = $_GET['filter'] ?? 'all';
if (!in_array($filter, $allowedFilters, true)) {
    $filter = 'all';
}

$where = '';
$params = [];
if ($filter === 'open') {
    $where = "WHERE a.status='open'";
} elseif ($filter === 'critical') {
    $where = "WHERE a.severity='critical'";
} elseif ($filter === 'resolved') {
    $where = "WHERE a.status='resolved'";
}

$alerts = DB::query(
    "SELECT a.*, u.username AS target_user, ack.username AS ack_by_user
     FROM alerts a
     LEFT JOIN users u   ON u.id   = a.target_user_id
     LEFT JOIN users ack ON ack.id = a.acknowledged_by
     $where
     ORDER BY a.id DESC LIMIT 200",
    $params
);

// Allowlist flash messages too — flash type controls a CSS class.
$allowedFlashTypes = ['info', 'success', 'warning', 'error'];
$flash = $_GET['flash'] ?? '';
$flashType = $_GET['flash_type'] ?? 'info';
if (!in_array($flashType, $allowedFlashTypes, true)) {
    $flashType = 'info';
}
// Trim flash message to a sane length to prevent layout-breaking input
if (is_string($flash) && strlen($flash) > 200) {
    $flash = substr($flash, 0, 200);
}
$csrf = SessionManager::csrfToken();
$current = 'alerts';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Alerts · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>
    <main class="main">
        <div class="topbar">
            <h2>🚨 Security Alerts</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <?php if ($flash): ?>
            <div class="alert-box <?= h($flashType) ?>"><?= h($flash) ?></div>
        <?php endif; ?>

        <div style="margin-bottom:16px">
            <a class="btn sm <?= $filter === 'all' ? 'primary' : 'ghost' ?>" href="?filter=all">All</a>
            <a class="btn sm <?= $filter === 'open' ? 'primary' : 'ghost' ?>" href="?filter=open">Open</a>
            <a class="btn sm <?= $filter === 'critical' ? 'primary' : 'ghost' ?>" href="?filter=critical">Critical</a>
            <a class="btn sm <?= $filter === 'resolved' ? 'primary' : 'ghost' ?>" href="?filter=resolved">Resolved</a>
        </div>

        <div class="panel">
            <h3>Alert Queue <small><?= count($alerts) ?> shown</small></h3>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>When</th>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Description</th>
                        <th>Source IP</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th style="text-align:right">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($alerts as $a): ?>
                        <tr>
                            <td>#<?= (int) $a['id'] ?></td>
                            <td><?= h(relative_time($a['created_at'])) ?><br><small style="color:var(--text-faint)"><?= h($a['created_at']) ?></small></td>
                            <td><span class="badge" style="background:<?= severity_color($a['severity']) ?>20;color:<?= severity_color($a['severity']) ?>;border:1px solid <?= severity_color($a['severity']) ?>40"><?= h(strtoupper($a['severity'])) ?></span></td>
                            <td><code><?= h($a['rule_name']) ?></code></td>
                            <td style="max-width:380px"><?= h($a['description']) ?></td>
                            <td><code><?= h($a['source_ip']) ?></code></td>
                            <td><?= h($a['target_user'] ?? $a['target_username'] ?? '—') ?></td>
                            <td>
                                <?= status_badge($a['status']) ?>
                                <?php if ($a['ack_by_user']): ?>
                                    <br><small style="color:var(--text-faint)">by <?= h($a['ack_by_user']) ?></small>
                                <?php endif; ?>
                            </td>
                            <td style="text-align:right;white-space:nowrap">
                                <?php if (!$canManageAlerts): ?>
                                    <small style="color:var(--text-faint)">read-only</small>
                                <?php endif; ?>
                                <?php if ($canManageAlerts && $a['status'] === 'open'): ?>
                                    <form method="post" action="/admin/actions.php" style="display:inline">
                                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                        <input type="hidden" name="redirect" value="/admin/alerts.php?filter=<?= h($filter) ?>">
                                        <input type="hidden" name="action" value="acknowledge_alert">
                                        <input type="hidden" name="alert_id" value="<?= (int)$a['id'] ?>">
                                        <button class="btn sm warning">Ack</button>
                                    </form>
                                <?php endif; ?>
                                <?php if ($canManageAlerts && $a['status'] !== 'resolved'): ?>
                                    <form method="post" action="/admin/actions.php" style="display:inline">
                                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                        <input type="hidden" name="redirect" value="/admin/alerts.php?filter=<?= h($filter) ?>">
                                        <input type="hidden" name="action" value="resolve_alert">
                                        <input type="hidden" name="alert_id" value="<?= (int)$a['id'] ?>">
                                        <button class="btn sm success">Resolve</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (!$alerts): ?>
                        <tr><td colspan="9" style="text-align:center;color:var(--text-faint);padding:40px">No alerts ✓</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
</body>
</html>
