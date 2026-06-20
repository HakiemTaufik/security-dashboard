<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';

security_headers();
$user = Auth::requireConsole();

$event  = $_GET['event']  ?? '';
$threat = $_GET['threat'] ?? '';
$user_q = $_GET['user']   ?? '';
$ip     = $_GET['ip']     ?? '';

$where = []; $params = [];
if ($event)  { $where[] = 'al.event_type = :event';  $params['event'] = $event; }
if ($threat) { $where[] = 'al.threat_flag = :threat'; $params['threat'] = $threat; }
if ($user_q) { $where[] = '(u.username LIKE :uq OR al.username_attempt LIKE :uq)'; $params['uq'] = "%$user_q%"; }
if ($ip)     { $where[] = 'al.ip_address LIKE :ip';   $params['ip'] = "%$ip%"; }

$whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$logs = DB::query(
    "SELECT al.*, u.username
     FROM auth_logs al
     LEFT JOIN users u ON u.id = al.user_id
     $whereSql
     ORDER BY al.id DESC LIMIT 200",
    $params
);

$current = 'logs';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Logs · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>
    <main class="main">
        <div class="topbar">
            <h2>📜 Audit Logs</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <div class="panel">
            <h3>Filters</h3>
            <form method="get" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px">
                <div class="form-row" style="margin:0">
                    <label>Event Type</label>
                    <select name="event">
                        <option value="">All events</option>
                        <?php foreach (['login_success','login_failed','login_locked','logout','password_reset','account_blocked','account_unblocked','admin_action','session_expired'] as $e): ?>
                            <option value="<?= $e ?>" <?= $event === $e ? 'selected' : '' ?>><?= $e ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-row" style="margin:0">
                    <label>Threat Flag</label>
                    <select name="threat">
                        <option value="">Any</option>
                        <?php foreach (['none','brute_force','rapid_fire','off_hours','geo_anomaly','insider'] as $t): ?>
                            <option value="<?= $t ?>" <?= $threat === $t ? 'selected' : '' ?>><?= $t ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-row" style="margin:0">
                    <label>User contains</label>
                    <input type="text" name="user" value="<?= h($user_q) ?>" placeholder="username">
                </div>
                <div class="form-row" style="margin:0">
                    <label>IP contains</label>
                    <input type="text" name="ip" value="<?= h($ip) ?>" placeholder="192.168.">
                </div>
                <div style="display:flex;align-items:flex-end;gap:8px">
                    <button class="btn primary" type="submit">Apply</button>
                    <a class="btn ghost" href="/admin/logs.php">Clear</a>
                </div>
            </form>
        </div>

        <div class="panel">
            <h3>Auth Log Entries <small><?= count($logs) ?> shown · BLAKE3 chained</small></h3>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>When</th>
                        <th>Event</th>
                        <th>User</th>
                        <th>IP</th>
                        <th>Device</th>
                        <th>Threat</th>
                        <th>Hash</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $r): ?>
                        <tr>
                            <td>#<?= (int) $r['id'] ?></td>
                            <td>
                                <?= h($r['created_at']) ?><br>
                                <small style="color:var(--text-faint)"><?= h(relative_time($r['created_at'])) ?></small>
                            </td>
                            <td><?= h($r['event_type']) ?></td>
                            <td><?= h($r['username'] ?? $r['username_attempt']) ?></td>
                            <td><code><?= h($r['ip_address']) ?></code></td>
                            <td style="color:var(--text-dim);font-size:11px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= h($r['user_agent']) ?>">
                                <?= h($r['device_info']) ?>
                            </td>
                            <td><span class="tag threat-<?= h($r['threat_flag']) ?>"><?= h($r['threat_flag']) ?></span></td>
                            <td><span class="hash" title="<?= h($r['integrity_hash']) ?>"><?= h(substr($r['integrity_hash'], 0, 16)) ?>…</span></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (!$logs): ?>
                        <tr><td colspan="8" style="text-align:center;color:var(--text-faint);padding:40px">No matching log entries.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
</body>
</html>
