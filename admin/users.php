<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/crypto.php';
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
$user = Auth::requireLogin('admin');

$flash = $_GET['flash'] ?? '';
$flashType = $_GET['flash_type'] ?? 'info';
// Allowlist flash type — only these CSS classes are valid.
if (!in_array($flashType, ['info', 'success', 'warning', 'error'], true)) {
    $flashType = 'info';
}
if (is_string($flash) && strlen($flash) > 200) {
    $flash = substr($flash, 0, 200);
}

$users = DB::query(
    "SELECT id, username, full_name, email_encrypted, role, department, status,
            failed_attempts, last_login_at, last_login_ip, created_at
     FROM users ORDER BY role DESC, username ASC"
);

$csrf = SessionManager::csrfToken();
$current = 'users';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Users · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>
    <main class="main">
        <div class="topbar">
            <h2>👥 User Management</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <?php if ($flash): ?>
            <div class="alert-box <?= h($flashType) ?>"><?= h($flash) ?></div>
        <?php endif; ?>

        <div class="panel">
            <h3>All Accounts <small><?= count($users) ?> users · PII fields encrypted with AES-256-GCM</small></h3>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Email <small>(masked)</small></th>
                        <th>Role</th>
                        <th>Department</th>
                        <th>Status</th>
                        <th>Failed</th>
                        <th>Last Login</th>
                        <th style="text-align:right">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $u): ?>
                        <?php
                        $emailPlain = $u['email_encrypted'] ? Crypto::decrypt($u['email_encrypted'], 'user-email') : null;
                        $emailDisplay = $emailPlain ? Crypto::maskEmail($emailPlain) : '—';
                        $isMe = (int) $u['id'] === (int) $user['id'];
                        ?>
                        <tr>
                            <td><strong><?= h($u['username']) ?></strong> <?= $isMe ? '<small style="color:var(--accent)">(you)</small>' : '' ?></td>
                            <td><?= h($u['full_name']) ?></td>
                            <td style="color:var(--text-dim)"><?= h($emailDisplay) ?></td>
                            <td><span class="badge" style="background:<?= $u['role'] === 'admin' ? 'rgba(168,85,247,.2);color:#d8b4fe' : 'rgba(59,130,246,.2);color:#93c5fd' ?>"><?= h($u['role']) ?></span></td>
                            <td><?= h($u['department'] ?: '—') ?></td>
                            <td><?= status_badge($u['status']) ?></td>
                            <td><?= (int) $u['failed_attempts'] > 0 ? '<span style="color:var(--warning)">' . (int)$u['failed_attempts'] . '</span>' : '0' ?></td>
                            <td style="color:var(--text-dim);font-size:12px">
                                <?= $u['last_login_at'] ? h(relative_time($u['last_login_at'])) : '—' ?>
                                <?php if ($u['last_login_ip']): ?><br><code style="font-size:11px"><?= h($u['last_login_ip']) ?></code><?php endif; ?>
                            </td>
                            <td style="text-align:right;white-space:nowrap">
                                <?php if (!$isMe): ?>
                                    <?php if ($u['status'] === 'disabled'): ?>
                                        <form method="post" action="/admin/actions.php" style="display:inline" onsubmit="return confirm('Unblock <?= h(addslashes($u['username'])) ?>?')">
                                            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                            <input type="hidden" name="redirect" value="/admin/users.php">
                                            <input type="hidden" name="action" value="unblock_user">
                                            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                            <button class="btn sm success">Unblock</button>
                                        </form>
                                    <?php else: ?>
                                        <form method="post" action="/admin/actions.php" style="display:inline" onsubmit="return confirm('Block <?= h(addslashes($u['username'])) ?>? They will be signed out.')">
                                            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                            <input type="hidden" name="redirect" value="/admin/users.php">
                                            <input type="hidden" name="action" value="block_user">
                                            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                            <button class="btn sm danger">Block</button>
                                        </form>
                                    <?php endif; ?>
                                    <form method="post" action="/admin/actions.php" style="display:inline" onsubmit="return confirm('Reset password for <?= h(addslashes($u['username'])) ?>? A temporary password will be shown once.')">
                                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                        <input type="hidden" name="redirect" value="/admin/users.php">
                                        <input type="hidden" name="action" value="reset_password">
                                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                        <button class="btn sm warning">Reset PW</button>
                                    </form>
                                    <form method="post" action="/admin/actions.php" style="display:inline-flex;gap:4px;align-items:center;margin-top:6px"
                                          onsubmit="return confirm('Update role/department for <?= h(addslashes($u['username'])) ?>?')">
                                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                        <input type="hidden" name="redirect" value="/admin/users.php">
                                        <input type="hidden" name="action" value="assign_role">
                                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                        <select name="role">
                                            <?php foreach (RBAC::ROLES as $r): ?>
                                                <option value="<?= h($r) ?>" <?= $u['role'] === $r ? 'selected' : '' ?>><?= h(RBAC::label($r)) ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <select name="department">
                                            <?php foreach (RBAC::DEPARTMENTS as $d): ?>
                                                <option value="<?= h($d) ?>" <?= $u['department'] === $d ? 'selected' : '' ?>><?= h($d) ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                        <button class="btn sm">Update</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <p style="font-size: 12px; color: var(--text-faint); margin-top: 16px;">
            🔒 Email and IC numbers are stored as AES-256-GCM ciphertext. Only masked previews are displayed.
            All actions are recorded in <code>admin_actions</code> with BLAKE3 integrity hashes.
        </p>
    </main>
</div>
</body>
</html>
