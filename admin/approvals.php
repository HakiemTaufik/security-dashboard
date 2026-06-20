<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/crypto.php';
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
$user = Auth::requireLogin('admin'); // approving is a privileged, admin-only action

$flash = $_GET['flash'] ?? '';
$flashType = $_GET['flash_type'] ?? 'info';
if (!in_array($flashType, ['info', 'success', 'warning', 'error'], true)) $flashType = 'info';
if (is_string($flash) && strlen($flash) > 200) $flash = substr($flash, 0, 200);

$pending = DB::query(
    "SELECT id, username, full_name, email_encrypted, requested_department, created_at
     FROM users WHERE status='pending' ORDER BY created_at ASC"
);

$csrf = SessionManager::csrfToken();
$current = 'approvals';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approvals · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>
    <main class="main">
        <div class="topbar">
            <h2>✅ Pending Approvals</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <?php if ($flash): ?>
            <div class="alert-box <?= h($flashType) ?>"><?= h($flash) ?></div>
        <?php endif; ?>

        <div class="alert-box info" style="font-size:13px">
            New self-registrations land here with <strong>no access</strong>. Verify the person,
            confirm their <strong>department</strong>, then approve. Every approved applicant becomes
            a standard <strong>employee</strong> — elevated roles (auditor, manager, admin) are granted
            afterwards from <a href="/admin/users.php">User Management</a>. The applicant never chooses
            their own role.
        </div>

        <div class="panel">
            <h3>Awaiting Review <small><?= count($pending) ?> pending</small></h3>
            <?php if (empty($pending)): ?>
                <p style="color:var(--text-faint)">Nothing pending. 🎉</p>
            <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Full Name</th>
                        <th>Email <small>(masked)</small></th>
                        <th>Requested Dept</th>
                        <th>Requested</th>
                        <th>Confirm Dept &amp; Approve</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pending as $p): ?>
                        <?php
                        $emailPlain = $p['email_encrypted'] ? Crypto::decrypt($p['email_encrypted'], 'user-email') : null;
                        $emailDisplay = $emailPlain ? Crypto::maskEmail($emailPlain) : '—';
                        $reqDept = $p['requested_department'] ?? '';
                        ?>
                        <tr>
                            <td><strong><?= h($p['username']) ?></strong></td>
                            <td><?= h($p['full_name']) ?></td>
                            <td style="color:var(--text-dim)"><?= h($emailDisplay) ?></td>
                            <td><?= h($reqDept ?: '—') ?></td>
                            <td style="font-size:12px;color:var(--text-dim)"><?= h(relative_time($p['created_at'])) ?></td>
                            <td>
                                <form method="post" action="/admin/actions.php" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center"
                                      onsubmit="return confirm('Approve <?= h(addslashes($p['username'])) ?>?')">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="redirect" value="/admin/approvals.php">
                                    <input type="hidden" name="action" value="approve_user">
                                    <input type="hidden" name="user_id" value="<?= (int) $p['id'] ?>">

                                    <select name="department" required>
                                        <option value="">Dept…</option>
                                        <?php foreach (RBAC::DEPARTMENTS as $d): ?>
                                            <option value="<?= h($d) ?>" <?= $reqDept === $d ? 'selected' : '' ?>><?= h($d) ?></option>
                                        <?php endforeach; ?>
                                    </select>

                                    <button class="btn sm success" type="submit">Approve as Employee</button>
                                </form>
                                <form method="post" action="/admin/actions.php" style="display:inline;margin-top:6px"
                                      onsubmit="return confirm('Reject and delete <?= h(addslashes($p['username'])) ?>?')">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="redirect" value="/admin/approvals.php">
                                    <input type="hidden" name="action" value="reject_user">
                                    <input type="hidden" name="user_id" value="<?= (int) $p['id'] ?>">
                                    <button class="btn sm danger" type="submit">Reject</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>

        <p style="font-size:12px;color:var(--text-faint);margin-top:12px">
            Every approval and rejection is recorded in <code>admin_actions</code> with a BLAKE3 integrity hash.
        </p>
    </main>
</div>
</body>
</html>
