<?php
/* Reusable admin sidebar. Usage:
     $current = 'dashboard'; include __DIR__ . '/_sidebar.php';

   This file is included AFTER auth, so $user (with $user['role']) is in
   scope. Management links (Users, Approvals) are gated behind the
   'manage_users' capability so a read-only AUDITOR sees the monitoring
   pages but none of the write-actions — separation of duties (comment #3).
*/
$current   = $current ?? '';
$role      = $user['role'] ?? '';
$canManage = class_exists('RBAC') ? RBAC::can($role, 'manage_users') : ($role === 'admin');

/* Each entry: [icon, label, url, requires_manage]. When requires_manage is
   true the link only renders for roles that hold the manage_users cap. */
$nav = [
    'dashboard'  => ['📊', 'Dashboard',     '/admin/dashboard.php',  false],
    'users'      => ['👥', 'Users',         '/admin/users.php',      true],
    'approvals'  => ['✅', 'Approvals',     '/admin/approvals.php',  true],
    'alerts'     => ['🚨', 'Alerts',        '/admin/alerts.php',     false],
    'logs'       => ['📜', 'Audit Logs',    '/admin/logs.php',       false],
    'integrity'  => ['🔐', 'Log Integrity', '/admin/integrity.php',  false],
    'policy'     => ['⚙️', 'Policy',        '/admin/policy.php',     false],
];
?>
<aside class="sidebar">
    <div class="brand">
        <h1><span class="logo">🛡️</span> Security</h1>
        <small>Admin Console</small>
    </div>
    <nav>
        <div class="section-title">Monitoring</div>
        <?php foreach ($nav as $key => [$ico, $label, $url, $needsManage]): ?>
            <?php if ($needsManage && !$canManage) continue; ?>
            <a class="<?= $current === $key ? 'active' : '' ?>" href="<?= $url ?>">
                <span><?= $ico ?></span> <?= h($label) ?>
            </a>
        <?php endforeach; ?>
        <div class="section-title">Account</div>
        <a href="/change-password.php">🔑 Change Password</a>
        <a href="/logout.php">🚪 Sign out</a>
    </nav>
</aside>
