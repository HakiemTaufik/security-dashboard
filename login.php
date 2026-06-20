<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/session.php';

security_headers();
SessionManager::start();

if (!empty($_SESSION['uid'])) {
    redirect($_SESSION['role'] === 'admin' ? '/admin/dashboard.php' : '/dashboard.php');
}

$err = '';
$msg = '';

if (isset($_GET['msg'])) {
    if ($_GET['msg'] === 'timeout')         $msg = 'You were logged out due to inactivity.';
    if ($_GET['msg'] === 'session_invalid') $msg = 'Session expired. Please log in again.';
    if ($_GET['msg'] === 'logout')          $msg = 'You have been logged out.';
    if ($_GET['msg'] === 'registered')      $msg = 'Account created. Please sign in.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!SessionManager::csrfCheck($_POST['csrf'] ?? null)) {
        $err = 'Invalid request token. Please refresh and try again.';
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';

        if ($username === '' || $password === '') {
            $err = 'Username and password are required.';
        } elseif (strlen($username) > 64) {
            $err = 'Invalid input.';
        } else {
            $res = Auth::login($username, $password);
            if ($res['ok']) {
                $u = $res['user'];
                redirect($u['role'] === 'admin' ? '/admin/dashboard.php' : '/dashboard.php');
            }
            $err = $res['msg'];
        }
    }
}

$csrf = SessionManager::csrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="form-card">
    <h2>🛡️ <?= h(APP_NAME) ?></h2>
    <p class="sub">Sign in to access the security dashboard</p>

    <?php if ($err): ?><div class="alert-box error"><?= h($err) ?></div><?php endif; ?>
    <?php if ($msg): ?><div class="alert-box info"><?= h($msg) ?></div><?php endif; ?>

    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">

        <div class="form-row">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" required maxlength="64" autofocus
                   value="<?= h($_POST['username'] ?? '') ?>">
        </div>

        <div class="form-row">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" required>
        </div>

        <button class="btn primary full" type="submit">Sign in</button>
    </form>

    <p style="text-align:center;margin-top:20px;font-size:13px;">
        Don't have an account? <a href="/register.php">Create one</a>
    </p>
    <p style="text-align:center;margin-top:8px;font-size:11px;color:var(--text-faint);">
        Protected by Argon2id · AES-256-GCM · BLAKE3
    </p>
</div>
</body>
</html>
