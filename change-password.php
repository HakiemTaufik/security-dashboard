<?php
/**
 * ============================================================
 * Change Password
 * ============================================================
 * Self-service password change for any signed-in user (admin or employee).
 *
 * Security checks performed:
 *   - CSRF token verification
 *   - Current password must be verified before any change
 *   - New password must meet the same strength policy as registration
 *   - New password cannot equal old password (forces real rotation)
 *   - Per-user rate limit (5 changes / hour)
 *   - All OTHER active sessions for this user are revoked
 *   - Event is logged into auth_logs with BLAKE3 integrity hash
 * ============================================================
 */
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/session.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/logger.php';

security_headers();
$user = Auth::requireLogin();

$err = '';
$msg = '';

/**
 * Strong password policy — identical to the rules enforced in register.php.
 */
function validate_new_password(string $pw, string $username, string $oldPlain): ?string {
    if (strlen($pw) < 10)                   return 'Password must be at least 10 characters.';
    if (!preg_match('/[A-Z]/', $pw))        return 'Password must contain an uppercase letter.';
    if (!preg_match('/[a-z]/', $pw))        return 'Password must contain a lowercase letter.';
    if (!preg_match('/[0-9]/', $pw))        return 'Password must contain a digit.';
    if (!preg_match('/[^A-Za-z0-9]/', $pw)) return 'Password must contain a symbol.';
    if (strcasecmp($pw, $username) === 0)   return 'Password cannot be the same as your username.';
    if (hash_equals($pw, $oldPlain))        return 'New password cannot be the same as your current password.';
    return null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!SessionManager::csrfCheck($_POST['csrf'] ?? null)) {
        $err = 'Invalid request token. Please refresh and try again.';
    } else {
        $current = $_POST['current_password'] ?? '';
        $new     = $_POST['new_password']     ?? '';
        $confirm = $_POST['confirm_password'] ?? '';

        // 1. Rate limit: max 5 successful password-changes per user per hour
        $recent = DB::one(
            "SELECT COUNT(*) c FROM auth_logs
             WHERE user_id = :uid
               AND event_type = 'password_changed'
               AND created_at >= NOW() - INTERVAL 1 HOUR",
            ['uid' => $user['id']]
        );
        if ((int)($recent['c'] ?? 0) >= 5) {
            $err = 'Too many password changes in the past hour. Please try again later.';
        }
        // 2. Re-fetch the user row to get the latest password_hash and status
        else {
            $row = DB::one("SELECT * FROM users WHERE id = :id", ['id' => $user['id']]);
            if (!$row) {
                $err = 'User record not found. Please sign in again.';
            }
            // 3. Verify the current password before allowing any change
            elseif (!Crypto::passwordVerify($current, $row['password_hash'])) {
                $err = 'Current password is incorrect.';
                Logger::log([
                    'user_id'          => $user['id'],
                    'username_attempt' => $user['username'],
                    'event_type'       => 'password_change_failed',
                    'notes'            => 'Wrong current password supplied',
                ]);
            }
            // 4. New password must match its confirmation
            elseif ($new !== $confirm) {
                $err = 'New password and confirmation do not match.';
            }
            // 5. New password must meet the strength policy
            elseif ($e = validate_new_password($new, $user['username'], $current)) {
                $err = $e;
            }
            // 6. All checks passed — commit the change
            else {
                try {
                    DB::exec(
                        "UPDATE users
                         SET password_hash = :h,
                             must_change_password = 0,
                             failed_attempts = 0,
                             locked_until = NULL
                         WHERE id = :id",
                        ['h' => Crypto::passwordHash($new), 'id' => $user['id']]
                    );

                    // 7. Revoke every OTHER active session for this user.
                    // The current browser keeps its session so the user isn't
                    // signed out mid-action; any other device gets kicked.
                    DB::exec(
                        "DELETE FROM active_sessions
                         WHERE user_id = :uid
                           AND session_id != :sid",
                        ['uid' => $user['id'], 'sid' => session_id()]
                    );

                    // 8. Audit log
                    Logger::log([
                        'user_id'          => $user['id'],
                        'username_attempt' => $user['username'],
                        'event_type'       => 'password_changed',
                        'notes'            => 'Self-service password change',
                    ]);

                    $msg = 'Password changed successfully. Other devices have been signed out.';
                } catch (Throwable $ex) {
                    $err = 'Could not save the new password. Please try again.';
                    Logger::log([
                        'user_id'          => $user['id'],
                        'username_attempt' => $user['username'],
                        'event_type'       => 'password_change_failed',
                        'notes'            => 'DB error: ' . substr($ex->getMessage(), 0, 200),
                    ]);
                }
            }
        }
    }
}

// Where the back-to-dashboard link should point
$dashUrl = $user['role'] === 'admin' ? '/admin/dashboard.php' : '/dashboard.php';
$mustChange = !empty($user['must_change_password']);
$csrf = SessionManager::csrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Change Password · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="form-card" style="max-width: 480px;">
    <h2>🔑 Change Password</h2>
    <p class="sub">Signed in as <strong><?= h($user['username']) ?></strong> (<?= h($user['role']) ?>)</p>

    <?php if ($mustChange && !$msg): ?>
        <div class="alert-box warning">
            Your administrator reset your password. You must choose a new one before continuing.
        </div>
    <?php endif; ?>

    <?php if ($err): ?><div class="alert-box error"><?= h($err) ?></div><?php endif; ?>

    <?php if ($msg): ?>
        <div class="alert-box success"><?= h($msg) ?></div>
        <p style="text-align:center;margin-top:16px">
            <a class="btn primary" href="<?= h($dashUrl) ?>">Back to dashboard →</a>
        </p>
    <?php else: ?>

    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">

        <div class="form-row">
            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password" required autofocus>
        </div>

        <div class="form-row">
            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password" required minlength="10">
            <small style="color:var(--text-faint);font-size:11px">
                Min 10 chars · upper + lower + digit + symbol · must differ from current.
            </small>
        </div>

        <div class="form-row">
            <label for="confirm_password">Confirm new password</label>
            <input id="confirm_password" name="confirm_password" type="password" required minlength="10">
        </div>

        <button class="btn primary full" type="submit">Update Password</button>
    </form>

    <p style="text-align:center;margin-top:20px;font-size:13px;">
        <a href="<?= h($dashUrl) ?>">← Back to dashboard</a>
    </p>
    <p style="text-align:center;margin-top:8px;font-size:11px;color:var(--text-faint);">
        Protected by Argon2id · CSRF tokens · BLAKE3 audit chain
    </p>
    <?php endif; ?>
</div>
</body>
</html>
