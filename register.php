<?php
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/session.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/logger.php';
require_once __DIR__ . '/includes/rbac.php';
require_once __DIR__ . '/config/policy.php';

security_headers();
SessionManager::start();

// If already logged in, redirect to dashboard
if (!empty($_SESSION['uid'])) {
    redirect($_SESSION['role'] === 'admin' ? '/admin/dashboard.php' : '/dashboard.php');
}

$err = '';
$msg = '';
$old = ['username' => '', 'email' => '', 'full_name' => '', 'ic' => '', 'department' => ''];

/**
 * Password policy is driven by the fixed SecurityBaseline (comment #1):
 *  - >= 12 chars (PCI DSS 4.0 §8.3.5)
 *  - mixed case, at least one digit, at least one symbol
 *  - cannot equal the username
 */
function validate_password(string $pw, string $username): ?string {
    $min = SecurityBaseline::PASSWORD_MIN_LENGTH;
    if (strlen($pw) < $min)             return "Password must be at least {$min} characters.";
    if (strlen($pw) > SecurityBaseline::PASSWORD_MAX_LENGTH) return 'Password is too long.';
    if (!preg_match('/[A-Z]/', $pw))    return 'Password must contain an uppercase letter.';
    if (!preg_match('/[a-z]/', $pw))    return 'Password must contain a lowercase letter.';
    if (!preg_match('/[0-9]/', $pw))    return 'Password must contain a digit.';
    if (!preg_match('/[^A-Za-z0-9]/', $pw)) return 'Password must contain a symbol.';
    if (strcasecmp($pw, $username) === 0)   return 'Password cannot be the same as your username.';
    return null;
}

function validate_username(string $u): ?string {
    if (!preg_match('/^[a-zA-Z0-9_.-]{3,64}$/', $u)) {
        return 'Username must be 3–64 chars: letters, digits, dot, dash, underscore.';
    }
    return null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!SessionManager::csrfCheck($_POST['csrf'] ?? null)) {
        $err = 'Invalid request token. Please refresh and try again.';
    } else {
        $username   = trim($_POST['username']   ?? '');
        $email      = trim($_POST['email']      ?? '');
        $full_name  = trim($_POST['full_name']  ?? '');
        $ic         = trim($_POST['ic']         ?? '');
        $department = trim($_POST['department'] ?? '');
        $password   = $_POST['password'] ?? '';
        $confirm    = $_POST['confirm']  ?? '';
        $old = compact('username', 'email', 'full_name', 'ic', 'department');

        $ip = Logger::clientIp();

        // 1. Rate limit: max 5 registrations per IP per hour
        $recent = DB::one(
            "SELECT COUNT(*) c FROM auth_logs
             WHERE ip_address = :ip
               AND event_type = 'register_pending'
               AND created_at >= NOW() - INTERVAL 1 HOUR",
            ['ip' => $ip]
        );
        if ((int)($recent['c'] ?? 0) >= 5) {
            $err = 'Too many registrations from your network in the past hour. Try again later.';
        }
        // 2. Honeypot — bots fill hidden fields
        elseif (!empty($_POST['website'])) {
            $err = 'Spam detected.';
            Logger::log([
                'user_id' => null, 'username_attempt' => $username,
                'event_type' => 'register_failed', 'ip_address' => $ip,
                'notes' => 'Honeypot triggered'
            ]);
        }
        // 3. Validate
        elseif ($e = validate_username($username)) { $err = $e; }
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL))
            $err = 'Please enter a valid email address.';
        elseif (mb_strlen($email) > 190)            $err = 'Email is too long.';
        elseif (mb_strlen($full_name) === 0 || mb_strlen($full_name) > 128)
            $err = 'Full name is required (max 128 characters).';
        elseif (!RBAC::isValidDepartment($department))
            $err = 'Please select your department.';
        elseif (!preg_match('/^[A-Za-z0-9]{4,32}$/', $ic))
            $err = 'IC/ID must be 4–32 alphanumeric characters.';
        elseif ($password !== $confirm)             $err = 'Passwords do not match.';
        elseif ($e = validate_password($password, $username)) { $err = $e; }
        else {
            // 4. Uniqueness checks
            $existsU = DB::one("SELECT id FROM users WHERE username = :u", ['u' => $username]);
            if ($existsU) {
                $err = 'That username is already taken.';
            } else {
                $emailHash = Crypto::emailHash($email);
                $existsE = DB::one("SELECT id FROM users WHERE email_hash = :h", ['h' => $emailHash]);
                if ($existsE) {
                    $err = 'That email address is already registered.';
                } else {
                    // 5. Create a PENDING account. Role is forced to the lowest
                    //    tier and the account has NO access until an admin
                    //    approves it. The user NEVER chooses their own role.
                    try {
                        DB::exec(
                            "INSERT INTO users
                                (username, password_hash, email_encrypted, email_hash,
                                 ic_encrypted, full_name, requested_department, role, status)
                             VALUES
                                (:u, :p, :e, :eh, :ic, :fn, :dept, 'employee', 'pending')",
                            [
                                'u'    => $username,
                                'p'    => Crypto::passwordHash($password),
                                'e'    => Crypto::encrypt($email, 'user-email'),
                                'eh'   => $emailHash,
                                'ic'   => Crypto::encrypt($ic, 'user-ic'),
                                'fn'   => $full_name,
                                'dept' => $department,
                            ]
                        );
                        $newId = (int) DB::lastId();

                        $flag = self_register_threat($ip);
                        Logger::log([
                            'user_id' => $newId,
                            'username_attempt' => $username,
                            'event_type' => 'register_pending',
                            'ip_address' => $ip,
                            'threat_flag' => $flag,
                            'notes' => 'Self-registration (pending approval), dept requested: ' . $department,
                        ]);

                        $msg = 'Account created. It is now pending administrator approval — '
                             . 'you will be able to sign in once an administrator approves it.';
                        $old = ['username' => '', 'email' => '', 'full_name' => '', 'ic' => '', 'department' => '']; // clear
                    } catch (Throwable $ex) {
                        $err = 'Registration failed. Please try again.';
                        Logger::log([
                            'user_id' => null, 'username_attempt' => $username,
                            'event_type' => 'register_failed', 'ip_address' => $ip,
                            'notes' => 'DB error: ' . substr($ex->getMessage(), 0, 200)
                        ]);
                    }
                }
            }
        }

        // Log notable validation failures (possible enumeration / abuse)
        if ($err && empty($msg) && empty($_POST['website'])) {
            if (stripos($err, 'taken') !== false
                || stripos($err, 'already registered') !== false
                || stripos($err, 'too many') !== false) {
                Logger::log([
                    'user_id' => null, 'username_attempt' => $username,
                    'event_type' => 'register_failed', 'ip_address' => $ip,
                    'notes' => substr($err, 0, 200),
                ]);
            }
        }
    }
}

/**
 * Detect registration flood (>=3 self-registrations from same IP within 10 min).
 */
function self_register_threat(string $ip): string {
    $r = DB::one(
        "SELECT COUNT(*) c FROM auth_logs
         WHERE ip_address = :ip
           AND event_type = 'register_pending'
           AND created_at >= NOW() - INTERVAL 10 MINUTE",
        ['ip' => $ip]
    );
    if ((int)($r['c'] ?? 0) + 1 >= 3) {
        $existing = DB::one(
            "SELECT id FROM alerts WHERE rule_name = 'register_flood' AND source_ip = :ip
                AND status = 'open' AND created_at >= NOW() - INTERVAL 10 MINUTE LIMIT 1",
            ['ip' => $ip]
        );
        if (!$existing) {
            DB::exec(
                "INSERT INTO alerts (severity, rule_name, source_ip, description)
                 VALUES ('warning', 'register_flood', :ip, :desc)",
                ['ip' => $ip, 'desc' => "Multiple registrations from $ip in 10 min — possible automated abuse."]
            );
        }
        return 'register_flood';
    }
    return 'none';
}

$csrf = SessionManager::csrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="form-card" style="max-width: 460px;">
    <h2>🛡️ Request an Account</h2>
    <p class="sub">Self-registration for <?= h(APP_NAME) ?>. New accounts require administrator approval.</p>

    <?php if ($err): ?><div class="alert-box error"><?= h($err) ?></div><?php endif; ?>
    <?php if ($msg): ?>
        <div class="alert-box success"><?= h($msg) ?></div>
        <p style="text-align:center;margin-top:16px"><a class="btn primary" href="/login.php">Back to sign in →</a></p>
    <?php else: ?>

    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
        <div style="position:absolute;left:-9999px" aria-hidden="true">
            <label>Website</label>
            <input type="text" name="website" tabindex="-1" autocomplete="off">
        </div>

        <div class="form-row">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" required maxlength="64" autofocus
                   value="<?= h($old['username']) ?>"
                   pattern="[a-zA-Z0-9_.\-]{3,64}"
                   title="3–64 chars: letters, digits, dot, dash, underscore">
        </div>

        <div class="form-row">
            <label for="full_name">Full Name</label>
            <input id="full_name" name="full_name" type="text" required maxlength="128"
                   value="<?= h($old['full_name']) ?>">
        </div>

        <div class="form-row">
            <label for="department">Department</label>
            <select id="department" name="department" required>
                <option value="">— Select your department —</option>
                <?php foreach (RBAC::DEPARTMENTS as $d): ?>
                    <option value="<?= h($d) ?>" <?= $old['department'] === $d ? 'selected' : '' ?>><?= h($d) ?></option>
                <?php endforeach; ?>
            </select>
            <small style="color:var(--text-faint);font-size:11px">An administrator will confirm your department and access level.</small>
        </div>

        <div class="form-row">
            <label for="email">Email</label>
            <input id="email" name="email" type="email" required maxlength="190"
                   value="<?= h($old['email']) ?>">
            <small style="color:var(--text-faint);font-size:11px">Encrypted with AES-256-GCM at rest.</small>
        </div>

        <div class="form-row">
            <label for="ic">IC / Employee ID</label>
            <input id="ic" name="ic" type="text" required maxlength="32"
                   value="<?= h($old['ic']) ?>"
                   pattern="[A-Za-z0-9]{4,32}"
                   title="4–32 alphanumeric characters">
            <small style="color:var(--text-faint);font-size:11px">Encrypted with AES-256-GCM at rest.</small>
        </div>

        <div class="form-row">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" required minlength="<?= (int) SecurityBaseline::PASSWORD_MIN_LENGTH ?>">
            <small style="color:var(--text-faint);font-size:11px">Min <?= (int) SecurityBaseline::PASSWORD_MIN_LENGTH ?> chars · upper + lower + digit + symbol.</small>
        </div>

        <div class="form-row">
            <label for="confirm">Confirm Password</label>
            <input id="confirm" name="confirm" type="password" required minlength="<?= (int) SecurityBaseline::PASSWORD_MIN_LENGTH ?>">
        </div>

        <button class="btn primary full" type="submit">Submit Registration</button>
    </form>

    <p style="text-align:center;margin-top:20px;font-size:13px;">
        Already have an account? <a href="/login.php">Sign in</a>
    </p>
    <p style="text-align:center;margin-top:8px;font-size:11px;color:var(--text-faint);">
        Protected by Argon2id · AES-256-GCM · BLAKE3
    </p>
    <?php endif; ?>
</div>
</body>
</html>
