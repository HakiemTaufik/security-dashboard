<?php
/**
 * Authentication module: login, logout, lockout, session management.
 *
 * CHANGED (comment #3):
 *   • 'pending' accounts cannot log in until an admin approves them.
 *   • requireConsole() gates the read-only admin pages to admin + auditor,
 *     while mutating pages keep requireLogin('admin').
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/detection.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/rbac.php';

class Auth
{
    /**
     * @return array ['ok'=>bool,'msg'=>string,'user'=>?array]
     */
    public static function login(string $username, string $password): array
    {
        $username = trim($username);
        $ip = Logger::clientIp();

        // Always perform a hash check (constant-time-ish defense against user enumeration)
        $user = DB::one("SELECT * FROM users WHERE username = :u", ['u' => $username]);

        // Lockout check
        if ($user && $user['status'] === 'locked' && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
            Logger::log([
                'user_id' => $user['id'], 'username_attempt' => $username,
                'event_type' => 'login_locked',
                'notes' => 'Account locked until ' . $user['locked_until']
            ]);
            return ['ok' => false, 'msg' => 'Account locked. Try again later.', 'user' => null];
        }

        if ($user && $user['status'] === 'disabled') {
            Logger::log([
                'user_id' => $user['id'], 'username_attempt' => $username,
                'event_type' => 'login_failed', 'notes' => 'Account disabled'
            ]);
            return ['ok' => false, 'msg' => 'Account is disabled. Contact administrator.', 'user' => null];
        }

        // Pending self-registration awaiting admin approval — no access yet.
        if ($user && $user['status'] === 'pending') {
            Logger::log([
                'user_id' => $user['id'], 'username_attempt' => $username,
                'event_type' => 'login_failed', 'notes' => 'Account pending approval'
            ]);
            return ['ok' => false, 'msg' => 'Your account is pending administrator approval.', 'user' => null];
        }

        $hash = $user['password_hash'] ?? '$argon2id$v=19$m=65536,t=4,p=1$ZHVtbXlzYWx0ZHVtbXlzYWx0$' . str_repeat('a', 43);
        $ok = $user ? Crypto::passwordVerify($password, $hash) : false;
        // Run a dummy verify when user not found, to equalize timing roughly
        if (!$user) {
            Crypto::passwordVerify($password, '$argon2id$v=19$m=65536,t=4,p=1$ZHVtbXlzYWx0ZHVtbXlzYWx0$' . str_repeat('a', 43));
        }

        if (!$ok) {
            self::handleFail($user, $username, $ip);
            return ['ok' => false, 'msg' => 'Invalid credentials.', 'user' => null];
        }

        // Success path
        self::handleSuccess($user, $ip);
        return ['ok' => true, 'msg' => 'Login successful.', 'user' => $user];
    }

    private static function handleFail(?array $user, string $username, string $ip): void
    {
        if ($user) {
            $p = Detection::policy();
            $newAttempts = ((int) $user['failed_attempts']) + 1;
            $params = [
                'fa'  => $newAttempts,
                'lf'  => date('Y-m-d H:i:s'),
                'id'  => $user['id'],
            ];
            $sql = "UPDATE users SET failed_attempts=:fa, last_failed_at=:lf";

            if ($newAttempts >= (int) $p['max_failed_attempts']) {
                $until = date('Y-m-d H:i:s', time() + 60 * (int) $p['lockout_minutes']);
                $sql .= ", status='locked', locked_until=:lu";
                $params['lu'] = $until;
            }
            $sql .= " WHERE id=:id";
            DB::exec($sql, $params);
        }

        // Evaluate detection FIRST so the resulting threat_flag is part
        // of the canonical row hashed into the integrity chain.
        $flag = Detection::evaluate([
            'user_id' => $user['id'] ?? null,
            'username_attempt' => $username,
            'event_type' => 'login_failed',
            'ip_address' => $ip,
        ]);

        Logger::log([
            'user_id' => $user['id'] ?? null,
            'username_attempt' => $username,
            'event_type' => 'login_failed',
            'ip_address' => $ip,
            'threat_flag' => $flag,
            'notes' => $user ? "Failed attempt #{$user['failed_attempts']}" : 'Unknown user'
        ]);
    }

    private static function handleSuccess(array $user, string $ip): void
    {
        // Reset counters / unlock
        DB::exec(
            "UPDATE users SET failed_attempts=0, locked_until=NULL,
                    status=IF(status='locked','active',status),
                    last_login_at=:t, last_login_ip=:ip
             WHERE id=:id",
            ['t' => date('Y-m-d H:i:s'), 'ip' => $ip, 'id' => $user['id']]
        );

        SessionManager::start();
        SessionManager::regenerate();
        $_SESSION['uid']  = (int) $user['id'];
        $_SESSION['uname'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['login_at'] = time();
        $_SESSION['ip']   = $ip;

       // Track active session in DB
        DB::exec(
            "INSERT INTO active_sessions (session_id, user_id, ip_address, user_agent, expires_at)
             VALUES (:sid, :uid, :ip, :ua, :exp_insert)
             ON DUPLICATE KEY UPDATE last_activity_at=NOW(), expires_at=:exp_update",
            [
                'sid' => session_id(),
                'uid' => $user['id'],
                'ip'  => $ip,
                'ua'  => Logger::userAgent(),
                'exp_insert' => date('Y-m-d H:i:s', time() + 60 * SESSION_LIFETIME_MIN),
                'exp_update' => date('Y-m-d H:i:s', time() + 60 * SESSION_LIFETIME_MIN),
            ]
        );

        // Evaluate detection FIRST so flag is part of integrity hash
        $flag = Detection::evaluate([
            'user_id' => $user['id'],
            'username_attempt' => $user['username'],
            'event_type' => 'login_success',
            'ip_address' => $ip,
        ]);

        Logger::log([
            'user_id' => $user['id'],
            'username_attempt' => $user['username'],
            'event_type' => 'login_success',
            'threat_flag' => $flag,
        ]);
    }

    public static function logout(): void
    {
        SessionManager::start();
        $uid = $_SESSION['uid'] ?? null;
        $uname = $_SESSION['uname'] ?? '';
        if ($uid) {
            Logger::log([
                'user_id' => $uid,
                'username_attempt' => $uname,
                'event_type' => 'logout',
            ]);
            DB::exec("DELETE FROM active_sessions WHERE session_id = :sid", ['sid' => session_id()]);
        }
        SessionManager::destroy();
    }

    /**
     * Require an authenticated, active user.
     * @param string|null $role optional exact role requirement (e.g. 'admin')
     */
    public static function requireLogin(?string $role = null): array
    {
        SessionManager::start();
        SessionManager::checkTimeout();
        if (empty($_SESSION['uid'])) {
            header('Location: /login.php');
            exit;
        }
        $u = DB::one("SELECT * FROM users WHERE id = :id", ['id' => $_SESSION['uid']]);
        if (!$u || $u['status'] !== 'active') {
            self::logout();
            header('Location: /login.php?msg=session_invalid');
            exit;
        }
        if ($role && $u['role'] !== $role) {
            http_response_code(403);
            die('Forbidden');
        }

        // Force password change after an admin reset.
        $script = basename($_SERVER['SCRIPT_NAME'] ?? '');
        $exempt = ['change-password.php', 'logout.php'];
        if (!empty($u['must_change_password']) && !in_array($script, $exempt, true)) {
            header('Location: /change-password.php');
            exit;
        }

        return $u;
    }

    /**
     * Require an authenticated, active user with READ access to the admin
     * console (admin OR auditor). Use on monitoring pages. Mutating pages keep
     * requireLogin('admin') so auditors can look but not touch.
     */
    public static function requireConsole(): array
    {
        $u = self::requireLogin(); // any active user, applies timeout + pw-change rules
        if (!in_array($u['role'], RBAC::consoleRoles(), true)) {
            http_response_code(403);
            die('Forbidden');
        }
        return $u;
    }

    /**
     * Require a specific capability (fine-grained). Returns the user row.
     */
    public static function requireCapability(string $capability): array
    {
        $u = self::requireLogin();
        if (!RBAC::can($u['role'], $capability)) {
            http_response_code(403);
            die('Forbidden');
        }
        return $u;
    }
}
