<?php
/**
 * Secure session management.
 * - HttpOnly, SameSite=Strict, Secure (when HTTPS)
 * - Idle timeout
 * - CSRF token helper
 */

require_once __DIR__ . '/../config/config.php';

class SessionManager
{
    private static bool $started = false;

    public static function start(): void
    {
        if (self::$started) return;
        if (session_status() === PHP_SESSION_ACTIVE) {
            self::$started = true;
            return;
        }

        session_name(SESSION_NAME);
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
              || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        ini_set('session.use_strict_mode', '1');
        session_start();
        self::$started = true;
    }

    public static function regenerate(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
    }

    public static function destroy(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params['path'], $params['domain'],
                    $params['secure'], $params['httponly']);
            }
            session_destroy();
        }
    }

    public static function checkTimeout(): void
    {
        if (!isset($_SESSION['login_at'])) return;
        $idle = time() - ($_SESSION['last_seen'] ?? $_SESSION['login_at']);
        if ($idle > SESSION_LIFETIME_MIN * 60) {
            self::destroy();
            header('Location: /login.php?msg=timeout');
            exit;
        }
        $_SESSION['last_seen'] = time();
    }

    public static function csrfToken(): string
    {
        self::start();
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf'];
    }

    public static function csrfCheck(?string $token): bool
    {
        self::start();
        return !empty($_SESSION['csrf']) && is_string($token) && hash_equals($_SESSION['csrf'], $token);
    }
}
