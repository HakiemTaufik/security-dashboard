<?php
/**
 * ============================================================
 * Security Dashboard - Central Configuration (template)
 * ============================================================
 * Copy this file to config/config.php and set real values below.
 * ============================================================
 */

// ---------- Database ----------
define('DB_HOST', 'localhost');           // Hostinger usually: localhost
define('DB_NAME', 'your_db_name');           // <-- set your DB name
define('DB_USER', 'your_db_user');           // <-- set your DB user
define('DB_PASS', 'CHANGE_ME');             // <-- set your DB password
define('DB_CHARSET', 'utf8mb4');

// ---------- Cryptography Keys ----------
// Each key is a 64-char hex string (32 bytes). Generate with:
//   php -r "echo bin2hex(random_bytes(32));"
define('AES_KEY_HEX', 'REPLACE_WITH_64_HEX_CHARS');           // php -r "echo bin2hex(random_bytes(32));"
define('BLAKE3_CTX_KEY_HEX', 'REPLACE_WITH_64_HEX_CHARS');     // second independent key
define('PEPPER',  'REPLACE_WITH_LONG_RANDOM_STRING'); // appended to passwords before hashing

// ---------- Argon2id parameters ----------
// Tuned for shared hosting; raise on dedicated servers.
define('ARGON2_MEMORY_COST', 65536); // 64 MB
define('ARGON2_TIME_COST',   4);
define('ARGON2_THREADS',     1);

// ---------- App ----------
define('APP_NAME', 'Security Dashboard');

// APP_ENV: set 'production' on the live site. 'development' enables verbose
// errors locally. The value is read via getenv() so that a `.env` or hPanel
// environment variable can override this default without editing the file.
define('APP_ENV',  getenv('APP_ENV') ?: 'production');
define('APP_TZ',   'Asia/Kuala_Lumpur');
define('SESSION_NAME', 'SDSESSID');
define('SESSION_LIFETIME_MIN', 15);

// ---------- Paths ----------
define('ROOT_PATH', dirname(__DIR__));
define('INC_PATH',  ROOT_PATH . '/includes');

// ---------- Error display ----------
if (APP_ENV === 'development') {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', '0');
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
}

date_default_timezone_set(APP_TZ);
