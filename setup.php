<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/**
 * ============================================================
 * One-time Setup Script
 * ============================================================
 * 1. Edit /config/config.php with real DB credentials and keys.
 * 2. Visit /setup.php in your browser.
 * 3. DELETE this file after setup completes.
 *
 * What this does:
 *   - Creates all tables from sql/schema.sql
 *   - Seeds default admin and employee users with Argon2id + AES-256-GCM
 *   - Creates the genesis row in auth_logs for the BLAKE3 chain
 *
 * Default credentials (CHANGE IMMEDIATELY):
 *   admin / Admin@12345
 *   employee01 / Employee@123
 * ============================================================
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/logger.php';
require_once __DIR__ . '/includes/helpers.php';

security_headers();

$messages = [];
$errors = [];
$ran = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['confirm'] ?? '') === 'YES') {
    $ran = true;
    try {
        // 1. Create tables
        $sql = file_get_contents(__DIR__ . '/sql/schema.sql');
        // Strip comment lines (-- ...) but keep content
        $statements = array_filter(array_map('trim', explode(';', $sql)));
        foreach ($statements as $stmt) {
            $stmt = preg_replace('/^\s*--.*$/m', '', $stmt);
            if (trim($stmt) === '') continue;
            DB::conn()->exec($stmt);
        }
        $messages[] = '✓ Schema created';

        // 1b. Apply schema migrations in filename order (01_, 02_, ...).
        // The base schema.sql holds the original tables; the migrations add
        // the integrity-monitoring tables and the roles/departments and
        // self-registration columns the app relies on.
        $migrationDir = __DIR__ . '/sql/migrations';
        $migrations = glob($migrationDir . '/*.sql') ?: [];
        sort($migrations);
        foreach ($migrations as $file) {
            $msql = file_get_contents($file);
            $mstatements = array_filter(array_map('trim', explode(';', $msql)));
            foreach ($mstatements as $stmt) {
                $stmt = preg_replace('/^\s*--.*$/m', '', $stmt);
                if (trim($stmt) === '') continue;
                DB::conn()->exec($stmt);
            }
            $messages[] = '✓ Migration applied: ' . basename($file);
        }

        // 2. Seed admin
        $existing = DB::one("SELECT id FROM users WHERE username='admin'");
        if (!$existing) {
            DB::exec(
                "INSERT INTO users (username, password_hash, email_encrypted, ic_encrypted,
                                    full_name, role, status, must_change_password)
                 VALUES (:u, :p, :e, :ic, :fn, 'admin', 'active', 1)",
                [
                    'u'  => 'admin',
                    'p'  => Crypto::passwordHash('Admin@12345'),
                    'e'  => Crypto::encrypt('admin@example.com', 'user-email'),
                    'ic' => Crypto::encrypt('A0000001', 'user-ic'),
                    'fn' => 'System Administrator',
                ]
            );
            $messages[] = '✓ Default admin created (admin / Admin@12345)';
        } else {
            $messages[] = '↺ admin user already exists, skipped';
        }

        // 3. Seed employee
        $existing = DB::one("SELECT id FROM users WHERE username='employee01'");
        if (!$existing) {
            DB::exec(
                "INSERT INTO users (username, password_hash, email_encrypted, ic_encrypted,
                                    full_name, role, status)
                 VALUES (:u, :p, :e, :ic, :fn, 'employee', 'active')",
                [
                    'u'  => 'employee01',
                    'p'  => Crypto::passwordHash('Employee@123'),
                    'e'  => Crypto::encrypt('alice@example.com', 'user-email'),
                    'ic' => Crypto::encrypt('990101015555', 'user-ic'),
                    'fn' => 'Alice Tan',
                ]
            );
            $messages[] = '✓ Default employee created (employee01 / Employee@123)';
        }

        // 4. Add a couple more employee accounts for demo
        foreach ([
            ['employee02', 'Employee@123', 'bob@example.com',   '880202025555', 'Bob Lim'],
            ['employee03', 'Employee@123', 'carol@example.com', '950303035555', 'Carol Wong'],
        ] as [$u, $pw, $em, $ic, $fn]) {
            $existing = DB::one("SELECT id FROM users WHERE username = :u", ['u' => $u]);
            if (!$existing) {
                DB::exec(
                    "INSERT INTO users (username, password_hash, email_encrypted, ic_encrypted, full_name, role, status)
                     VALUES (:u,:p,:e,:ic,:fn,'employee','active')",
                    [
                        'u'  => $u,
                        'p'  => Crypto::passwordHash($pw),
                        'e'  => Crypto::encrypt($em, 'user-email'),
                        'ic' => Crypto::encrypt($ic, 'user-ic'),
                        'fn' => $fn,
                    ]
                );
                $messages[] = "✓ Demo user $u created";
            }
        }

        // 5. Genesis log entry (so chain starts)
        $count = DB::one("SELECT COUNT(*) c FROM auth_logs");
        if ((int) $count['c'] === 0) {
            Logger::log([
                'user_id'          => null,
                'username_attempt' => '__system__',
                'event_type'       => 'admin_action',
                'ip_address'       => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
                'notes'            => 'System initialized',
            ]);
            $messages[] = '✓ Log chain initialized (genesis entry)';
        }

        $messages[] = '<strong>Setup complete. Now DELETE this file (public/setup.php) for security.</strong>';
    } catch (Throwable $e) {
        $errors[] = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Setup · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="form-card" style="max-width: 600px;">
    <h2>🚀 First-Time Setup</h2>
    <p class="sub">Initialize the Security Dashboard database</p>

    <?php if ($errors): foreach ($errors as $e): ?>
        <div class="alert-box error"><?= h($e) ?></div>
    <?php endforeach; endif; ?>

    <?php if ($messages): ?>
        <div class="alert-box success">
            <?php foreach ($messages as $m): ?>
                <div><?= $m ?></div>
            <?php endforeach; ?>
        </div>
        <?php if ($ran && !$errors): ?>
            <p style="text-align:center"><a class="btn primary" href="/login.php">Go to login</a></p>
        <?php endif; ?>
    <?php else: ?>
        <div class="alert-box warning">
            <strong>Before running setup:</strong>
            <ol style="margin: 8px 0 0 20px; font-size: 13px;">
                <li>Edit <code>/config/config.php</code> with real DB credentials.</li>
                <li>Generate AES key: <code>php -r "echo bin2hex(random_bytes(32));"</code></li>
                <li>Generate BLAKE3 key the same way.</li>
                <li>Replace the placeholders for <code>AES_KEY_HEX</code>, <code>BLAKE3_CTX_KEY_HEX</code>, and <code>PEPPER</code>.</li>
                <li>Make sure your MySQL DB exists on Hostinger.</li>
            </ol>
        </div>
        <form method="post">
            <input type="hidden" name="confirm" value="YES">
            <button class="btn danger full" type="submit">Run Setup</button>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
