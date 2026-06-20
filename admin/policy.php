<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../config/policy.php';

security_headers();
// Read-only console page: admins AND auditors may view it.
$user = Auth::requireConsole();

$standards = SecurityBaseline::standards();
$current = 'policy';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Policy · <?= h(APP_NAME) ?></title>
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/_sidebar.php'; ?>
    <main class="main">
        <div class="topbar">
            <h2>⚙️ Security Baseline</h2>
            <div class="user-info">
                <span class="role-badge"><?= h($user['role']) ?></span>
                <span><?= h($user['username']) ?></span>
            </div>
        </div>

        <div class="alert-box info" style="font-size:13px">
            <strong>🔒 This baseline is fixed and code-managed.</strong>
            Thresholds are defined in <code>config/policy.php</code> and version-controlled.
            They <strong>cannot be changed from this console</strong> — altering a value is a
            reviewed, redeployed change. This prevents an operator (or a stolen admin session)
            from weakening a control at runtime.
        </div>

        <div class="panel">
            <h3>Authentication &amp; Session Controls <small>mapped to industry standards</small></h3>
            <table>
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Value</th>
                        <th>Standard</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($standards as $row): ?>
                        <tr>
                            <td><?= h($row[0]) ?></td>
                            <td><strong><?= h((string) $row[1]) ?></strong></td>
                            <td style="color:var(--text-dim);font-size:13px"><?= h($row[2]) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    <tr>
                        <td>Minimum password length</td>
                        <td><strong><?= (int) SecurityBaseline::PASSWORD_MIN_LENGTH ?></strong></td>
                        <td style="color:var(--text-dim);font-size:13px">PCI DSS 4.0 §8.3.5 (≥12); NIST SP 800-63B-4 (length over complexity)</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="panel">
            <h3>Cryptography <small>configured in config/config.php</small></h3>
            <table>
                <tr><td>Password hashing</td><td><span class="badge" style="background:rgba(16,185,129,.2);color:#86efac">Argon2id</span></td><td style="color:var(--text-dim);font-size:13px">OWASP Password Storage Cheat Sheet</td></tr>
                <tr><td>PII encryption</td><td><span class="badge" style="background:rgba(16,185,129,.2);color:#86efac">AES-256-GCM</span></td><td style="color:var(--text-dim);font-size:13px">Authenticated encryption (NIST SP 800-38D)</td></tr>
                <tr><td>Log integrity</td><td><span class="badge" style="background:rgba(16,185,129,.2);color:#86efac">BLAKE3 keyed</span></td><td style="color:var(--text-dim);font-size:13px">Keyed hash chain (tamper-evident)</td></tr>
                <tr><td>Memory cost</td><td><?= ARGON2_MEMORY_COST ?> KB</td><td style="color:var(--text-dim);font-size:13px">OWASP minimum 19,456 KB (19 MiB) — this exceeds it</td></tr>
                <tr><td>Time cost</td><td><?= ARGON2_TIME_COST ?> iterations</td><td style="color:var(--text-dim);font-size:13px">OWASP minimum t=2 — this exceeds it</td></tr>
            </table>
        </div>

        <p style="font-size:12px;color:var(--text-faint);margin-top:12px">
            To change a value: edit <code>config/policy.php</code> (or the cryptography constants
            in <code>config/config.php</code>), have the change reviewed, and redeploy.
        </p>
    </main>
</div>
</body>
</html>
