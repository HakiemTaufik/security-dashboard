<?php
/**
 * Admin action handler. POST-only. CSRF-protected.
 * Records every action in admin_actions with BLAKE3 integrity hash.
 *
 * CHANGED:
 *   • update_policy is REMOVED — the security baseline is code-managed
 *     (config/policy.php) and can no longer be altered from the web tier.
 *   • approve_user / reject_user added for the registration approval workflow.
 */
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../includes/crypto.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
$user = Auth::requireLogin('admin');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die('Method not allowed');
}
if (!SessionManager::csrfCheck($_POST['csrf'] ?? null)) {
    http_response_code(403);
    die('Invalid CSRF token');
}

$action = $_POST['action'] ?? '';
$redirect = $_POST['redirect'] ?? '/admin/dashboard.php';
$msg = ''; $err = '';

function recordAdminAction(int $adminId, string $action, ?int $targetId, string $detail): void
{
    $row = [
        'admin_id'      => $adminId,
        'action'        => $action,
        'target_user_id'=> $targetId,
        'detail'        => $detail,
        'ip_address'    => Logger::clientIp(),
        'created_at'    => date('Y-m-d H:i:s'),
    ];
    $prev = DB::one("SELECT integrity_hash FROM admin_actions ORDER BY id DESC LIMIT 1");
    $prevHash = $prev['integrity_hash'] ?? str_repeat('0', 64);
    $row['integrity_hash'] = Crypto::logHash($prevHash, $row);

    DB::exec(
        "INSERT INTO admin_actions
         (admin_id, action, target_user_id, detail, ip_address, integrity_hash, created_at)
         VALUES (:admin_id, :action, :target_user_id, :detail, :ip_address, :integrity_hash, :created_at)",
        $row
    );
}

try {
    switch ($action) {
        case 'block_user': {
            $tid = (int) ($_POST['user_id'] ?? 0);
            if (!$tid || $tid === (int) $user['id']) throw new Exception('Invalid target.');
            $t = DB::one("SELECT username FROM users WHERE id = :id", ['id' => $tid]);
            if (!$t) throw new Exception('User not found.');
            DB::exec("UPDATE users SET status='disabled' WHERE id = :id", ['id' => $tid]);
            DB::exec("DELETE FROM active_sessions WHERE user_id = :id", ['id' => $tid]);
            recordAdminAction($user['id'], 'block_user', $tid, "Blocked user '{$t['username']}'");
            Logger::log([
                'user_id' => $tid, 'username_attempt' => $t['username'],
                'event_type' => 'account_blocked',
                'notes' => "Blocked by admin {$user['username']}",
            ]);
            $msg = "User '{$t['username']}' has been blocked.";
            break;
        }

        case 'unblock_user': {
            $tid = (int) ($_POST['user_id'] ?? 0);
            $t = DB::one("SELECT username FROM users WHERE id = :id", ['id' => $tid]);
            if (!$t) throw new Exception('User not found.');
            DB::exec("UPDATE users SET status='active', failed_attempts=0, locked_until=NULL WHERE id = :id", ['id' => $tid]);
            recordAdminAction($user['id'], 'unblock_user', $tid, "Unblocked user '{$t['username']}'");
            Logger::log([
                'user_id' => $tid, 'username_attempt' => $t['username'],
                'event_type' => 'account_unblocked',
                'notes' => "Unblocked by admin {$user['username']}",
            ]);
            $msg = "User '{$t['username']}' has been unblocked.";
            break;
        }

        case 'reset_password': {
            $tid = (int) ($_POST['user_id'] ?? 0);
            $t = DB::one("SELECT username FROM users WHERE id = :id", ['id' => $tid]);
            if (!$t) throw new Exception('User not found.');
            $temp = bin2hex(random_bytes(6)); // 12 hex chars
            DB::exec(
                "UPDATE users SET password_hash = :h, must_change_password = 1, failed_attempts=0, locked_until=NULL WHERE id = :id",
                ['h' => Crypto::passwordHash($temp), 'id' => $tid]
            );
            recordAdminAction($user['id'], 'reset_password', $tid, "Reset password for '{$t['username']}'");
            Logger::log([
                'user_id' => $tid, 'username_attempt' => $t['username'],
                'event_type' => 'password_reset',
                'notes' => "Reset by admin {$user['username']}",
            ]);
            $msg = "Password reset. Temporary password for '{$t['username']}': $temp  (deliver via secure channel)";
            break;
        }

        case 'approve_user': {
            $tid  = (int) ($_POST['user_id'] ?? 0);
            $dept = trim($_POST['department'] ?? '');
            // Every approved applicant becomes a standard employee. Elevated
            // roles are granted separately from User Management (assign_role),
            // so the approval step only needs to confirm the department.
            $role = 'employee';
            if (!RBAC::isValidDepartment($dept)) throw new Exception('Invalid department.');

            $t = DB::one("SELECT username, status FROM users WHERE id = :id", ['id' => $tid]);
            if (!$t) throw new Exception('User not found.');
            if ($t['status'] !== 'pending') throw new Exception('Account is not pending approval.');

            DB::exec(
                "UPDATE users
                    SET status='active', role=:role, department=:dept,
                        approved_by=:by, approved_at=NOW()
                  WHERE id=:id AND status='pending'",
                ['role' => $role, 'dept' => $dept, 'by' => $user['id'], 'id' => $tid]
            );
            recordAdminAction($user['id'], 'approve_user', $tid,
                "Approved '{$t['username']}' as {$role} in {$dept}");
            Logger::log([
                'user_id' => $tid, 'username_attempt' => $t['username'],
                'event_type' => 'account_approved',
                'notes' => "Approved by {$user['username']} as {$role} / {$dept}",
            ]);
            $msg = "Approved '{$t['username']}' as employee ({$dept}).";
            break;
        }

        case 'assign_role': {
            // Change an existing (active) user's role and/or department. This is
            // how auditor / manager / admin roles are granted — never at signup.
            $tid  = (int) ($_POST['user_id'] ?? 0);
            $role = trim($_POST['role'] ?? '');
            $dept = trim($_POST['department'] ?? '');
            if (!RBAC::isValidRole($role))       throw new Exception('Invalid role.');
            if (!RBAC::isValidDepartment($dept)) throw new Exception('Invalid department.');
            if ($tid === (int) $user['id'])      throw new Exception('You cannot change your own role.');

            $t = DB::one("SELECT username, status FROM users WHERE id = :id", ['id' => $tid]);
            if (!$t) throw new Exception('User not found.');
            if ($t['status'] === 'pending') throw new Exception('Approve the account first.');

            DB::exec(
                "UPDATE users SET role=:role, department=:dept WHERE id=:id",
                ['role' => $role, 'dept' => $dept, 'id' => $tid]
            );
            recordAdminAction($user['id'], 'assign_role', $tid,
                "Set '{$t['username']}' to {$role} / {$dept}");
            Logger::log([
                'user_id' => $tid, 'username_attempt' => $t['username'],
                'event_type' => 'admin_action',
                'notes' => "Role/department set to {$role} / {$dept} by {$user['username']}",
            ]);
            $msg = "Updated '{$t['username']}' → {$role} ({$dept}).";
            break;
        }

        case 'reject_user': {
            $tid = (int) ($_POST['user_id'] ?? 0);
            $t = DB::one("SELECT username, status FROM users WHERE id = :id", ['id' => $tid]);
            if (!$t) throw new Exception('User not found.');
            if ($t['status'] !== 'pending') throw new Exception('Only pending accounts can be rejected.');

            // Audit BEFORE deletion (FK ON DELETE SET NULL keeps the log rows;
            // the username is preserved in the detail/notes text).
            recordAdminAction($user['id'], 'reject_user', $tid, "Rejected registration '{$t['username']}'");
            Logger::log([
                'user_id' => $tid, 'username_attempt' => $t['username'],
                'event_type' => 'account_rejected',
                'notes' => "Rejected by admin {$user['username']}",
            ]);
            DB::exec("DELETE FROM users WHERE id = :id AND status='pending'", ['id' => $tid]);
            $msg = "Rejected and removed pending registration '{$t['username']}'.";
            break;
        }

        case 'acknowledge_alert': {
            $aid = (int) ($_POST['alert_id'] ?? 0);
            DB::exec(
                "UPDATE alerts SET status='acknowledged', acknowledged_by=:by, acknowledged_at=NOW()
                 WHERE id=:id AND status='open'",
                ['by' => $user['id'], 'id' => $aid]
            );
            recordAdminAction($user['id'], 'acknowledge_alert', null, "Acknowledged alert #$aid");
            $msg = "Alert #$aid acknowledged.";
            break;
        }

        case 'resolve_alert': {
            $aid = (int) ($_POST['alert_id'] ?? 0);
            DB::exec(
                "UPDATE alerts SET status='resolved', acknowledged_by=:by, acknowledged_at=NOW()
                 WHERE id=:id",
                ['by' => $user['id'], 'id' => $aid]
            );
            recordAdminAction($user['id'], 'resolve_alert', null, "Resolved alert #$aid");
            $msg = "Alert #$aid resolved.";
            break;
        }

        case 'update_policy':
            // Intentionally disabled. The security baseline is fixed and
            // code-managed (config/policy.php). It must not be editable at
            // runtime — see comment #1 rationale.
            throw new Exception('The security baseline is code-managed and cannot be changed from the console.');

        default:
            throw new Exception('Unknown action.');
    }
} catch (Throwable $e) {
    $err = $e->getMessage();
}

// Build redirect with flash message
$qs = http_build_query(['flash' => $msg ?: $err, 'flash_type' => $err ? 'error' : 'success']);
$sep = strpos($redirect, '?') === false ? '?' : '&';
header("Location: $redirect$sep$qs");
exit;
