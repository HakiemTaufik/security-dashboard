<?php
/**
 * ============================================================
 * RBAC — Role-Based Access Control  (comment #3)
 * ============================================================
 * Separates IDENTITY (department — who you are) from AUTHORIZATION
 * (role — what you may do), which is the standard RBAC model.
 *
 * Roles (access tiers):
 *   admin    — full console: view + manage users, alerts, policy
 *   auditor  — READ-ONLY console: see everything, change nothing
 *              (separation of duties — ideal for oversight/compliance)
 *   manager  — department lead; staff app access (own dashboard)
 *   employee — standard staff; own dashboard only
 *
 * Departments are an attribute, not a permission. "Finance / employee"
 * and "Security / auditor" are now expressible.
 * ============================================================
 */

final class RBAC
{
    public const ROLES = ['admin', 'auditor', 'manager', 'employee'];

    public const DEPARTMENTS = ['IT', 'Security', 'HR', 'Finance', 'Operations', 'Management'];

    /**
     * Capability matrix. A capability is a verb the app checks before acting.
     *   view_console  — may open the admin monitoring pages (read)
     *   manage_users  — may block/unblock/reset/approve users (write)
     *   manage_alerts — may acknowledge/resolve alerts (write)
     *   run_integrity — may trigger a verification run
     */
    private const CAPS = [
        'admin'    => ['view_console', 'manage_users', 'manage_alerts', 'run_integrity'],
        'auditor'  => ['view_console', 'run_integrity'],          // read-only + can verify
        'manager'  => [],                                          // staff dashboard only
        'employee' => [],                                          // staff dashboard only
    ];

    public static function can(?string $role, string $capability): bool
    {
        if ($role === null) return false;
        return in_array($capability, self::CAPS[$role] ?? [], true);
    }

    /** Roles that can open the admin console at all (read access). */
    public static function consoleRoles(): array
    {
        $out = [];
        foreach (self::CAPS as $role => $caps) {
            if (in_array('view_console', $caps, true)) $out[] = $role;
        }
        return $out; // ['admin','auditor']
    }

    public static function isValidRole(string $role): bool
    {
        return in_array($role, self::ROLES, true);
    }

    public static function isValidDepartment(string $dept): bool
    {
        return in_array($dept, self::DEPARTMENTS, true);
    }

    public static function label(string $role): string
    {
        return ucfirst($role);
    }
}
