<?php
/**
 * ============================================================
 * SECURITY BASELINE — fixed, code-managed policy
 * ============================================================
 * This file is the SINGLE SOURCE OF TRUTH for every security
 * threshold in the application.
 *
 * WHY THIS IS A CODE FILE AND NOT A DATABASE-EDITABLE FORM
 * -------------------------------------------------------
 * A security baseline must not be weakenable at runtime by an
 * operator. If an administrator (or an attacker who has stolen
 * an admin session) could set "max failed attempts = 9999" or
 * "lockout = 0" from a web form, the brute-force protection
 * would be one click away from being disabled. Separating the
 * *policy* (what the controls are) from *operations* (running
 * the system day to day) is a core principle in ISO 27001 A.5,
 * NIST 800-53 (CM-/AC- families) and the CIS Controls.
 *
 * Changing a value here is therefore a *change-managed* action:
 * edit the file, review it, and redeploy. It cannot be done by
 * clicking a button in the admin console.
 *
 * Each value below cites the standard it is derived from.
 * Last reviewed: 2026-06-15.
 * ============================================================
 */

final class SecurityBaseline
{
    /**
     * Account-lockout & detection thresholds.
     * Keys are intentionally identical to the legacy `security_policy`
     * columns so the rest of the code reads them unchanged.
     */
    private const VALUES = [
        // --- Account lockout (authentication throttling) ---
        // 5 consecutive failures before lockout.
        // CIS / Microsoft security baseline = 5; PCI DSS 4.0 §8.3.4 ceiling = 10.
        // We choose the stricter CIS value.
        'max_failed_attempts'        => 5,

        // Lockout duration in minutes.
        // PCI DSS 4.0 §8.3.7 requires "minimum 30 minutes, or until an
        // administrator unlocks the account". We use 30.
        'lockout_minutes'            => 30,

        // --- Brute-force detection (alerting, not lockout) ---
        // Internal detection-engine tuning. Not a compliance control —
        // these only decide when an *alert* is raised.
        'brute_force_window_minutes' => 10,
        'brute_force_threshold'      => 10,

        // --- Rapid-fire detection (alerting) ---
        'rapid_fire_seconds'         => 5,
        'rapid_fire_threshold'       => 4,

        // --- Off-hours detection (operational, org-specific) ---
        // Business hours window used only to flag out-of-hours logins.
        'working_hours_start'        => 8,   // 08:00
        'working_hours_end'          => 18,  // 18:00

        // --- Session idle timeout (minutes) ---
        // PCI DSS 4.0 §8.2.8 and NIST SP 800-63B-4 (AAL3 reauth on
        // inactivity) = 15 minutes for sensitive/administrative systems.
        // NOTE: the live enforcement constant is SESSION_LIFETIME_MIN in
        // config/config.php — set that to 15 to match this baseline.
        'session_timeout_minutes'    => 15,
    ];

    // --- Password policy (used by register.php / change-password.php) ---
    // PCI DSS 4.0 §8.3.5: minimum 12 characters.
    // NIST SP 800-63B-4: length is the primary strength factor; composition
    // rules are *not* required by NIST but are kept here to satisfy the
    // project rubric. Breach-list checking is the recommended future add-on.
    public const PASSWORD_MIN_LENGTH = 12;
    public const PASSWORD_MAX_LENGTH = 128;      // allow long passphrases
    public const PASSWORD_REQUIRE_UPPER  = true;
    public const PASSWORD_REQUIRE_LOWER  = true;
    public const PASSWORD_REQUIRE_DIGIT  = true;
    public const PASSWORD_REQUIRE_SYMBOL = true;

    /**
     * Returns the baseline as an array in the same shape the code used to
     * read from the `security_policy` table. Drop-in replacement for the old
     * DB lookup.
     */
    public static function get(): array
    {
        return self::VALUES;
    }

    /** Convenience getter for a single value. */
    public static function value(string $key, $default = null)
    {
        return self::VALUES[$key] ?? $default;
    }

    /**
     * Human-readable mapping of each control to the standard it satisfies.
     * Used by the read-only admin/policy.php view so the standard is visible
     * to assessors without exposing an editable form.
     */
    public static function standards(): array
    {
        return [
            'max_failed_attempts'     => ['Max failed attempts before lockout', self::VALUES['max_failed_attempts'], 'CIS / Microsoft baseline (≤10 per PCI DSS 4.0 §8.3.4)'],
            'lockout_minutes'         => ['Lockout duration (minutes)', self::VALUES['lockout_minutes'], 'PCI DSS 4.0 §8.3.7 (≥30 min or admin unlock)'],
            'session_timeout_minutes' => ['Idle session timeout (minutes)', self::VALUES['session_timeout_minutes'], 'PCI DSS 4.0 §8.2.8 / NIST SP 800-63B-4 AAL3'],
            'brute_force_window_minutes' => ['Brute-force window (minutes)', self::VALUES['brute_force_window_minutes'], 'Detection tuning (internal)'],
            'brute_force_threshold'   => ['Brute-force failure threshold', self::VALUES['brute_force_threshold'], 'Detection tuning (internal)'],
            'rapid_fire_seconds'      => ['Rapid-fire window (seconds)', self::VALUES['rapid_fire_seconds'], 'Detection tuning (internal)'],
            'rapid_fire_threshold'    => ['Rapid-fire failure threshold', self::VALUES['rapid_fire_threshold'], 'Detection tuning (internal)'],
            'working_hours_start'     => ['Working hours start', self::VALUES['working_hours_start'] . ':00', 'Operational (org-specific)'],
            'working_hours_end'       => ['Working hours end', self::VALUES['working_hours_end'] . ':00', 'Operational (org-specific)'],
        ];
    }
}
