<?php
/**
 * Rule-based threat detection. Run BEFORE the log entry is inserted so the
 * resulting threat_flag becomes part of the integrity-hashed canonical row.
 *
 * CHANGED (comment #1): thresholds now come from the fixed, code-managed
 * SecurityBaseline (config/policy.php) instead of the runtime-editable
 * security_policy table. They can no longer be weakened from the web UI.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/../config/policy.php';

class Detection
{
    /**
     * Returns the fixed security baseline. Kept as a method (same name/shape
     * as before) so callers do not change. No longer touches the database.
     */
    public static function policy(): array
    {
        return SecurityBaseline::get();
    }

    /**
     * Evaluate detection rules. Returns the threat flag to assign to the
     * upcoming log entry ('none' if nothing triggers), and raises alerts
     * for any positive detections.
     *
     * @param array $ctx ['user_id', 'username_attempt', 'event_type', 'ip_address', 'role'?]
     * @return string one of: none, brute_force, rapid_fire, off_hours, insider, geo_anomaly
     */
    public static function evaluate(array $ctx): string
    {
        $p = self::policy();
        $flag = 'none';

        if ($ctx['event_type'] === 'login_failed') {
            // rapid-fire is a stricter overlay; check it first so its label wins
            if (self::checkRapidFire($ctx, $p)) {
                $flag = 'rapid_fire';
            } elseif (self::checkBruteForce($ctx, $p)) {
                $flag = 'brute_force';
            }
        } elseif ($ctx['event_type'] === 'login_success') {
            if (self::checkOffHours($ctx, $p)) {
                $flag = 'off_hours';
            }
        }

        return $flag;
    }

    private static function checkBruteForce(array $ctx, array $p): bool
    {
        $window = (int) $p['brute_force_window_minutes'];
        $threshold = (int) $p['brute_force_threshold'];

        $r = DB::one(
            "SELECT COUNT(*) AS c, COUNT(DISTINCT username_attempt) AS u
             FROM auth_logs
             WHERE ip_address = :ip
               AND event_type = 'login_failed'
               AND created_at >= (NOW() - INTERVAL :w MINUTE)",
            ['ip' => $ctx['ip_address'], 'w' => $window]
        );
        $count = (int) ($r['c'] ?? 0);
        $distinctUsers = (int) ($r['u'] ?? 0);

        // Note: the *current* failed attempt has not been logged yet, so we
        // compare against (threshold - 1).
        if ($count + 1 >= $threshold) {
            $sev = $distinctUsers + 1 >= 3 ? 'critical' : 'warning';
            self::raise([
                'severity'    => $sev,
                'rule_name'   => 'brute_force',
                'target_user' => $ctx['username_attempt'],
                'source_ip'   => $ctx['ip_address'],
                'description' => sprintf(
                    'Brute-force suspected: %d failed logins in %d min from %s across %d username(s).',
                    $count + 1, $window, $ctx['ip_address'], max($distinctUsers, 1)
                ),
            ]);
            return true;
        }
        return false;
    }

    private static function checkRapidFire(array $ctx, array $p): bool
    {
        $sec = (int) $p['rapid_fire_seconds'];
        $thr = (int) $p['rapid_fire_threshold'];
        $r = DB::one(
            "SELECT COUNT(*) c FROM auth_logs
             WHERE ip_address = :ip
               AND event_type = 'login_failed'
               AND created_at >= (NOW() - INTERVAL :s SECOND)",
            ['ip' => $ctx['ip_address'], 's' => $sec]
        );
        $c = (int) ($r['c'] ?? 0);
        if ($c + 1 >= $thr) {
            self::raise([
                'severity'    => 'warning',
                'rule_name'   => 'rapid_fire',
                'target_user' => $ctx['username_attempt'],
                'source_ip'   => $ctx['ip_address'],
                'description' => sprintf(
                    'Rapid-fire failures: %d attempts within %d seconds from %s.',
                    $c + 1, $sec, $ctx['ip_address']
                ),
            ]);
            return true;
        }
        return false;
    }

    private static function checkOffHours(array $ctx, array $p): bool
    {
        $hour  = (int) date('G');
        $start = (int) $p['working_hours_start'];
        $end   = (int) $p['working_hours_end'];
        if ($hour < $start || $hour >= $end) {
            // Off-hours informational alert (only for non-admin staff)
            $u = $ctx['user_id']
                ? DB::one("SELECT role FROM users WHERE id = :id", ['id' => $ctx['user_id']])
                : null;
            if ($u && $u['role'] !== 'admin') {
                self::raise([
                    'severity'    => 'info',
                    'rule_name'   => 'off_hours',
                    'target_user' => $ctx['username_attempt'],
                    'source_ip'   => $ctx['ip_address'],
                    'description' => sprintf(
                        'Off-hours login by %s at %s (working hours %d:00–%d:00).',
                        $ctx['username_attempt'], date('H:i'), $start, $end
                    ),
                ]);
                return true;
            }
        }
        return false;
    }

    private static function raise(array $a): void
    {
        // Avoid duplicate alert spam: same rule + ip + open in last 5 min
        $dupe = DB::one(
            "SELECT id FROM alerts
             WHERE rule_name = :r
               AND IFNULL(source_ip,'') = :ip
               AND status = 'open'
               AND created_at >= (NOW() - INTERVAL 5 MINUTE)
             LIMIT 1",
            ['r' => $a['rule_name'], 'ip' => $a['source_ip'] ?? '']
        );
        if ($dupe) return;

        $userId = null;
        if (!empty($a['target_user'])) {
            $u = DB::one("SELECT id FROM users WHERE username = :n", ['n' => $a['target_user']]);
            $userId = $u['id'] ?? null;
        }
        DB::exec(
            "INSERT INTO alerts (severity, rule_name, target_user_id, target_username, source_ip, description)
             VALUES (:sev, :rn, :uid, :uname, :ip, :desc)",
            [
                'sev'   => $a['severity'],
                'rn'    => $a['rule_name'],
                'uid'   => $userId,
                'uname' => $a['target_user'] ?? null,
                'ip'    => $a['source_ip'] ?? null,
                'desc'  => $a['description'],
            ]
        );
    }
}
