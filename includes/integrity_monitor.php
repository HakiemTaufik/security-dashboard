<?php
/**
 * ============================================================
 * IntegrityMonitor  (comment #2)
 * ============================================================
 * Makes BLAKE3 chain verification efficient and automatic.
 *
 * The old design re-hashed up to 10,000 rows on every manual click. That is
 * O(all rows) and slow. This class adds:
 *
 *   • runIncremental() — verifies only rows added since the last good
 *     checkpoint. O(new rows). Cheap enough to run every few minutes.
 *   • runFull()        — verifies the whole chain from genesis. Catches
 *     tampering of OLD (already-checkpointed) rows, which incremental cannot.
 *     Run this infrequently (e.g. once a day, off-peak).
 *
 * On any failure it (a) writes a CRITICAL alert to the alerts table and
 * (b) best-effort emails every admin. The alert row is the reliable channel;
 * email is a convenience notification on top.
 * ============================================================
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/logger.php';

class IntegrityMonitor
{
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Verify only the rows added since the last good checkpoint.
     * Returns the recorded check result array.
     */
    public static function runIncremental(): array
    {
        $start = microtime(true);
        $cp = self::checkpoint();
        $fromId   = (int) $cp['last_verified_id'];
        $prevHash = $cp['last_verified_hash'] ?: self::GENESIS_HASH;

        $rows = DB::query(
            "SELECT id, user_id, username_attempt, event_type, ip_address, user_agent,
                    device_info, session_id, threat_flag, notes, integrity_hash, prev_hash, created_at
             FROM auth_logs WHERE id > :fromId ORDER BY id ASC",
            ['fromId' => $fromId]
        );

        $result = self::verifyRows($rows, $prevHash);
        $durationMs = (int) round((microtime(true) - $start) * 1000);

        if ($result['ok']) {
            // Advance the checkpoint to the latest verified row.
            if (!empty($rows)) {
                $last = end($rows);
                self::saveCheckpoint((int) $last['id'], $last['integrity_hash']);
            }
            return self::record('incremental', 'ok', count($rows), null, $durationMs,
                'Verified ' . count($rows) . ' new entries.');
        }

        // Tampering found — do NOT advance the checkpoint.
        $rec = self::record('incremental', 'tampered', count($rows), $result['first_bad_id'], $durationMs,
            'Tampering at log #' . $result['first_bad_id']);
        self::notify($result['first_bad_id'], 'incremental');
        return $rec;
    }

    /**
     * Verify the entire chain from genesis. Use for the periodic deep sweep
     * and for the manual "Run Full Verification" button.
     *
     * @param string $type 'full' (scheduled) or 'manual' (button)
     */
    public static function runFull(string $type = 'full'): array
    {
        $start = microtime(true);
        $rows = DB::query(
            "SELECT id, user_id, username_attempt, event_type, ip_address, user_agent,
                    device_info, session_id, threat_flag, notes, integrity_hash, prev_hash, created_at
             FROM auth_logs ORDER BY id ASC"
        );
        $result = self::verifyRows($rows, self::GENESIS_HASH);
        $durationMs = (int) round((microtime(true) - $start) * 1000);

        if ($result['ok']) {
            if (!empty($rows)) {
                $last = end($rows);
                self::saveCheckpoint((int) $last['id'], $last['integrity_hash']);
            }
            return self::record($type, 'ok', count($rows), null, $durationMs,
                'Full chain intact (' . count($rows) . ' entries).');
        }

        $rec = self::record($type, 'tampered', count($rows), $result['first_bad_id'], $durationMs,
            'Tampering at log #' . $result['first_bad_id']);
        self::notify($result['first_bad_id'], $type);
        return $rec;
    }

    /**
     * Core verifier. Walks rows, recomputing each hash and checking the link.
     * @return array ['ok'=>bool, 'first_bad_id'=>?int, 'broken'=>array]
     */
    private static function verifyRows(array $rows, string $startPrev): array
    {
        $expectedPrev = $startPrev;
        $firstBad = null;
        $broken = [];
        foreach ($rows as $r) {
            $rowForHash = [
                'user_id'          => $r['user_id'],
                'username_attempt' => $r['username_attempt'],
                'event_type'       => $r['event_type'],
                'ip_address'       => $r['ip_address'],
                'user_agent'       => $r['user_agent'],
                'device_info'      => $r['device_info'],
                'session_id'       => $r['session_id'],
                'threat_flag'      => $r['threat_flag'],
                'notes'            => $r['notes'],
                'created_at'       => $r['created_at'],
            ];
            $expected = Crypto::logHash($expectedPrev, $rowForHash);
            $linkBad = !Crypto::hashEquals($r['prev_hash'], $expectedPrev);
            $hashBad = !Crypto::hashEquals($r['integrity_hash'], $expected);
            if ($linkBad || $hashBad) {
                if ($firstBad === null) $firstBad = (int) $r['id'];
                $broken[] = (int) $r['id'];
            }
            $expectedPrev = $r['integrity_hash']; // chain continues with stored value
        }
        return ['ok' => empty($broken), 'first_bad_id' => $firstBad, 'broken' => $broken];
    }

    // ---------- checkpoint helpers ----------

    public static function checkpoint(): array
    {
        $row = DB::one("SELECT last_verified_id, last_verified_hash FROM integrity_checkpoint WHERE id=1");
        if (!$row) {
            DB::exec("INSERT INTO integrity_checkpoint (id) VALUES (1) ON DUPLICATE KEY UPDATE id=id");
            $row = ['last_verified_id' => 0, 'last_verified_hash' => self::GENESIS_HASH];
        }
        return $row;
    }

    private static function saveCheckpoint(int $id, string $hash): void
    {
        DB::exec(
            "UPDATE integrity_checkpoint SET last_verified_id=:id, last_verified_hash=:h WHERE id=1",
            ['id' => $id, 'h' => $hash]
        );
    }

    // ---------- history helpers ----------

    private static function record(string $type, string $status, int $rows, ?int $firstBad, int $ms, string $msg): array
    {
        DB::exec(
            "INSERT INTO integrity_checks (check_type, status, rows_scanned, first_bad_id, duration_ms, message)
             VALUES (:t, :s, :rows, :bad, :ms, :msg)",
            ['t' => $type, 's' => $status, 'rows' => $rows, 'bad' => $firstBad, 'ms' => $ms, 'msg' => $msg]
        );
        return ['check_type' => $type, 'status' => $status, 'rows_scanned' => $rows,
                'first_bad_id' => $firstBad, 'duration_ms' => $ms, 'message' => $msg];
    }

    public static function lastCheck(): ?array
    {
        return DB::one("SELECT * FROM integrity_checks ORDER BY id DESC LIMIT 1");
    }

    public static function history(int $limit = 20): array
    {
        return DB::query("SELECT * FROM integrity_checks ORDER BY id DESC LIMIT :lim", ['lim' => $limit]);
    }

    // ---------- notification ----------

    /**
     * Raise a critical alert (deduplicated) and best-effort email all admins.
     */
    private static function notify(?int $firstBadId, string $type): void
    {
        $desc = sprintf(
            'LOG INTEGRITY VIOLATION (%s check): the BLAKE3 hash chain failed verification at log #%s. '
            . 'This indicates the auth_logs table may have been tampered with.',
            $type, $firstBadId ?? '?'
        );

        // 1) Alert row — dedupe an open integrity alert in the last hour.
        $dupe = DB::one(
            "SELECT id FROM alerts WHERE rule_name='log_integrity' AND status='open'
             AND created_at >= (NOW() - INTERVAL 1 HOUR) LIMIT 1"
        );
        if (!$dupe) {
            DB::exec(
                "INSERT INTO alerts (severity, rule_name, source_ip, description)
                 VALUES ('critical', 'log_integrity', NULL, :desc)",
                ['desc' => $desc]
            );
        }

        // 2) Best-effort email to every admin. Wrapped so a mail failure never
        //    breaks the cron job — the alert row above is the reliable record.
        try {
            self::emailAdmins('[SECURITY] Log integrity violation detected', $desc);
        } catch (\Throwable $e) {
            // swallow — alert row already persisted
        }
    }

    private static function emailAdmins(string $subject, string $body): void
    {
        if (!function_exists('mail')) return;
        $admins = DB::query("SELECT email_encrypted FROM users WHERE role='admin' AND status='active'");
        $headers = 'From: security@' . ($_SERVER['SERVER_NAME'] ?? 'localhost') . "\r\n"
                 . "Content-Type: text/plain; charset=utf-8\r\n";
        foreach ($admins as $a) {
            if (empty($a['email_encrypted'])) continue;
            $email = Crypto::decrypt($a['email_encrypted'], 'user-email');
            if ($email && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                @mail($email, $subject, $body, $headers);
            }
        }
    }
}
