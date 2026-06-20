<?php
/**
 * Centralized logger.
 * Every event becomes a row in auth_logs with a BLAKE3-keyed integrity hash
 * chained to the previous row's hash. Tampering with any row breaks the chain
 * downstream and is detectable by /admin/integrity.php.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

class Logger
{
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Append a log entry. Returns inserted ID.
     *
     * @param array $opts keys: user_id, username_attempt, event_type,
     *                          ip_address, user_agent, device_info,
     *                          session_id, threat_flag, notes
     */
    /**
     * Append a log entry atomically.
     *
     * The read-chain-tip → compute-hash → insert sequence is wrapped in a
     * transaction with SELECT ... FOR UPDATE. This prevents two concurrent
     * requests (e.g. during a ZAP scan that fires many login attempts per
     * second) from reading the same chain tip and both computing their hash
     * against it — which would leave one row with a wrong prev_hash and
     * break the integrity chain.
     *
     * InnoDB row-level locking ensures only one transaction at a time can
     * hold the lock on the latest row, so the second request blocks until
     * the first commits.
     */
    public static function log(array $opts): int
    {
        $row = [
            'user_id'          => $opts['user_id']          ?? null,
            'username_attempt' => $opts['username_attempt'] ?? '',
            'event_type'       => $opts['event_type']       ?? 'login_failed',
            'ip_address'       => $opts['ip_address']       ?? self::clientIp(),
            'user_agent'       => $opts['user_agent']       ?? self::userAgent(),
            'device_info'      => $opts['device_info']      ?? self::deviceInfo(),
            'session_id'       => $opts['session_id']       ?? session_id(),
            'threat_flag'      => $opts['threat_flag']      ?? 'none',
            'notes'            => $opts['notes']            ?? null,
            'created_at'       => date('Y-m-d H:i:s'),
        ];

        $pdo = DB::conn();
        $pdo->beginTransaction();
        try {
            // Lock the latest row so no other request can read the chain
            // tip until this transaction commits. If the table is empty,
            // FOR UPDATE returns nothing and we fall back to GENESIS_HASH.
            $tip = $pdo->prepare(
                "SELECT integrity_hash FROM auth_logs ORDER BY id DESC LIMIT 1 FOR UPDATE"
            );
            $tip->execute();
            $prevRow  = $tip->fetch(\PDO::FETCH_ASSOC);
            $prevHash = $prevRow['integrity_hash'] ?? self::GENESIS_HASH;

            $integrityHash = Crypto::logHash($prevHash, $row);

            $sql = "INSERT INTO auth_logs
                    (user_id, username_attempt, event_type, ip_address, user_agent,
                     device_info, session_id, threat_flag, notes, integrity_hash, prev_hash, created_at)
                    VALUES
                    (:user_id, :username_attempt, :event_type, :ip_address, :user_agent,
                     :device_info, :session_id, :threat_flag, :notes, :integrity_hash, :prev_hash, :created_at)";
            $stmt = $pdo->prepare($sql);
            $stmt->execute(array_merge($row, [
                'integrity_hash' => $integrityHash,
                'prev_hash'      => $prevHash,
            ]));
            $id = (int) $pdo->lastInsertId();

            $pdo->commit();
            return $id;
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    public static function lastHash(): string
    {
        $row = DB::one("SELECT integrity_hash FROM auth_logs ORDER BY id DESC LIMIT 1");
        return $row['integrity_hash'] ?? self::GENESIS_HASH;
    }

    /**
     * Verify the integrity chain. Returns array of any broken row IDs.
     * Empty array == chain intact.
     */
    public static function verifyChain(int $limit = 1000): array
    {
        $rows = DB::query(
            "SELECT id, user_id, username_attempt, event_type, ip_address, user_agent,
                    device_info, session_id, threat_flag, notes, integrity_hash, prev_hash, created_at
             FROM auth_logs ORDER BY id ASC LIMIT :lim",
            ['lim' => $limit]
        );
        $broken = [];
        $expectedPrev = self::GENESIS_HASH;
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
                $broken[] = [
                    'id' => (int) $r['id'],
                    'expected_prev' => $expectedPrev,
                    'stored_prev'   => $r['prev_hash'],
                    'expected_hash' => $expected,
                    'stored_hash'   => $r['integrity_hash'],
                ];
            }
            $expectedPrev = $r['integrity_hash']; // chain continues with stored value
        }
        return $broken;
    }

    public static function clientIp(): string
    {
        $candidates = [
            $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
            $_SERVER['HTTP_X_FORWARDED_FOR']  ?? null,
            $_SERVER['REMOTE_ADDR']           ?? null,
        ];
        foreach ($candidates as $c) {
            if (!$c) continue;
            $first = trim(explode(',', $c)[0]);
            if (filter_var($first, FILTER_VALIDATE_IP)) return $first;
        }
        return '0.0.0.0';
    }

    public static function userAgent(): string
    {
        return substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);
    }

    public static function deviceInfo(): string
    {
        $ua = self::userAgent();
        $os = 'Unknown';
        $browser = 'Unknown';
        if (preg_match('/Windows NT [\d\.]+/', $ua, $m)) $os = $m[0];
        elseif (preg_match('/Mac OS X [\d_\.]+/', $ua, $m)) $os = $m[0];
        elseif (preg_match('/Android [\d\.]+/', $ua, $m)) $os = $m[0];
        elseif (preg_match('/iPhone OS [\d_]+/', $ua, $m)) $os = $m[0];
        elseif (stripos($ua, 'Linux') !== false) $os = 'Linux';

        if (stripos($ua, 'Edg/') !== false)        $browser = 'Edge';
        elseif (stripos($ua, 'Chrome') !== false)  $browser = 'Chrome';
        elseif (stripos($ua, 'Firefox') !== false) $browser = 'Firefox';
        elseif (stripos($ua, 'Safari') !== false)  $browser = 'Safari';

        return "$os / $browser";
    }
}
