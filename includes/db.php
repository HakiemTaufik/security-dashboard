<?php
/**
 * Database singleton using PDO + prepared statements.
 * All queries in this app are parameterized — no string concatenation.
 */

require_once __DIR__ . '/../config/config.php';

class DB
{
    private static ?PDO $pdo = null;

    public static function conn(): PDO
    {
        if (self::$pdo === null) {
            $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s',
                DB_HOST, DB_NAME, DB_CHARSET);
            $opts = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false, // real prepared statements
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET . " COLLATE utf8mb4_unicode_ci",
            ];
            try {
                self::$pdo = new PDO($dsn, DB_USER, DB_PASS, $opts);

                // Align MySQL's session timezone with PHP's (APP_TZ). Without this,
                // MySQL writes NOW()/CURRENT_TIMESTAMP in the server's zone (UTC on
                // most hosts) while PHP reads "X ago" in APP_TZ — making fresh rows
                // look hours old. We pass a numeric offset (e.g. +08:00) rather than
                // a named zone because shared hosts rarely load MySQL's timezone
                // tables. Offset is derived from APP_TZ so the two never drift.
                $offsetSec = (new DateTimeZone(APP_TZ))->getOffset(new DateTime('now', new DateTimeZone('UTC')));
                $sign = $offsetSec < 0 ? '-' : '+';
                $abs  = abs($offsetSec);
                $tzOffset = sprintf('%s%02d:%02d', $sign, intdiv($abs, 3600), intdiv($abs % 3600, 60));
                self::$pdo->exec("SET time_zone = '$tzOffset'");
            } catch (PDOException $e) {
                // In development, show the underlying error to help debugging.
                // In production, return a generic 500 to avoid leaking DB host
                // names or schema details to an attacker.
                http_response_code(500);
                $isDev = (defined('APP_ENV') ? APP_ENV : 'production') === 'development';
                if ($isDev) {
                    die('DB connect failed: ' . $e->getMessage());
                }
                die('Database unavailable.');
            }
        }
        return self::$pdo;
    }

    /** Convenience: run a parameterized query and return all rows. */
    public static function query(string $sql, array $params = []): array
    {
        $stmt = self::conn()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /** Convenience: fetch single row. */
    public static function one(string $sql, array $params = []): ?array
    {
        $stmt = self::conn()->prepare($sql);
        $stmt->execute($params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Convenience: execute INSERT/UPDATE/DELETE, return affected rows. */
    public static function exec(string $sql, array $params = []): int
    {
        $stmt = self::conn()->prepare($sql);
        $stmt->execute($params);
        return $stmt->rowCount();
    }

    public static function lastId(): string
    {
        return self::conn()->lastInsertId();
    }
}
