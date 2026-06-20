<?php
/**
 * ============================================================
 * Crypto helper - all sensitive operations live here.
 * ============================================================
 *  - Argon2id password hashing/verification
 *  - AES-256-GCM authenticated encryption for PII
 *  - BLAKE3 keyed integrity hashing for log chaining
 *  - HMAC-SHA256 email hash for unique-lookup of encrypted PII
 *
 * Constant-time comparisons used where applicable.
 * ============================================================
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/blake3.php';

class Crypto
{
    // ------------------------------------------------------------------
    // Password hashing (Argon2id)
    // ------------------------------------------------------------------
    public static function passwordHash(string $plain): string
    {
        $peppered = self::pepper($plain);
        return password_hash($peppered, PASSWORD_ARGON2ID, [
            'memory_cost' => ARGON2_MEMORY_COST,
            'time_cost'   => ARGON2_TIME_COST,
            'threads'     => ARGON2_THREADS,
        ]);
    }

    public static function passwordVerify(string $plain, string $hash): bool
    {
        return password_verify(self::pepper($plain), $hash);
    }

    public static function passwordNeedsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => ARGON2_MEMORY_COST,
            'time_cost'   => ARGON2_TIME_COST,
            'threads'     => ARGON2_THREADS,
        ]);
    }

    private static function pepper(string $plain): string
    {
        return hash_hmac('sha256', $plain, PEPPER, true) . $plain;
    }

    // ------------------------------------------------------------------
    // AES-256-GCM (PII encryption)
    // ------------------------------------------------------------------
    public static function encrypt(string $plaintext, string $aad = ''): string
    {
        $key = self::aesKey();
        $iv  = random_bytes(12);
        $tag = '';
        $ct  = openssl_encrypt(
            $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16
        );
        if ($ct === false) {
            throw new RuntimeException('AES-256-GCM encryption failed: ' . openssl_error_string());
        }
        return base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $encoded, string $aad = ''): ?string
    {
        $bin = base64_decode($encoded, true);
        if ($bin === false || strlen($bin) < 28) {
            return null;
        }
        $iv  = substr($bin, 0, 12);
        $tag = substr($bin, 12, 16);
        $ct  = substr($bin, 28);

        // openssl_decrypt returns FALSE on any error (wrong key, wrong AAD,
        // tampered ciphertext, invalid GCM tag). Treat any failure as
        // "no data" — never return false or a corrupted value to the caller.
        $pt = openssl_decrypt($ct, 'aes-256-gcm', self::aesKey(), OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($pt === false) {
            return null;
        }
        return $pt;
    }

    public static function maskEmail(?string $email): string
    {
        if (!$email || strpos($email, '@') === false) return '***';
        [$local, $domain] = explode('@', $email, 2);
        $localMasked = mb_substr($local, 0, 2) . str_repeat('*', max(1, mb_strlen($local) - 2));
        return $localMasked . '@' . $domain;
    }

    public static function maskIC(?string $ic): string
    {
        if (!$ic) return '***';
        $len = strlen($ic);
        if ($len <= 4) return str_repeat('*', $len);
        return substr($ic, 0, 2) . str_repeat('*', $len - 4) . substr($ic, -2);
    }

    /**
     * Deterministic email hash for unique-lookup. Uses HMAC-SHA256 with PEPPER
     * so an attacker without the pepper cannot precompute hashes from a leaked DB.
     */
    public static function emailHash(string $email): string
    {
        $normalized = strtolower(trim($email));
        return hash_hmac('sha256', $normalized, PEPPER);
    }

    private static function aesKey(): string
    {
        $key = @hex2bin(AES_KEY_HEX);
        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException('AES_KEY_HEX must be 64 hex characters (32 bytes).');
        }
        return $key;
    }

    private static function blake3Key(): string
    {
        $k = @hex2bin(BLAKE3_CTX_KEY_HEX);
        if ($k === false || strlen($k) !== 32) {
            throw new RuntimeException('BLAKE3_CTX_KEY_HEX must be 64 hex characters.');
        }
        return $k;
    }

    // ------------------------------------------------------------------
    // BLAKE3 log integrity
    // ------------------------------------------------------------------
    public static function logHash(string $prevHashHex, array $row): string
    {
        $canonical = self::canonicalize($row);
        $input = hex2bin($prevHashHex) . $canonical;
        return Blake3::keyedHex(self::blake3Key(), $input);
    }

    public static function canonicalize(array $row): string
    {
        ksort($row);
        return json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public static function hashEquals(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}
