-- ============================================================
-- Migration 01 — Automated Integrity Monitoring  (comment #2)
-- Run once (e.g. via a one-time migrate page or phpMyAdmin), then keep.
-- Safe to re-run: uses IF NOT EXISTS.
-- ============================================================

-- Stores the last successfully verified position in the hash chain so that
-- routine checks only need to verify NEW rows (incremental) instead of
-- re-hashing the whole table every time.
CREATE TABLE IF NOT EXISTS integrity_checkpoint (
    id TINYINT UNSIGNED PRIMARY KEY DEFAULT 1,
    last_verified_id   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_verified_hash CHAR(64) NOT NULL
        DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO integrity_checkpoint (id) VALUES (1)
ON DUPLICATE KEY UPDATE id = id;

-- History of every automated/manual integrity check, so the dashboard can
-- show "last checked X ago, status OK" without re-running anything.
CREATE TABLE IF NOT EXISTS integrity_checks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    check_type   ENUM('incremental','full','manual') NOT NULL DEFAULT 'incremental',
    status       ENUM('ok','tampered','error')       NOT NULL DEFAULT 'ok',
    rows_scanned INT UNSIGNED NOT NULL DEFAULT 0,
    first_bad_id BIGINT UNSIGNED NULL,
    duration_ms  INT UNSIGNED NOT NULL DEFAULT 0,
    message      VARCHAR(255) NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created (created_at),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
