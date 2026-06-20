-- ============================================================
-- Security Dashboard System - Database Schema
-- MySQL 5.7+ / MariaDB 10.3+
-- ============================================================

-- Drop existing (use cautiously in production!)
-- DROP DATABASE IF EXISTS security_dashboard;
-- CREATE DATABASE security_dashboard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE security_dashboard;

-- ============================================================
-- USERS TABLE
-- Stores accounts. Sensitive PII (email, ic_number) is AES-256-GCM encrypted.
-- Password is Argon2id hashed.
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL COMMENT 'Argon2id hash from password_hash()',
    email_encrypted TEXT NULL COMMENT 'AES-256-GCM ciphertext (base64) of email',
    ic_encrypted TEXT NULL COMMENT 'AES-256-GCM ciphertext (base64) of IC/ID number',
    full_name VARCHAR(128) NULL,
    role ENUM('admin','employee') NOT NULL DEFAULT 'employee',
    status ENUM('active','locked','disabled') NOT NULL DEFAULT 'active',
    failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    last_failed_at DATETIME NULL,
    locked_until DATETIME NULL,
    last_login_at DATETIME NULL,
    last_login_ip VARCHAR(45) NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- AUTH LOGS TABLE
-- Every login attempt (success and failure). BLAKE3 integrity hash chained.
-- ============================================================
CREATE TABLE IF NOT EXISTS auth_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL COMMENT 'NULL if username did not exist',
    username_attempt VARCHAR(64) NOT NULL,
    event_type ENUM(
        'login_success',
        'login_failed',
        'login_locked',
        'logout',
        'password_reset',
        'account_blocked',
        'account_unblocked',
        'admin_action',
        'session_expired'
    ) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500) NULL,
    device_info VARCHAR(255) NULL,
    session_id VARCHAR(128) NULL,
    threat_flag ENUM('none','brute_force','off_hours','geo_anomaly','insider','rapid_fire') NOT NULL DEFAULT 'none',
    notes TEXT NULL,
    integrity_hash CHAR(64) NOT NULL COMMENT 'BLAKE3 hash of (prev_hash || canonical_row)',
    prev_hash CHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_event (event_type),
    INDEX idx_threat (threat_flag),
    INDEX idx_created (created_at),
    INDEX idx_ip (ip_address),
    CONSTRAINT fk_authlog_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- ALERTS TABLE
-- Threshold-based alerts triggered by detection rules.
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    severity ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    rule_name VARCHAR(64) NOT NULL,
    target_user_id INT UNSIGNED NULL,
    target_username VARCHAR(64) NULL,
    source_ip VARCHAR(45) NULL,
    description TEXT NOT NULL,
    status ENUM('open','acknowledged','resolved') NOT NULL DEFAULT 'open',
    acknowledged_by INT UNSIGNED NULL,
    acknowledged_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_severity (severity),
    INDEX idx_created (created_at),
    CONSTRAINT fk_alert_user FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_alert_admin FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- ADMIN ACTIONS TABLE
-- Audit trail for admin operations (block, unblock, reset, etc.)
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_actions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    admin_id INT UNSIGNED NOT NULL,
    action ENUM('block_user','unblock_user','reset_password','update_policy','acknowledge_alert','resolve_alert') NOT NULL,
    target_user_id INT UNSIGNED NULL,
    detail TEXT NULL,
    ip_address VARCHAR(45) NOT NULL,
    integrity_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_admin (admin_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at),
    CONSTRAINT fk_adm_admin FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_adm_target FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- SECURITY POLICY TABLE (single-row config)
-- Editable thresholds for detection rules.
-- ============================================================
CREATE TABLE IF NOT EXISTS security_policy (
    id TINYINT UNSIGNED PRIMARY KEY DEFAULT 1,
    max_failed_attempts INT UNSIGNED NOT NULL DEFAULT 5,
    lockout_minutes INT UNSIGNED NOT NULL DEFAULT 15,
    brute_force_window_minutes INT UNSIGNED NOT NULL DEFAULT 10,
    brute_force_threshold INT UNSIGNED NOT NULL DEFAULT 10,
    rapid_fire_seconds INT UNSIGNED NOT NULL DEFAULT 5,
    rapid_fire_threshold INT UNSIGNED NOT NULL DEFAULT 4,
    working_hours_start TINYINT UNSIGNED NOT NULL DEFAULT 8,
    working_hours_end TINYINT UNSIGNED NOT NULL DEFAULT 18,
    session_timeout_minutes INT UNSIGNED NOT NULL DEFAULT 30,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed single policy row
INSERT INTO security_policy (id) VALUES (1)
ON DUPLICATE KEY UPDATE id=id;

-- ============================================================
-- SESSIONS TABLE (server-side session tracking, complements PHP session)
-- ============================================================
CREATE TABLE IF NOT EXISTS active_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at),
    CONSTRAINT fk_sess_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
