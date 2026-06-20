-- ============================================================
-- Migration 02 — Roles, Departments & Self-Registration Workflow
-- ============================================================
-- Upgrades a database created from the original schema.sql to support:
--   * Two extra role tiers: auditor (read-only console) and manager
--   * A 'pending' account state for self-registration approval
--   * Department assignment + the department requested at signup
--   * A deterministic email hash for duplicate-email checks
--   * Approval audit columns (who approved, when)
--   * The log/admin-action event types used by the registration,
--     approval and change-password flows
--
-- Run once on an existing database. Fresh installs created by setup.php
-- already include these changes (setup.php applies migrations after the
-- base schema), so this file does not need to be run again afterwards.
-- ============================================================

-- ---------- users: roles & status ----------
ALTER TABLE users
    MODIFY role ENUM('admin','auditor','manager','employee') NOT NULL DEFAULT 'employee';

ALTER TABLE users
    MODIFY status ENUM('active','locked','disabled','pending') NOT NULL DEFAULT 'active';

-- ---------- users: department & approval columns ----------
ALTER TABLE users
    ADD COLUMN email_hash CHAR(64) NULL AFTER email_encrypted,
    ADD COLUMN department VARCHAR(32) NULL AFTER role,
    ADD COLUMN requested_department VARCHAR(32) NULL AFTER department,
    ADD COLUMN approved_by INT UNSIGNED NULL AFTER requested_department,
    ADD COLUMN approved_at DATETIME NULL AFTER approved_by;

-- Deterministic HMAC-SHA256 (hex) of the normalized email. Lets the app
-- detect duplicate emails without decrypting email_encrypted. NULL is
-- allowed for seeded accounts; MySQL permits multiple NULLs in a UNIQUE key.
ALTER TABLE users
    ADD UNIQUE KEY uq_users_email_hash (email_hash);

-- approved_by points at the admin who approved the account.
ALTER TABLE users
    ADD CONSTRAINT fk_users_approved_by FOREIGN KEY (approved_by)
        REFERENCES users(id) ON DELETE SET NULL;

-- ---------- auth_logs: new event types ----------
ALTER TABLE auth_logs
    MODIFY event_type ENUM(
        'login_success',
        'login_failed',
        'login_locked',
        'logout',
        'password_reset',
        'password_changed',
        'password_change_failed',
        'register_pending',
        'register_failed',
        'account_approved',
        'account_rejected',
        'account_blocked',
        'account_unblocked',
        'admin_action',
        'session_expired'
    ) NOT NULL;

-- ---------- admin_actions: new action types ----------
ALTER TABLE admin_actions
    MODIFY action ENUM(
        'block_user',
        'unblock_user',
        'reset_password',
        'approve_user',
        'reject_user',
        'assign_role',
        'update_policy',
        'acknowledge_alert',
        'resolve_alert'
    ) NOT NULL;
