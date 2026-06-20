# Hostinger Deployment Guide

## Overview

This Security Dashboard is built for Hostinger shared hosting. PHP and MySQL come pre-installed, so no additional setup is needed beyond uploading the files and running the one-time initializer.

## Prerequisites

You will need:
- A Hostinger account with at least the Premium plan (for MySQL access)
- Access to **hPanel** (Hostinger's control panel)
- An SSL certificate (Hostinger provides free Let's Encrypt SSL — enable it before going live)

## Step 1 — Create the MySQL database

1. In hPanel, go to **Databases → Management**.
2. Click **Create new database**. Note down:
   - Database name (looks like `u123456_secdash`)
   - Database username (looks like `u123456_secadmin`)
   - Database password (you choose this)
3. Keep these values handy for Step 3.

## Step 2 — Upload files

You can either upload via the **File Manager** in hPanel or use FTP/SFTP credentials from hPanel.

The folder structure should be:

```
public_html/                       (Hostinger's web root — upload everything here)
├── .htaccess                      (blocks config/, includes/, sql/, docs/ from the web)
├── index.php
├── login.php
├── logout.php
├── register.php
├── change-password.php
├── dashboard.php
├── setup.php                      (delete after running once)
├── admin/
├── api/
├── assets/
├── config/
│   ├── config.php                 (you create this — see Step 3)
│   └── policy.php
├── includes/
├── cron/
├── sql/
└── docs/
```

> **Important:** This is a single-folder layout — upload the entire project into
> Hostinger's `public_html`. The `config/`, `includes/`, `sql/`, and `docs/` folders are
> blocked from web access by the included `.htaccess` (directory listing is disabled and
> direct requests to those paths return 403), so the DB credentials and crypto keys are not
> reachable from a browser even though they live inside the web root.

## Step 3 — Configure secrets

The repository ships `config/config.example.php` (a template) but not the real
`config/config.php`. Create your copy first:

```bash
cp config/config.example.php config/config.php
```

Then open `config/config.php` and replace the placeholders:

```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'u123456_secdash');     // your real DB name
define('DB_USER', 'u123456_secadmin');    // your real DB user
define('DB_PASS', 'your-real-db-password');
```

Generate fresh cryptographic keys. On any machine with PHP installed, run:

```bash
php -r "echo bin2hex(random_bytes(32));"
```

Run this command **three times**. Use the three outputs for:

```php
define('AES_KEY_HEX',         'paste-first-output-here');
define('BLAKE3_CTX_KEY_HEX',  'paste-second-output-here');
define('PEPPER',              'paste-third-output-here');
```

Treat these like passwords. If they leak, rotate them (note: changing AES_KEY_HEX makes existing encrypted PII unreadable, and changing BLAKE3_CTX_KEY_HEX invalidates the existing log chain — only do these if you are starting fresh).

## Step 4 — Run setup

Visit:

```
https://yourdomain.com/setup.php
```

Click **Run Setup**. The script will:
- Create all database tables from `sql/schema.sql`
- Apply the schema migrations in `sql/migrations/` (integrity-monitoring tables, plus the roles/departments and self-registration columns)
- Create the default admin (`admin` / `Admin@12345`)
- Create three demo employee accounts
- Insert the genesis log entry to anchor the BLAKE3 chain

## Step 5 — Harden

After setup completes:

1. **Delete `public_html/setup.php`** — leaving it accessible is a serious risk.
2. Sign in as `admin` / `Admin@12345`.
3. Use **Users → Reset PW** on `admin` and any test accounts to rotate the default credentials.
4. Edit the root `.htaccess` and uncomment the HTTPS rewrite block.
5. In hPanel, ensure your free Let's Encrypt SSL is active for the domain.

## Step 6 — Verify

Sign in and check each page renders:
- `/admin/dashboard.php` — charts populated, recent activity visible
- `/admin/users.php` — user table shows AES-encrypted email displayed as masked
- `/admin/integrity.php` — click "Run Full Verification", expect ✓ Chain intact
- `/admin/policy.php` — confirm the security baseline (lockout, idle timeout, password policy) renders. This page is **read-only**; the thresholds live in `config/policy.php` and cannot be changed from the UI by design.

## Troubleshooting

**"AES_KEY_HEX must be 64 hex characters"** — your config has the placeholder. Generate real keys per Step 3.

**Chart pages blank / 401 on `/api/chart-data.php`** — you are not signed in as admin. Check session cookie domain in hPanel; SSL must be on.

**"Database unavailable"** — DB credentials wrong, or `localhost` is not the right host for your plan (some Hostinger plans need a specific MySQL hostname; check hPanel → Databases → Connection Info).

**`setup.php` errors with "Access denied"** — DB user doesn't have CREATE TABLE permission. In hPanel, ensure the user is assigned to the database with all privileges.

## Performance notes

- Pure-PHP BLAKE3 is roughly 10–50 KB/sec on shared hosting. For the small canonical-JSON inputs we hash (typically under 500 bytes), this means well under 1ms per log entry — imperceptible.
- AES-256-GCM uses native OpenSSL — full-speed.
- Argon2id uses 64 MB / 4 iterations by default. On constrained shared hosting you can lower `ARGON2_MEMORY_COST` to 32768 (32 MB) without significantly weakening it.

## Cleanup checklist before viva/demo

- [ ] `setup.php` deleted
- [ ] `admin` password rotated from `Admin@12345`
- [ ] HTTPS forced via `.htaccess`
- [ ] `APP_ENV` in config set to `production`
- [ ] DB user has only the privileges it needs
