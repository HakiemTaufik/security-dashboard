# Web-Based Security Log Dashboard for Admin Activity Monitoring

A self-contained PHP web application for centralized authentication monitoring, threat
detection, and tamper-evident security logging. Built for a university final-year project
covering Argon2id password hashing, AES-256-GCM PII encryption, and BLAKE3 cryptographic
log integrity.

> **Educational project.** This is a learning/demo application. It implements many real
> security controls, but it has not been independently audited and is not hardened for
> production use without further review.

![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4)
![MySQL](https://img.shields.io/badge/MySQL-5.7%2B-4479A1)
![License](https://img.shields.io/badge/License-MIT-green)

## What it does

- **Centralized event logging** — every login, logout, lockout, and admin action is recorded
  via parameterized queries, capturing IP, user agent, device fingerprint, and session ID.
- **Cryptographic data protection**
    - Passwords: Argon2id (built-in PHP), with a server-side pepper (HMAC-SHA256)
    - PII (email, IC number): AES-256-GCM authenticated encryption
    - Log entries: BLAKE3-keyed hash chain (pure-PHP implementation, no extensions needed)
- **Visualized authentication patterns** — admin dashboard with Chart.js: 24-hour timeline
  (success vs failed logins), event-type breakdown, top source IPs, threat-flag distribution.
  Auto-refreshes every 30 seconds.
- **Rule-based detection**
    - `brute_force` — many failures from one IP within a window; escalates to critical when
      ≥3 distinct usernames are targeted
    - `rapid_fire` — burst failures within seconds
    - `off_hours` — successful employee logins outside configured working hours
- **Threshold-based alerting** — alerts written to a queue; deduplicated to prevent spam.
- **Administrative response** — block/unblock users, force password reset, acknowledge/resolve
  alerts. Every admin action is itself BLAKE3-chained for forensic non-repudiation.
- **Evidence integrity** — `admin/integrity.php` recomputes the entire log chain on demand;
  any database tampering breaks the chain and is identified to the exact row.

## Stack

- PHP 7.4+ (works on 8.x — no extensions required beyond the OpenSSL/PDO that ship with Hostinger)
- MySQL 5.7+ / MariaDB 10.3+
- Chart.js 4.4 (loaded from CDN — not bundled)
- No frameworks, no Composer, no build step

## Security baseline (code-managed, not editable at runtime)

Security thresholds (lockout count, lockout duration, session idle timeout, detection tuning,
password policy) live in `config/policy.php` as a fixed `SecurityBaseline` class. They are
**intentionally not editable from the admin UI** — a baseline that an operator (or an attacker
with a stolen admin session) could weaken from a web form is not a baseline. `admin/policy.php`
is a **read-only** view that shows each control and the standard it maps to (PCI DSS, NIST
SP 800-63B, CIS). Changing a value is a change-managed action: edit the file, review, redeploy.

## Architecture

```
┌─────────────────┐
│  Browser (admin)│
└────────┬────────┘
         │ HTTPS
┌────────▼─────────────────────────────────────────┐
│  PHP — public_html/ (web root)                    │
│  ├─ login.php → Auth::login()                     │
│  ├─ admin/dashboard.php → Chart.js + JSON API     │
│  ├─ admin/integrity.php → Logger::verifyChain()   │
│  └─ admin/actions.php (CSRF-guarded mutations)    │
└────────┬─────────────────────────────────────────┘
         │
┌────────▼──────────────────────────┐
│  /includes (blocked from web)      │
│  ├─ auth.php       Authentication  │
│  ├─ crypto.php     AES, Argon2id   │
│  ├─ blake3.php     Log integrity   │
│  ├─ logger.php     Hash chain      │
│  ├─ detection.php  Threat rules    │
│  └─ session.php    Session + CSRF  │
└────────┬──────────────────────────┘
         │
    ┌────▼─────┐
    │  MySQL   │  users / auth_logs / alerts /
    │          │  admin_actions
    └──────────┘
```

## Quick start

> Note: the repository ships `config/config.example.php` only. The real `config/config.php`
> holds live credentials and is git-ignored — you create it locally and never commit it.

1. Read `docs/DEPLOY.md` and follow it on your hosting account.
2. Copy the template and fill it in:
   ```bash
   cp config/config.example.php config/config.php
   ```
3. Generate three independent keys and paste them into `config/config.php`:
   ```bash
   php -r "for(\$i=0;\$i<3;\$i++) echo bin2hex(random_bytes(32)).PHP_EOL;"
   ```
   Set `DB_HOST`/`DB_NAME`/`DB_USER`/`DB_PASS`, then `AES_KEY_HEX`, `BLAKE3_CTX_KEY_HEX`, `PEPPER`.
4. Visit `https://yourdomain/setup.php` and click **Run Setup**.
5. **Delete `setup.php`** from the server.
6. Log in as `admin` / `Admin@12345` and rotate the password immediately.

For demo / viva, follow `docs/TEST_SIMULATIONS.md` to walk through every detection rule and
the integrity check.

## File map

The repository root **is** the web root (`public_html/`).

| Path | Purpose |
|------|---------|
| `config/config.example.php` | Template for DB credentials + the three keys. Copy to `config/config.php`. |
| `config/policy.php` | Fixed, code-managed `SecurityBaseline` (thresholds + password policy). |
| `includes/blake3.php` | Pure-PHP BLAKE3 (validated against official test vectors). |
| `includes/crypto.php` | Argon2id, AES-256-GCM, log-hash helpers. |
| `includes/logger.php` | `Logger::log()` / `Logger::verifyChain()`. |
| `includes/detection.php` | Brute force, rapid fire, off-hours rules. |
| `includes/auth.php` | Login, logout, lockout, session bootstrap. |
| `includes/session.php` | Secure session config + CSRF tokens. |
| `login.php` | Login page (CSRF-protected). |
| `dashboard.php` | Employee landing page (own activity + own PII decrypted). |
| `admin/dashboard.php` | The main SOC dashboard. |
| `admin/users.php` | User management with block/unblock/reset. |
| `admin/alerts.php` | Alert triage (acknowledge/resolve). |
| `admin/logs.php` | Filterable audit log viewer. |
| `admin/integrity.php` | BLAKE3 chain verification — proves tamper detection. |
| `admin/policy.php` | **Read-only** view of the security baseline. |
| `admin/actions.php` | POST-only handler for every privileged mutation. |
| `api/chart-data.php` | JSON for Chart.js (admin-only). |
| `cron/integrity_monitor.php` | Scheduled chain check (CLI or token-guarded URL). |
| `sql/schema.sql` | Database schema. |
| `sql/migrations/` | Incremental schema migrations. |
| `docs/DEPLOY.md` | Hosting deployment walkthrough. |
| `docs/TEST_SIMULATIONS.md` | Demo scripts for each objective. |

## Security highlights

- All database queries use PDO prepared statements (the `DB` class does not concatenate parameters).
- Sessions: `HttpOnly`, `SameSite=Strict`, `Secure` (auto-detected from HTTPS), strict mode,
  idle timeout enforced.
- CSRF tokens on every POST endpoint (32-byte random hex, `hash_equals` for verification).
- CSP: `default-src 'self'`; scripts also allow `cdn.jsdelivr.net` (Chart.js); styles allow inline (`'unsafe-inline'`); no third-party fonts or other external origins.
- BLAKE3 keyed mode means even a database admin without the server key cannot rewrite history
  undetectably.
- Email and IC stored only as authenticated ciphertext (the GCM tag means tampering breaks decryption).
- Argon2id password hashes are peppered with HMAC-SHA256 before hashing — a leaked DB alone does
  not enable offline cracking.
- `.htaccess` disables directory listing, blocks `.md`/`.sql`/`config`/`includes`/`sql`/`docs`
  from the web, and sets HSTS + security headers.

## Default credentials (created by `setup.php` — CHANGE BEFORE/AFTER DEPLOY)

These are fixed demo accounts the setup script creates. Rotate them immediately; never leave
them on a publicly reachable instance.

| Username | Password | Role |
|----------|----------|------|
| admin | Admin@12345 | admin |
| employee01 | Employee@123 | employee |
| employee02 | Employee@123 | employee |
| employee03 | Employee@123 | employee |

