# Test Simulations for Objective 3

> *"Test the system's ability to detect suspicious activities and verify log integrity through simulations."*

This document gives you ready-to-run, demo-friendly test cases. Each one maps to a specific feature you claimed in the proposal. Capture screenshots of the dashboard during these tests for your viva report.

---

## Test 1 — Brute Force Detection

**Maps to:** Function 2 (Threat Identification), brute_force rule

### Setup

Default policy thresholds:
- `brute_force_window_minutes` = 10
- `brute_force_threshold` = 10 (raises alert)
- 3+ distinct usernames at same IP escalates to **critical**

### Steps

1. Open a private/incognito window.
2. Try logging in with these credentials in quick succession:
   ```
   admin       / wrongpass1
   admin       / wrongpass2
   admin       / wrongpass3
   admin       / wrongpass4
   admin       / wrongpass5
   employee01  / wrongpass1
   employee02  / wrongpass1
   employee03  / wrongpass1
   nobody      / wrongpass1
   anotheruser / wrongpass1
   ```
3. Open `/admin/alerts.php` (in another browser, signed in as admin).

### Expected

- A **brute_force** alert appears within seconds of crossing the 10th attempt.
- Severity is `critical` because attempts targeted ≥3 different usernames.
- The rows in `/admin/logs.php` from that IP show the `brute_force` threat tag.
- The `admin` account becomes `locked` after 5 failed attempts and stays locked for 15 minutes.

### Screenshot opportunities

- Alerts page showing the critical alert
- Logs page filtered by `threat=brute_force`
- Users page showing `admin` with status = Locked

---

## Test 2 — Rapid-Fire Detection

**Maps to:** rapid_fire rule (a stricter, faster variant of brute force)

### Setup

- `rapid_fire_seconds` = 5
- `rapid_fire_threshold` = 4 attempts in 5 seconds

### Steps

Open a terminal and run (replace `yourdomain.com`):

```bash
for i in 1 2 3 4 5; do
  curl -s -X POST https://yourdomain.com/login.php \
    -d "username=admin&password=wrong$i&csrf=stub" \
    -o /dev/null -w "Attempt $i: %{http_code}\n"
done
```

(The CSRF will fail, but the failed attempts still get logged.)

### Expected

A `rapid_fire` alert at warning severity, attributed to your IP.

> *Note:* CSRF blocks the form submission so technically these don't reach `Auth::login()`. To run this test for real, do it through the browser by attempting 4 quick failed logins manually.

---

## Test 3 — Off-Hours Login Detection

**Maps to:** off_hours rule

### Setup

Default working hours are 8:00–18:00. Either:
- Run this test outside those hours (easiest), OR
- Temporarily edit `config/policy.php` and set `'working_hours_start' => 23` and `'working_hours_end' => 24` so any current login counts as off-hours, then reload. (The baseline is code-managed and has no admin-UI form; restore the original values after testing.)

### Steps

1. Sign in as `employee01` / `Employee@123`.
2. Open `/admin/alerts.php` as admin.

### Expected

- `info`-level alert with rule `off_hours`.
- The successful login row in logs has the `off_hours` threat tag.
- This rule **only** applies to users with role = `employee`. Admin logins outside working hours do NOT alert (admins are expected to respond to incidents at any hour).

---

## Test 4 — Account Lockout & Recovery

**Maps to:** Function 5 (Administrative Response)

### Steps

1. Try logging in as `employee01` with the wrong password 5 times.
2. The 5th attempt locks the account.
3. As admin, open `/admin/users.php`. `employee01` shows status **Locked**.
4. Click **Unblock**.
5. Log out, then sign in as `employee01` with the correct password.

### Expected

- Lockout takes effect after 5 failures (set in the code-managed baseline, `config/policy.php`).
- Auto-unlock would happen after 15 minutes; the manual Unblock button overrides that immediately.
- Both events (`account_blocked` from auto-lockout? in this case it was `login_failed` × 5 + `login_locked`; `account_unblocked` when admin unblocks) appear in logs.

---

## Test 5 — Admin Password Reset

**Maps to:** Function 5

### Steps

1. As admin, go to `/admin/users.php`.
2. Click **Reset PW** for `employee01`.
3. Read the temporary password shown in the green flash banner.
4. Sign out, sign in as `employee01` with that temporary password.

### Expected

- The temporary password works once.
- The `password_reset` event is logged in `auth_logs`.
- The action is also recorded in `admin_actions` with its own BLAKE3 integrity hash.

---

## Test 6 — Log Integrity Verification (THE BIG ONE)

**Maps to:** Function 6 (Evidence Integrity), Objective 3 directly.

This is the test that proves your tamper-detection works.

### Steps

1. Generate some log entries by logging in/out a few times.
2. As admin, open `/admin/integrity.php`. Click **Run Full Verification**.
   → Should show ✓ Chain intact.
3. Now simulate tampering. Open phpMyAdmin (or hPanel's database manager). Run:
   ```sql
   UPDATE auth_logs
   SET ip_address = '10.0.0.1'
   WHERE id = 5;
   ```
   (Pick any existing row ID. Pretend an attacker is forging the source IP of a successful login.)
4. Reload `/admin/integrity.php` and click **Run Full Verification** again.

### Expected

- ⚠ **INTEGRITY VIOLATION DETECTED.**
- Row #5 is listed as broken: stored hash ≠ expected hash.
- All rows AFTER #5 are also listed as broken because their `prev_hash` no longer matches the recomputed hash of row #5.
- The first failing row tells you exactly where the tampering occurred.

### Why this works

For each row, the integrity hash is:
```
integrity_hash = BLAKE3-keyed(K, prev_hash || canonical_json(row))
```
where `K` is the secret server key from `BLAKE3_CTX_KEY_HEX`. Without `K`, an attacker cannot regenerate matching hashes even if they can edit the database freely. The chain structure means tampering also cascades — you cannot quietly change one row.

### Screenshot opportunity

Side-by-side: green ✓ before tampering, red ⚠ after.

---

## Test 7 — PII Encryption (AES-256-GCM)

**Maps to:** Function 7 (Access Control), AES requirement

### Steps

1. Sign in to phpMyAdmin and run:
   ```sql
   SELECT username, email_encrypted FROM users WHERE username='employee01';
   ```
2. Note the `email_encrypted` field — it's a base64 string with no readable email.
3. Open `/admin/users.php`. The same row shows the email masked, e.g. `al***@example.com`. The application decrypts at display-time only.
4. As `employee01`, sign in and open `/dashboard.php`. Your own email is shown decrypted to you.

### Expected

- Database stores ciphertext only.
- Even an attacker with full DB read access (e.g., a SQL-injection leak from another app on the server) cannot recover plaintext PII without the AES key, which lives in `config.php` (outside the web root).
- The 12-byte IV and 16-byte GCM tag are prepended to the ciphertext, so any tampering with the stored value fails decryption (authenticated encryption).

---

## Test 8 — Argon2id Password Verification

**Maps to:** Function 7, Argon2id requirement

### Steps

```sql
SELECT username, password_hash FROM users LIMIT 1;
```

### Expected

The hash starts with `$argon2id$v=19$m=65536,t=4,p=1$`. The `m=`, `t=`, `p=` parameters confirm:
- Memory cost: 64 MB
- Time cost: 4 iterations
- Parallelism: 1 thread

These values come from `config.php` and can be tuned. Passwords are also peppered with HMAC-SHA256 before hashing — even if the database leaks, an attacker without the pepper cannot brute-force the hashes offline using standard Argon2id crackers.

---

## Reporting

For your viva, capture:

1. ✓ Login flow as admin and as employee
2. ✓ Brute force alert appearing on the alerts page
3. ✓ Off-hours alert
4. ✓ Lockout + unblock workflow
5. ✓ Integrity check passing on a clean DB
6. ✓ Integrity check FAILING after a SQL UPDATE
7. ✓ phpMyAdmin showing encrypted email_encrypted column
8. ✓ phpMyAdmin showing Argon2id $argon2id$v=19$ password hash
9. ✓ Charts on the admin dashboard reflecting the activity from your tests
10. ✓ Active session count incrementing/decrementing as users sign in and out

Each one demonstrates a different objective from your proposal.
