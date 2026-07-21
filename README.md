# Financial Audit Tracking System

A demo bank whose every action — every login, every shilling moved, every admin
click — is automatically recorded, risk-scored, and surfaced to auditors.

Real banks do not have auditors collecting logs by hand. The application emits
the evidence itself. That principle drives the whole design: **the bank cannot
perform an action without leaving an audit row behind.**

```
                    ┌─────────────────────────┐
                    │       DEMO BANK         │
                    │                         │
                    │  Register    Deposit    │
                    │  Login       Withdraw   │
                    │  Logout      Transfer   │
                    │  Password    Bills      │
                    └───────────┬─────────────┘
                                │
                  every action emits an audit event
                                │
                                ▼
                    ┌─────────────────────────┐
                    │      AUDIT ENGINE       │
                    │                         │
                    │  categorise → score →   │
                    │  persist → detect fraud │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │    AUDITOR DASHBOARD    │
                    │                         │
                    │  KPIs · alerts · search │
                    │  timelines · reports    │
                    └─────────────────────────┘
```

---

## Getting it running

You need **XAMPP** (PHP 8+ and MySQL/MariaDB). Nothing else — no Node, no npm,
no cloud services.

**1. Start MySQL** — open the XAMPP Control Panel and click *Start* next to MySQL.

**2. Create the database and load the schema:**

```bash
C:\xampp\mysql\bin\mysql.exe -u root < database/schema.sql
```

**3. Start the app:**

```bash
C:\xampp\php\php.exe -S localhost:8000 -t public
```

Then open **<http://localhost:8000>** and **create the first account** from the
sign-up page (see *Create the first account* below). The system ships empty —
there are no pre-made users, so the first person to register bootstraps it.

> `database/seed.php` is a reset tool: running it **wipes every user and all
> data** back to empty. You only need it to start over, not on first install.

> Prefer Apache? Copy the project into `C:\xampp\htdocs\`, point Apache's
> document root at the `public/` folder, and start Apache instead of step 4.

### Turn on the AI Audit Assistant's Claude mode (optional)

Auditors and admins get an **AI assistant** page where they ask questions in
plain English — "show all high-risk withdrawals this week", "why was John
flagged", "which customer has the highest risk score". It works out of the box
with a **built-in rule engine** (no key, offline, free) that maps questions to
safe, pre-built queries.

Add an Anthropic API key and it upgrades to **Claude**, which understands any
phrasing and writes its own read-only SQL — every query is sandboxed through
`SqlGuard` (SELECT-only, allow-listed tables, run-and-rollback) before it runs,
so the model can never change a record.

1. Get a key at <https://console.anthropic.com/>.
2. Start the app with it set:

   ```bash
   ANTHROPIC_API_KEY="sk-ant-..." C:\xampp\php\php.exe -S localhost:8000 -t public
   ```

   (Or paste it into `config/config.php` under `ai` → `api_key`.)

The assistant is **read-only** and **auditor/admin only**, and every question is
itself written to the audit log. Unlike the Google client id, this key is a
**secret** — keep it out of the repo.

### Turn on "Continue with Google" (optional)

The Google button is built in but stays hidden until you give it a Client ID —
that ID is tied to your own Google account, so it can't be shipped in the repo.

1. Go to <https://console.cloud.google.com/apis/credentials>.
2. **Create Credentials → OAuth client ID → Web application.**
3. Under **Authorised JavaScript origins**, add `http://localhost:8000`.
4. Copy the Client ID it gives you (it ends in `.apps.googleusercontent.com`).
5. Start the app with it set:

   ```bash
   GOOGLE_CLIENT_ID="your-id.apps.googleusercontent.com" \
     C:\xampp\php\php.exe -S localhost:8000 -t public
   ```

   (Or paste it into `config/config.php` under `google` → `client_id`.)

The button now appears on the login and sign-up pages. Signing in with Google
creates a customer account on first use, links to an existing account if the
email already matches, and — like everything else — is written to the audit log.

If you already had a database before adding this feature, apply the migration
once: `mysql -u root audit_tracking < database/migrations/001_google_auth.sql`.

### Create the first account

The system ships **completely empty** — there are no pre-made accounts of any
kind. Open the sign-up page and register the first user, choosing a role on the
picker:

| Role on sign-up | What it can do                                               |
|-----------------|-------------------------------------------------------------|
| Administrator   | Manage users, retune the fraud thresholds, see system health |
| Auditor         | The dashboard, the alert queue, the audit log, investigations |
| Demo Bank user  | The customer banking app (checking + savings)                |

Create an **Administrator** first if you want the admin panel. Then create a
**Demo Bank user** and start banking — every login, deposit, withdrawal and
transfer is recorded, and the fraud rules raise alerts on their own when a real
pattern trips them (e.g. withdraw more than KES 500,000, or log in from a
different country using the "Simulate location" panel).

---

## Try the security features

The point of the project is that the audit system reacts on its own. Four ways
to prove it to yourself:

**Trip the fraud engine.** Sign in as `faith_n`, deposit 1,000,000, then
withdraw 600,000. The withdrawal comes back flagged, and a **HIGH** alert is
already waiting in the auditor's queue before you get there.

**Get an account locked.** Try to sign in as `aisha_h` with the wrong password
five times. The account locks itself and a **CRITICAL** brute-force alert is
raised. Only an admin can let her back in.

**Fake a login from another country.** On the login page, expand *Simulate
location & device*, set the country to something other than Kenya, and sign in
as a customer. The impossible-travel rule fires.

**Watch an auditor get caught.** Sign in as `faith_n` (a customer) and manually
visit `/dashboard.html`. You are turned away — and the attempt itself is written
to the audit log as a **CRITICAL** `unauthorized_access` event.

---

## How it works

### The Audit Engine

Bank code never touches the `audit_events` table. It calls
`AuditEngine::record()`, and the engine decides what the event *means*:

1. **Categorise** it into one of seven compliance categories (Authentication,
   Financial Transaction, User Management, Security, Data Integrity, Access
   Control, Administration).
2. **Score** it 0–100 and assign LOW / MEDIUM / HIGH / CRITICAL.
3. **Persist** it with the full context — who, what, when, how much, from which
   IP, browser, OS, device and country.
4. **Hand it to the fraud rules**, which may raise an alert.

That single choke point is what makes the trail trustworthy.

### Risk scoring is contextual

A base risk gets *escalated* by the details of the event. One failed login is a
typo; five is an attack:

| Event                          | Risk       |
|--------------------------------|------------|
| Successful login               | LOW        |
| Failed login (1st)             | MEDIUM     |
| Failed login (5th)             | CRITICAL   |
| Withdrawal of 10,000           | LOW        |
| Withdrawal of 600,000          | HIGH       |
| Login from a new country       | CRITICAL   |
| Admin deletes a user           | CRITICAL   |
| Admin changes someone's role   | CRITICAL   |

### Fraud detection

Eight rules, all reading their thresholds from the database so an admin can
retune them live — no code change, no restart:

| Rule                   | Fires when                                              |
|------------------------|---------------------------------------------------------|
| `brute_force`          | 5+ failed logins in 10 minutes → account auto-locks      |
| `large_withdrawal`     | A withdrawal at or above 500,000                         |
| `large_transfer`       | A transfer at or above 300,000                           |
| `rapid_transfers`      | 3+ transfers inside one minute (structuring)             |
| `account_drain`        | One withdrawal removing 90%+ of the balance              |
| `new_device`           | First login from an unrecognised browser/OS/device       |
| `new_country`          | Login from a country the account has never used          |
| `daily_limit_exceeded` | Transfers today exceed 1,000,000                         |

Alerts are **deduplicated**: one incident produces one alert, however many
events it generates. Without that, every retry against a locked account would
raise another CRITICAL and the queue would drown.

### Investigation workflow

Alerts move through the states a real security team uses:

```
new → under_investigation → confirmed_fraud
                          → false_positive
                          → resolved → closed
```

Auditors attach **findings** and **recommendations** to a case. And because
auditors are accountable too, every status change and note they write is *itself*
an audit event.

---

## Security

| Concern              | How it is handled                                                              |
|----------------------|--------------------------------------------------------------------------------|
| Password storage     | `password_hash()` — bcrypt, cost 12. Never stored or recoverable in plain text  |
| SQL injection        | Every query is a PDO prepared statement. No string-concatenated SQL anywhere    |
| XSS                  | All user-supplied text is escaped before it reaches the DOM                     |
| Session hijacking    | `HttpOnly` cookies, session ID regenerated on login, `SameSite=Lax`             |
| Brute force          | Rate limiting, automatic lockout, and a CRITICAL alert                          |
| Privilege escalation | Role checks on every protected endpoint; refusals are logged as CRITICAL        |
| Insider threat       | Admin and auditor actions are audited exactly like customer actions             |

---

## Project layout

```
config/
  config.php            Database credentials (override with env vars)

database/
  schema.sql            8 tables, foreign keys, indexes
  seed.php              Bootstrap: the admin + auditor accounts only, no demo data

src/
  Database.php          PDO wrapper — every query is prepared
  Auth.php              Sessions, bcrypt, role-based access control
  Context.php           Device/location fingerprint of a request
  RiskEngine.php        The event catalog: category + risk scoring
  AuditEngine.php       Records events, runs detection, dedupes alerts
  FraudEngine.php       The eight detection rules
  Bank.php              Accounts, transactions, balances
  Response.php          JSON and CSV responses

public/
  index.html            Routes you to your role's home
  login.html            Sign in (+ location simulator)
  register.html         Open an account
  bank.html             Customer: balances, deposit, withdraw, transfer, bills
  dashboard.html        Auditor: KPIs, risk summary, charts, live feed
  audits.html           Auditor: search and filter every event, export CSV
  alerts.html           Auditor: the fraud alert queue
  alert.html            Auditor: one case — status, findings, recommendations
  timeline.html         Auditor: one customer's full history, devices, risk
  admin.html            Admin: users, risk thresholds, system health

  api/
    auth.php            register, login, logout, me, change-password
    bank.php            accounts, transactions, deposit, withdraw, transfer, pay
    audit.php           dashboard, events, timeline, alerts, notes, export, meta
    admin.php           users, rules, health, analytics

  assets/js/
    api.js              The only place the frontend talks to the server
    ui.js               Shell, formatting, risk/status badges
```

---

## Built with

- **Frontend** — HTML5, Tailwind CSS, vanilla JavaScript, Chart.js
- **Backend** — PHP 8.2, PDO, sessions, bcrypt
- **Database** — MySQL / MariaDB
- **Runs on** — XAMPP
