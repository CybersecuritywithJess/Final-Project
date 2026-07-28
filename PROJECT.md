# Financial Audit Tracking System

**A demo bank ("Union Bank of Africa") whose every action — every login, every
shilling moved, every administrative click — is automatically recorded,
risk-scored, and surfaced to auditors.**

---

## 1. Abstract

Most audit systems are built the wrong way around: an application is written
first, and logging is bolted on afterwards, collected by hand and trusted on
faith. This project inverts that. The audit trail comes **first**, and the bank
is built on top of it. The result is a system in which **the bank cannot perform
a single action without leaving an audit record behind** — because the only path
that writes to the audit store is the audit engine itself.

The system models a small retail bank (customers with checking and savings
accounts who deposit, withdraw, transfer and pay bills) and pairs it with a full
auditor back-office: a real-time dashboard, a searchable audit log, an automated
fraud-detection engine, a case-based investigation workflow, exportable reports,
and an AI-powered audit assistant that answers questions about the data in plain
English.

---

## 2. Problem Statement

In real financial institutions, the integrity of the audit trail is a security
control in its own right. If actions can occur without being logged — or if logs
can be edited after the fact — then accountability collapses and fraud becomes
invisible. Auditors need a **complete, contextual, tamper-resistant** record of
every event, the ability to **search and filter** it efficiently, and
**automated help** flagging the events that matter. This project demonstrates a
system that provides exactly that.

---

## 3. Specific Objectives

1. To design a system that **centralizes all transaction audit logs** into a
   single, standardized repository to ensure a complete and reliable audit trail.
2. To design a system that **captures detailed transaction context** by recording
   comprehensive metadata such as user identity, role, transaction details, and
   network information.
3. To design a system that implements **role-based access control (RBAC)** to
   restrict access based on user roles while ensuring secure and isolated
   handling of bank-specific data.
4. To design a system that provides **advanced filtering and search**
   functionality to enable efficient retrieval of transactions based on
   parameters such as status, user, date range, amount, and risk level.
5. To design a system that includes a **real-time activity monitoring dashboard**
   to display user activities, transaction metrics, and flagged risks for
   improved decision-making.
6. To design a system that incorporates **automated risk detection and alerting**
   mechanisms to identify and flag suspicious transactions based on predefined
   criteria.
7. To design a system that **generates and exports standardized audit reports**,
   enabling auditors to produce filtered, evidence-ready records of logged
   activity for compliance, analysis, and decision-making.
8. To design a system that incorporates an **AI-powered audit assistant**,
   enabling auditors to query and analyze audit data using natural language while
   enforcing read-only, access-controlled, and fully logged interactions.

---

## 4. System Architecture

The design enforces a single, unavoidable choke point. Bank code never touches
the audit store directly — it calls the Audit Engine, which categorizes, scores,
persists, and runs fraud detection on every event.

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

## 5. User Roles (RBAC)

Access is strictly separated by role. Every protected endpoint checks the
caller's role, and any refused attempt is itself logged as a CRITICAL event.

| Role          | Can do                                                              |
|---------------|--------------------------------------------------------------------|
| **Customer**  | The Demo Bank only — checking + savings, deposit, withdraw, transfer, pay bills. Never sees the audit system. |
| **Auditor**   | The dashboard, the audit log, the fraud-alert queue, investigations, reports, and the AI assistant. Cannot move any money. |
| **Administrator** | Everything an auditor can do, plus user management and live tuning of the fraud thresholds. |

Separation of duties is not a feature added on top; it is the shape of the
system. An auditor investigates but cannot transact; a customer transacts but
cannot investigate.

---

## 6. Core Features

- **Centralized audit log** — one standardized repository (`audit_events`) that
  every action funnels into.
- **Contextual capture** — who, what, when, how much, from which IP, browser, OS,
  device and country, plus event-specific metadata.
- **Real-time dashboard** — KPIs, risk summary, login/transaction trends,
  category breakdown, an activity heatmap, and a live event feed.
- **Advanced audit search** — filter by text, risk level, category, event type,
  user, country, IP, amount range, and date range; paginated results.
- **Colour-coded audit rows** — bank (customer) activity renders green; audit-
  system and staff activity renders white, so the two sources are distinguishable
  at a glance.
- **Automated fraud detection** — eight rules with admin-tunable thresholds.
- **Investigation workflow** — fraud alerts move through a defined case lifecycle
  with findings and recommendations.
- **Report generation & export** — download the filtered audit log as CSV for
  compliance and analysis.
- **AI Audit Assistant** — ask questions in plain English (page + floating
  widget), read-only and fully logged.
- **Authentication** — username/password (bcrypt) plus optional "Continue with
  Google".

---

## 7. The Audit Engine

Bank code calls `AuditEngine::record()`, and the engine decides what the event
*means*:

1. **Categorise** it into one of seven compliance categories: Authentication,
   Financial Transaction, User Management, Security, Data Integrity, Access
   Control, Administration.
2. **Score** it 0–100 and assign a level: LOW / MEDIUM / HIGH / CRITICAL.
3. **Persist** it with full context — actor, subject, amount, IP, browser, OS,
   device, country, session, and any event-specific metadata.
4. **Hand it to the fraud rules**, which may raise an alert.

That single choke point is what makes the trail trustworthy: there is no second
way to write history.

---

## 8. Risk Scoring

Risk is **contextual**. A base risk is escalated by the details of the event —
one failed login is a typo; five is an attack.

| Level     | Score |
|-----------|-------|
| LOW       | 10    |
| MEDIUM    | 40    |
| HIGH      | 70    |
| CRITICAL  | 95    |

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

Thresholds live in the database, so an administrator can retune them live with no
code change and no restart.

---

## 9. Fraud Detection Rules

Eight rules read their thresholds from the database at detection time:

| Rule                   | Fires when                                              |
|------------------------|---------------------------------------------------------|
| `brute_force`          | 5+ failed logins in 10 minutes → account auto-locks     |
| `large_withdrawal`     | A withdrawal at or above the configured threshold       |
| `large_transfer`       | A transfer at or above the configured threshold         |
| `rapid_transfers`      | 3+ transfers inside one minute (structuring)            |
| `account_drain`        | One withdrawal removing 90%+ of the balance             |
| `new_device`           | First login from an unrecognised browser/OS/device      |
| `new_country`          | Login from a country the account has never used         |
| `daily_limit_exceeded` | Transfers today exceed the configured daily limit       |

Alerts are **deduplicated** — one incident produces one alert, however many
events it generates — so the queue never drowns in repeats.

---

## 10. Investigation Workflow

Fraud alerts move through the states a real security team uses:

```
new → under_investigation → confirmed_fraud
                          → false_positive
                          → resolved → closed
```

Auditors attach **findings** and **recommendations** to a case. Because auditors
are accountable too, every status change and note they write is *itself* an audit
event.

---

## 11. AI Audit Assistant

Auditors and admins can ask questions about the audit data in plain English —
"show all high-risk withdrawals this week", "why was this customer flagged",
"how many failed logins today" — from a dedicated page and a floating chat widget.

- **Built-in rule engine** (default, offline, no key): maps questions to safe,
  pre-built queries.
- **Claude mode** (optional, with an API key): understands free-form phrasing and
  writes its own **read-only** SQL, which is sandboxed and validated
  (SELECT-only, allow-listed tables, run-and-rollback) before execution.

The assistant is **read-only** and **auditor/admin only**, and every question is
itself written to the audit log.

---

## 12. What an Audit Record Captures

Each row in the audit log records, where applicable:

| Field                | Source                                             |
|----------------------|----------------------------------------------------|
| Audit reference      | `audit_ref` — a unique, human-readable id          |
| Source               | `bank` (customer activity) or `system` (staff/engine) |
| User (subject)       | user id, username, full name, email                |
| Role                 | the actor's role                                   |
| Action performed     | event type (e.g. `withdrawal`, `login_failed`)     |
| Description          | a human-readable summary                           |
| Category             | one of the seven compliance categories             |
| Date & time          | `created_at`                                        |
| Transaction amount   | where the event is financial                        |
| Transaction status   | via the linked transaction                          |
| Risk level & score   | `risk_level`, `risk_score`                           |
| IP address           | `ip_address`                                        |
| Device information    | browser, OS, device type                            |
| Location             | country, city                                       |
| Metadata             | event-specific detail, e.g. old/new values          |

---

## 13. Data Model

Eight tables, with foreign keys and indexes:

| Table          | Holds                                                          |
|----------------|---------------------------------------------------------------|
| `users`        | Accounts, roles, status, failed-login counters, auth provider |
| `accounts`     | Checking and savings accounts and balances                    |
| `transactions` | Deposits, withdrawals, transfers, payments and their status   |
| `audit_events` | The central, standardized audit log                           |
| `alerts`       | Fraud alerts and their investigation status                   |
| `alert_notes`  | Findings and recommendations attached to a case               |
| `devices`      | Known devices per user (for new-device detection)             |
| `risk_rules`   | Admin-tunable fraud thresholds                                 |

---

## 14. Technology Stack

- **Frontend** — HTML5, Tailwind CSS, vanilla JavaScript, Chart.js
- **Backend** — PHP 8.2, PDO, sessions, bcrypt
- **Database** — MySQL / MariaDB
- **Runs on** — XAMPP (no Node, no build step, no external services required)
- **Optional** — Google Identity Services (social sign-in), Anthropic Claude
  (natural-language assistant)

---

## 15. Security

| Concern              | How it is handled                                                             |
|----------------------|-------------------------------------------------------------------------------|
| Password storage     | `password_hash()` — bcrypt, cost 12. Never stored in plain text                |
| SQL injection        | Every query is a PDO prepared statement. No string-concatenated SQL            |
| XSS                  | All user-supplied text is escaped before it reaches the DOM                    |
| Session hijacking    | `HttpOnly` cookies, session id regenerated on login, `SameSite=Lax`            |
| Brute force          | Rate limiting, automatic lockout, and a CRITICAL alert                         |
| Privilege escalation | Role checks on every protected endpoint; refusals logged as CRITICAL           |
| Insider threat       | Admin and auditor actions are audited exactly like customer actions            |
| AI safety            | Assistant SQL is SELECT-only, allow-listed, and run-and-rollback validated     |

---

## 16. Project Structure

```
config/
  config.php            Database credentials + optional Google / AI keys

database/
  schema.sql            Tables, foreign keys, indexes
  seed.php              Reset tool — wipes all data back to empty

src/
  Database.php          PDO wrapper — every query is prepared
  Auth.php              Sessions, bcrypt, role-based access control
  Context.php           Device/location fingerprint of a request
  RiskEngine.php        The event catalog: category + risk scoring
  AuditEngine.php       Records events, runs detection, dedupes alerts
  FraudEngine.php       The eight detection rules
  Bank.php              Accounts, transactions, balances
  GoogleAuth.php        "Continue with Google" verification
  AuditAssistant.php    Built-in natural-language rule engine
  ClaudeAssistant.php   Optional Claude-powered querying
  SqlGuard.php          Read-only sandbox for model-generated SQL
  Response.php          JSON and CSV responses

public/
  index.html            Landing page
  login.html            Sign in (+ location simulator)
  register.html         Open an account
  bank.html             Customer: balances, deposit, withdraw, transfer, bills
  dashboard.html        Auditor: KPIs, charts, live feed
  audits.html           Auditor: search/filter the log, export CSV
  alerts.html           Auditor: the fraud-alert queue
  alert.html            Auditor: one case — status, findings, recommendations
  timeline.html         Auditor: one customer's full history
  admin.html            Admin: users, risk thresholds, system health
  assistant.html        Auditor/Admin: the AI assistant

  api/
    auth.php             register, login, logout, me, change-password, google
    bank.php             accounts, transactions, deposit, withdraw, transfer, pay
    audit.php            dashboard, events, timeline, alerts, notes, export, meta
    admin.php            users, rules, health, analytics
    assistant.php        ask (natural-language querying)

  assets/js/
    api.js               The only place the frontend talks to the server
    ui.js                Shell, formatting, risk/status badges
```

---

## 17. Getting Started

You need **XAMPP** (PHP 8+ and MySQL/MariaDB). Nothing else.

1. **Start MySQL** from the XAMPP Control Panel.
2. **Create the database and load the schema:**
   ```bash
   C:\xampp\mysql\bin\mysql.exe -u root < database/schema.sql
   ```
3. **Start the app:**
   ```bash
   C:\xampp\php\php.exe -S localhost:8000 -t public
   ```
4. Open **http://localhost:8000** and **register the first account**. The system
   ships completely empty — the first person to sign up bootstraps it. Choose
   **Administrator** on the role picker for the admin panel, **Auditor** for the
   audit tools, or **Demo Bank user** to start banking.

> `database/seed.php` is a reset tool — running it wipes every user and all data
> back to empty. You only need it to start over.

### Optional integrations

- **AI Assistant (Claude mode):** start the server with `ANTHROPIC_API_KEY` set,
  or paste the key into `config/config.php`. Without a key, the built-in engine
  is used.
- **Continue with Google:** create an OAuth 2.0 Client ID (Web application) with
  `http://localhost:8000` as an authorised JavaScript origin, then set
  `GOOGLE_CLIENT_ID` (env or `config/config.php`). The button appears once a
  Client ID is present.
