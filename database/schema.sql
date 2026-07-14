-- Financial Audit Tracking System — MySQL / MariaDB schema
--
-- Two halves:
--   The Demo Bank .... users, accounts, transactions
--   The Audit System . audit_events, alerts, alert_notes, devices, risk_rules
--
-- Load with:  mysql -u root < database/schema.sql

DROP DATABASE IF EXISTS audit_tracking;
CREATE DATABASE audit_tracking CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE audit_tracking;

-- ---------------------------------------------------------------- DEMO BANK

CREATE TABLE users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    full_name     VARCHAR(120) NOT NULL,
    email         VARCHAR(150) NOT NULL UNIQUE,
    phone         VARCHAR(30),

    -- NULL for people who signed in with Google: they never set a password
    -- here, so there is nothing to hash and nothing for us to leak.
    password_hash VARCHAR(255) NULL,
    google_id     VARCHAR(64)  NULL UNIQUE,
    avatar_url    VARCHAR(255) NULL,
    auth_provider ENUM('password', 'google') NOT NULL DEFAULT 'password',

    role          ENUM('customer', 'auditor', 'admin') NOT NULL DEFAULT 'customer',
    status        ENUM('active', 'locked', 'closed')   NOT NULL DEFAULT 'active',
    failed_logins INT          NOT NULL DEFAULT 0,
    locked_at     DATETIME     NULL,
    home_country  VARCHAR(60)  NOT NULL DEFAULT 'Kenya',
    mfa_enabled   TINYINT(1)   NOT NULL DEFAULT 0,
    last_login_at DATETIME     NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_role   (role),
    INDEX idx_users_status (status)
) ENGINE=InnoDB;

CREATE TABLE accounts (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    account_number VARCHAR(20) NOT NULL UNIQUE,
    type           ENUM('checking', 'savings') NOT NULL,
    balance        DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
    currency       VARCHAR(3)     NOT NULL DEFAULT 'KES',
    created_at     DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_accounts_user (user_id)
) ENGINE=InnoDB;

CREATE TABLE transactions (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    reference       VARCHAR(20) NOT NULL UNIQUE,          -- TXN-000123
    user_id         INT NOT NULL,
    type            ENUM('deposit', 'withdrawal', 'transfer',
                         'savings_deposit', 'bill_payment', 'airtime') NOT NULL,
    amount          DECIMAL(15, 2) NOT NULL,
    currency        VARCHAR(3)     NOT NULL DEFAULT 'KES',
    from_account_id INT NULL,
    to_account_id   INT NULL,
    counterparty    VARCHAR(120)   NULL,                  -- receiver / biller
    status          ENUM('completed', 'failed', 'pending', 'flagged')
                    NOT NULL DEFAULT 'completed',
    description     VARCHAR(255)   NULL,
    ip_address      VARCHAR(45)    NULL,
    created_at      DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)         REFERENCES users(id)    ON DELETE CASCADE,
    FOREIGN KEY (from_account_id) REFERENCES accounts(id) ON DELETE SET NULL,
    FOREIGN KEY (to_account_id)   REFERENCES accounts(id) ON DELETE SET NULL,
    INDEX idx_txn_user    (user_id),
    INDEX idx_txn_created (created_at),
    INDEX idx_txn_status  (status)
) ENGINE=InnoDB;

-- ------------------------------------------------------------- AUDIT SYSTEM

-- Every meaningful action in the bank writes exactly one row here.
CREATE TABLE audit_events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    audit_ref       VARCHAR(20) NOT NULL UNIQUE,          -- AUD-000123
    event_type      VARCHAR(50) NOT NULL,                 -- login_failed, withdrawal, ...
    category        ENUM('Authentication', 'Financial Transaction', 'User Management',
                         'Security', 'Data Integrity', 'Access Control', 'Administration')
                    NOT NULL,
    description     VARCHAR(500) NOT NULL,

    -- who the event is ABOUT vs who PERFORMED it (they differ for admin actions)
    subject_user_id INT NULL,
    actor_user_id   INT NULL,
    actor_role      VARCHAR(20) NULL,

    risk_level      ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'LOW',
    risk_score      TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- 0-100

    transaction_id  INT NULL,
    amount          DECIMAL(15, 2) NULL,

    -- device / location context
    ip_address      VARCHAR(45) NULL,
    browser         VARCHAR(60) NULL,
    os              VARCHAR(60) NULL,
    device_type     VARCHAR(30) NULL,
    country         VARCHAR(60) NULL,
    city            VARCHAR(60) NULL,
    session_id      VARCHAR(64) NULL,

    metadata        JSON NULL,                             -- extra detail per event
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (subject_user_id) REFERENCES users(id)        ON DELETE SET NULL,
    FOREIGN KEY (actor_user_id)   REFERENCES users(id)        ON DELETE SET NULL,
    FOREIGN KEY (transaction_id)  REFERENCES transactions(id) ON DELETE SET NULL,

    INDEX idx_audit_created  (created_at),
    INDEX idx_audit_subject  (subject_user_id),
    INDEX idx_audit_type     (event_type),
    INDEX idx_audit_risk     (risk_level),
    INDEX idx_audit_category (category),
    INDEX idx_audit_ip       (ip_address)
) ENGINE=InnoDB;

-- Fraud alerts raised automatically by the detection rules.
CREATE TABLE alerts (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    alert_ref      VARCHAR(20) NOT NULL UNIQUE,           -- ALR-000123
    audit_event_id INT NULL,
    user_id        INT NULL,
    rule_key       VARCHAR(50)  NOT NULL,                 -- brute_force, large_withdrawal, ...
    title          VARCHAR(150) NOT NULL,
    description    VARCHAR(500) NOT NULL,
    risk_level     ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status         ENUM('new', 'under_investigation', 'confirmed_fraud',
                        'false_positive', 'resolved', 'closed')
                   NOT NULL DEFAULT 'new',
    assigned_to    INT NULL,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (audit_event_id) REFERENCES audit_events(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id)        REFERENCES users(id)        ON DELETE SET NULL,
    FOREIGN KEY (assigned_to)    REFERENCES users(id)        ON DELETE SET NULL,

    INDEX idx_alerts_status (status),
    INDEX idx_alerts_risk   (risk_level),
    INDEX idx_alerts_user   (user_id)
) ENGINE=InnoDB;

-- Auditor investigation notes attached to an alert.
CREATE TABLE alert_notes (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    alert_id       INT NOT NULL,
    auditor_id     INT NULL,
    finding        TEXT NOT NULL,
    recommendation TEXT NULL,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id)   REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (auditor_id) REFERENCES users(id)  ON DELETE SET NULL,
    INDEX idx_notes_alert (alert_id)
) ENGINE=InnoDB;

-- Devices seen per user — powers the "login from a new device" rule.
CREATE TABLE devices (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT NOT NULL,
    fingerprint  VARCHAR(32) NOT NULL,                    -- hash(browser+os+device)
    browser      VARCHAR(60) NULL,
    os           VARCHAR(60) NULL,
    device_type  VARCHAR(30) NULL,
    last_ip      VARCHAR(45) NULL,
    last_country VARCHAR(60) NULL,
    first_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_user_device (user_id, fingerprint)
) ENGINE=InnoDB;

-- Admin-configurable thresholds. Every fraud rule reads its numbers from here
-- instead of hard-coding them, so an admin can retune detection at runtime.
CREATE TABLE risk_rules (
    rule_key    VARCHAR(50) PRIMARY KEY,
    label       VARCHAR(120)  NOT NULL,
    value       DECIMAL(15, 2) NOT NULL,
    unit        VARCHAR(20)   NULL,
    description VARCHAR(255)  NULL,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by  INT NULL,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

INSERT INTO risk_rules (rule_key, label, value, unit, description) VALUES
('max_failed_logins',             'Failed logins before account lock', 5,       'attempts',
 'Consecutive failed logins that lock the account and raise a CRITICAL alert.'),
('brute_force_window_minutes',    'Brute-force detection window',      10,      'minutes',
 'Window in which repeated failed logins count as a brute-force attempt.'),
('large_withdrawal_threshold',    'Large withdrawal threshold',        500000,  'KES',
 'Withdrawals at or above this amount are flagged HIGH risk.'),
('large_transfer_threshold',      'Large transfer threshold',          300000,  'KES',
 'Transfers at or above this amount are flagged HIGH risk.'),
('rapid_transfer_count',          'Rapid transfer count',              3,       'transfers',
 'Transfers within the rapid window that trigger a structuring alert.'),
('rapid_transfer_window_minutes', 'Rapid transfer window',             1,       'minutes',
 'Window used to detect several transfers fired off in quick succession.'),
('account_drain_percent',         'Account drain threshold',           90,      '%',
 'A single withdrawal taking at least this share of the balance is suspicious.'),
('daily_transfer_limit',          'Daily transfer limit',              1000000, 'KES',
 'Total transfers per customer per day before an alert is raised.'),
('session_timeout_minutes',       'Session timeout',                   30,      'minutes',
 'How long a login session stays valid before it expires.');
