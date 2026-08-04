<?php

/**
 * Adds the security controls — daily transaction limits and brute-force login
 * protection — to an EXISTING database.
 *
 * A fresh install gets all of this from schema.sql already. Run this only if your
 * audit_tracking database was created before the security controls existed:
 *
 *   C:\xampp\php\php.exe database\migrations\003_security_controls.php
 *
 * Safe to run more than once: every step checks first and skips what is already
 * in place. No customer data, balance or audit row is modified.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../src/Database.php';

$pdo = Database::connect();

/** True when $table already has a column called $column. */
function hasColumn(string $table, string $column): bool
{
    return (bool) Database::all("SHOW COLUMNS FROM `$table` LIKE " . Database::connect()->quote($column));
}

/** True when the database already has a table called $table. */
function hasTable(string $table): bool
{
    return (bool) Database::all('SHOW TABLES LIKE ' . Database::connect()->quote($table));
}

/** Add a column only if it is missing. */
function addColumn(PDO $pdo, string $table, string $column, string $definition): void
{
    if (hasColumn($table, $column)) {
        echo "  - $table.$column already present, skipping\n";
        return;
    }
    $pdo->exec("ALTER TABLE `$table` ADD COLUMN $definition");
    echo "  + added $table.$column\n";
}

// ------------------------------------------------------------------- USERS

echo "Updating users (timed lockout + brute-force escalation)...\n";

addColumn($pdo, 'users', 'locked_until', 'locked_until DATETIME NULL AFTER locked_at');
addColumn($pdo, 'users', 'lockout_count', 'lockout_count INT NOT NULL DEFAULT 0 AFTER locked_until');

// Widen the status enum so a permanent security lock can be expressed.
$pdo->exec("ALTER TABLE users MODIFY status
            ENUM('active', 'locked', 'closed', 'brute_force_locked')
            NOT NULL DEFAULT 'active'");
echo "  + users.status now allows 'brute_force_locked'\n";

// ---------------------------------------------------------------- ACCOUNTS

echo "\nUpdating accounts (transaction restriction + daily limit)...\n";

addColumn($pdo, 'accounts', 'account_status',
    "account_status ENUM('active', 'restricted') NOT NULL DEFAULT 'active' AFTER currency");
addColumn($pdo, 'accounts', 'daily_limit',
    'daily_limit DECIMAL(15, 2) NOT NULL DEFAULT 0.00 AFTER account_status');
addColumn($pdo, 'accounts', 'limit_violation_count',
    'limit_violation_count INT NOT NULL DEFAULT 0 AFTER daily_limit');

// Seed each account's stored limit from its live balance so the admin view has a
// sensible number before the customer's next transaction recomputes it.
$percent = (float) (Database::value(
    "SELECT value FROM risk_rules WHERE rule_key = 'daily_limit_percent'"
) ?? 30);
Database::run('UPDATE accounts SET daily_limit = ROUND(balance * ? / 100, 2)', [$percent]);
echo "  + seeded daily_limit at $percent% of each balance\n";

// ------------------------------------------------------------ TRANSACTIONS

echo "\nUpdating transactions (decline reason)...\n";

addColumn($pdo, 'transactions', 'failure_reason',
    'failure_reason VARCHAR(255) NULL AFTER status');

$pdo->exec("ALTER TABLE transactions MODIFY status
            ENUM('completed', 'failed', 'pending', 'flagged', 'declined')
            NOT NULL DEFAULT 'completed'");
echo "  + transactions.status now allows 'declined'\n";

// --------------------------------------------------------- SECURITY FLAGS

echo "\nCreating security_flags...\n";

if (hasTable('security_flags')) {
    echo "  - security_flags already exists, skipping\n";
} else {
    $pdo->exec("
        CREATE TABLE security_flags (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            flag_ref       VARCHAR(20) NOT NULL UNIQUE,
            user_id        INT NULL,
            account_id     INT NULL,
            flag_type      VARCHAR(50)  NOT NULL,
            severity       ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
            description    VARCHAR(500) NOT NULL,
            status         ENUM('open', 'resolved') NOT NULL DEFAULT 'open',
            audit_event_id INT NULL,
            created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at    DATETIME NULL,
            resolved_by    INT NULL,

            FOREIGN KEY (user_id)        REFERENCES users(id)        ON DELETE SET NULL,
            FOREIGN KEY (account_id)     REFERENCES accounts(id)     ON DELETE SET NULL,
            FOREIGN KEY (audit_event_id) REFERENCES audit_events(id) ON DELETE SET NULL,
            FOREIGN KEY (resolved_by)    REFERENCES users(id)        ON DELETE SET NULL,

            INDEX idx_flags_status (status),
            INDEX idx_flags_type   (flag_type),
            INDEX idx_flags_user   (user_id)
        ) ENGINE=InnoDB
    ");
    echo "  + created security_flags\n";
}

// --------------------------------------------------------- LOGIN ATTEMPTS

echo "\nCreating login_attempts...\n";

if (hasTable('login_attempts')) {
    echo "  - login_attempts already exists, skipping\n";
} else {
    $pdo->exec("
        CREATE TABLE login_attempts (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            user_id    INT NULL,
            username   VARCHAR(150) NULL,
            ip_address VARCHAR(45)  NULL,
            user_agent VARCHAR(255) NULL,
            status     ENUM('SUCCESS', 'FAILED') NOT NULL,
            reason     VARCHAR(100) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_attempts_user    (user_id),
            INDEX idx_attempts_created (created_at),
            INDEX idx_attempts_ip      (ip_address)
        ) ENGINE=InnoDB
    ");
    echo "  + created login_attempts\n";
}

// ------------------------------------------------------------- RISK RULES

echo "\nAdding configurable thresholds...\n";

$rules = [
    ['daily_limit_percent', 'Daily limit (% of balance)', 30, '%',
     'Share of the account balance a customer may transact in one day.'],
    ['limit_violations_before_restriction', 'Limit violations before restriction', 3, 'attempts',
     'Declined over-limit attempts before the account is restricted from transacting.'],
    ['login_lockout_minutes', 'Login lockout duration', 2, 'minutes',
     'How long an account stays locked after too many failed logins.'],
    ['lockout_cycles_before_permanent', 'Lockout cycles before security lock', 3, 'cycles',
     'Repeated lockout cycles that mark a brute-force attack and lock the account permanently.'],
];

foreach ($rules as [$key, $label, $value, $unit, $description]) {
    if (Database::one('SELECT rule_key FROM risk_rules WHERE rule_key = ?', [$key])) {
        echo "  - $key already configured, leaving the admin's value alone\n";
        continue;
    }
    Database::run(
        'INSERT INTO risk_rules (rule_key, label, value, unit, description) VALUES (?, ?, ?, ?, ?)',
        [$key, $label, $value, $unit, $description]
    );
    echo "  + $key = $value $unit\n";
}

echo "\nDone. The security controls are live:\n";
echo "  - customers must deposit before they can transact\n";
echo "  - transactions above the daily limit are declined and flagged\n";
echo "  - repeated failed logins lock an account temporarily, then permanently\n";
echo "  - admins clear both from Administration -> Security\n";
