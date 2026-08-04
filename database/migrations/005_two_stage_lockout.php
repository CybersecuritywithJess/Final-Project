<?php

/**
 * Switches brute-force protection to a two-stage escalation.
 *
 * Before: an account had to be locked out three separate times before the lock
 * became permanent, and any successful login wiped that history — so a patient
 * attacker could fail, wait, fail, wait, indefinitely.
 *
 * After:
 *   Stage 1 — max_failed_logins failures        -> temporary lock (a warning)
 *   Stage 2 — post_lockout_failures failures    -> permanent security lock
 *             (measured after the account has been locked out once)
 *
 * A correct password still clears the failed-attempt counter, but no longer
 * clears the record of having been locked out. That record is what puts the
 * account on the shorter Stage 2 threshold, and only an administrator's
 * "Activate" clears it.
 *
 *   C:\xampp\php\php.exe database\migrations\005_two_stage_lockout.php
 *
 * Safe to run more than once.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../src/Database.php';

echo "Switching brute-force protection to two-stage escalation...\n\n";

// 1. The Stage 2 threshold.
if (Database::one("SELECT rule_key FROM risk_rules WHERE rule_key = 'post_lockout_failures'")) {
    echo "  - post_lockout_failures already configured, leaving your value alone\n";
} else {
    Database::run(
        'INSERT INTO risk_rules (rule_key, label, value, unit, description) VALUES (?, ?, ?, ?, ?)',
        [
            'post_lockout_failures',
            'Failures after a lockout',
            3,
            'attempts',
            'Once an account has been locked out before, this many further failures lock it permanently.',
        ]
    );
    echo "  + post_lockout_failures = 3 attempts\n";
}

// 2. The old cycle-counting rule no longer governs anything. Leaving it on the
//    thresholds page would let an admin tune a number that does nothing.
if (Database::one("SELECT rule_key FROM risk_rules WHERE rule_key = 'lockout_cycles_before_permanent'")) {
    Database::run("DELETE FROM risk_rules WHERE rule_key = 'lockout_cycles_before_permanent'");
    echo "  - removed lockout_cycles_before_permanent (no longer used)\n";
} else {
    echo "  - lockout_cycles_before_permanent already removed\n";
}

echo "\nBrute-force protection is now:\n";
$stage1 = (int) Database::value("SELECT value FROM risk_rules WHERE rule_key = 'max_failed_logins'");
$minutes = (int) Database::value("SELECT value FROM risk_rules WHERE rule_key = 'login_lockout_minutes'");
$stage2 = (int) Database::value("SELECT value FROM risk_rules WHERE rule_key = 'post_lockout_failures'");

echo "  Stage 1: $stage1 failed logins  -> locked for $minutes minute(s) (a warning)\n";
echo "  Stage 2: $stage2 further failures -> permanent security lock, admin must reactivate\n";
echo "\nA correct password clears the attempt counter but not the warning.\n";
