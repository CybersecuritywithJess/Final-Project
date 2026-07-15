<?php

/**
 * Bootstrap the system with the two staff accounts you need to get in — an
 * administrator and an auditor — and NOTHING else.
 *
 * There is deliberately no fabricated history here: no demo customers, no
 * invented transactions, no planted fraud. The audit log and the alert queue
 * start empty and fill only with things that genuinely happen once people use
 * the app. What you see in the dashboard is real.
 *
 *   php database/seed.php
 *
 * Customers register themselves from the sign-up page; real banking activity
 * then generates the audit events, and the fraud rules raise alerts on their
 * own when a real pattern trips them.
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/Auth.php';

const PASSWORD = 'Password123!';

$pdo = Database::connect();

echo "Clearing all existing data...\n";
$pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
foreach (['alert_notes', 'alerts', 'audit_events', 'transactions', 'devices', 'accounts', 'users'] as $table) {
    $pdo->exec("TRUNCATE TABLE $table");
}
$pdo->exec('SET FOREIGN_KEY_CHECKS = 1');

$hash = password_hash(PASSWORD, PASSWORD_BCRYPT, ['cost' => 12]);

// The only rows we create: the accounts that let you sign in. They are inserted
// silently — creating them is not itself "activity", so it writes no audit
// events. The log is genuinely empty until the first real login.
$staff = [
    ['admin',   'System Administrator', 'admin@sentinelbank.co.ke',   'admin'],
    ['auditor', 'Lead Auditor',         'auditor@sentinelbank.co.ke', 'auditor'],
];

$insert = $pdo->prepare(
    'INSERT INTO users (username, full_name, email, password_hash, role, auth_provider)
     VALUES (?, ?, ?, ?, ?, \'password\')'
);

foreach ($staff as [$username, $fullName, $email, $role]) {
    $insert->execute([$username, $fullName, $email, $hash, $role]);
    echo "  created $role account: $username\n";
}

echo "\n";
echo "Done. The system is clean — no demo data.\n\n";
echo "  Sign in to bootstrap the system:\n";
echo "    Admin     username: admin      password: " . PASSWORD . "\n";
echo "    Auditor   username: auditor    password: " . PASSWORD . "\n\n";
echo "  Everything else — customers, transactions, audit events, alerts —\n";
echo "  is created by real use from here on.\n";
