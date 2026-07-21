<?php

/**
 * Reset the system to completely empty — no users at all.
 *
 * There are deliberately no pre-made accounts: no demo customers, no bootstrap
 * admin or auditor, no invented history. Everything — including the very first
 * administrator — is created by real people signing up. The audit log and the
 * alert queue start empty and fill only with what genuinely happens.
 *
 *   php database/seed.php
 *
 * After running this, open the sign-up page and register the first account.
 * Choose "Administrator" (or "Auditor") on the role picker to create a staff
 * login; choose "Demo Bank user" for a customer.
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/Database.php';

$pdo = Database::connect();

echo "Clearing all data (users, accounts, transactions, audit events, alerts)...\n";
$pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
foreach (['alert_notes', 'alerts', 'audit_events', 'transactions', 'devices', 'accounts', 'users'] as $table) {
    $pdo->exec("TRUNCATE TABLE $table");
}
$pdo->exec('SET FOREIGN_KEY_CHECKS = 1');

echo "\n";
echo "Done. The system is completely empty — no users, no demo data.\n\n";
echo "  Next step: open http://localhost:8000/register.html and create the\n";
echo "  first account. Pick \"Administrator\" on the role picker for an admin\n";
echo "  login, \"Auditor\" for an auditor, or \"Demo Bank user\" for a customer.\n";
