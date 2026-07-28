<?php

/**
 * Adds tamper-evidence to the audit log on an EXISTING database.
 *
 * A fresh install already has the prev_hash/row_hash columns from schema.sql and
 * an empty audit_events table, so this script has nothing to do for it. Run this
 * only if your audit_tracking database predates the hash chain:
 *
 *   C:\xampp\php\php.exe database\migrations\002_audit_integrity.php
 *
 * It is safe to run more than once — adding the columns is skipped if they
 * already exist, and the backfill recomputes every row's hash from scratch, so
 * re-running just re-seals the chain rather than corrupting it.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../src/Database.php';
require_once __DIR__ . '/../../src/AuditEngine.php';

$pdo = Database::connect();

// 1. Add the columns if this database was created before they existed.
$existing = array_column(
    Database::all("SHOW COLUMNS FROM audit_events LIKE 'row_hash'"),
    'Field'
);

if (!$existing) {
    echo "Adding prev_hash / row_hash columns to audit_events...\n";
    $pdo->exec('ALTER TABLE audit_events
                    ADD COLUMN prev_hash CHAR(64) NULL AFTER created_at,
                    ADD COLUMN row_hash  CHAR(64) NULL AFTER prev_hash');
} else {
    echo "Columns already present — skipping ALTER TABLE.\n";
}

// 2. Backfill: seal every existing row into a hash chain, oldest first, using the
//    exact same hashing rules AuditEngine uses for new events and for verification.
$total = (int) Database::value('SELECT COUNT(*) FROM audit_events');
echo "Sealing $total existing audit events into a hash chain...\n";

$prevHash = AuditEngine::GENESIS_HASH;
$stmt = $pdo->query('SELECT * FROM audit_events ORDER BY id ASC');
$update = $pdo->prepare('UPDATE audit_events SET prev_hash = ?, row_hash = ? WHERE id = ?');

$done = 0;
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $rowHash = AuditEngine::hashRow($row, $prevHash);
    $update->execute([$prevHash, $rowHash, $row['id']]);
    $prevHash = $rowHash;

    $done++;
    if ($done % 500 === 0) {
        echo "  ...$done / $total\n";
    }
}

echo "\nDone. $done events sealed.\n";
echo "Verify it worked: sign in as an admin, open Administration -> System health,\n";
echo "and click \"Verify integrity\" — it should report the chain intact.\n";
