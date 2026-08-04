<?php

/**
 * Stops a legitimate admin action from breaking the audit hash chain.
 *
 * audit_events.subject_user_id / actor_user_id / transaction_id were foreign
 * keys declared ON DELETE SET NULL. Those three columns are part of what the
 * hash chain seals, so deleting a user rewrote history underneath the seal:
 * the ids became NULL, every affected row stopped matching its own hash, and
 * "Verify integrity" reported tampering even though nobody had tampered.
 *
 * An audit row is a statement about something that happened. It should not
 * change when a person is later removed — the identity is already preserved in
 * the event's description and metadata, so the id is kept as a plain number
 * that points at a user who may no longer exist. Every query that joins users
 * to audit_events already uses a LEFT JOIN, so nothing downstream breaks.
 *
 *   C:\xampp\php\php.exe database\migrations\004_audit_immutability.php
 *
 * Safe to run more than once. It re-seals the chain at the end, so run it after
 * any deletion that already broke the seal.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../src/Database.php';
require_once __DIR__ . '/../../src/AuditEngine.php';

$pdo = Database::connect();

// 1. Drop the constraints that let a delete rewrite the log.
$foreignKeys = Database::all("
    SELECT CONSTRAINT_NAME, COLUMN_NAME
      FROM information_schema.KEY_COLUMN_USAGE
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'audit_events'
       AND REFERENCED_TABLE_NAME IS NOT NULL
");

if (!$foreignKeys) {
    echo "No foreign keys left on audit_events — already migrated.\n";
} else {
    foreach ($foreignKeys as $fk) {
        $pdo->exec("ALTER TABLE audit_events DROP FOREIGN KEY `{$fk['CONSTRAINT_NAME']}`");
        echo "  - dropped FK on audit_events.{$fk['COLUMN_NAME']} (was ON DELETE SET NULL)\n";
    }
}

// 2. Re-seal the chain. Any row already blanked by a past delete is sealed as it
//    now stands — the damage cannot be undone, but the log is trustworthy from
//    here on, and it can no longer be broken by an ordinary admin action.
$total = (int) Database::value('SELECT COUNT(*) FROM audit_events');
echo "\nRe-sealing $total audit events...\n";

$prevHash = AuditEngine::GENESIS_HASH;
$stmt = $pdo->query('SELECT * FROM audit_events ORDER BY id ASC');
$update = $pdo->prepare('UPDATE audit_events SET prev_hash = ?, row_hash = ? WHERE id = ?');

$done = 0;
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $rowHash = AuditEngine::hashRow($row, $prevHash);
    $update->execute([$prevHash, $rowHash, $row['id']]);
    $prevHash = $rowHash;
    $done++;
}

$result = AuditEngine::verifyChain();
echo "Done. $done events sealed — chain " . ($result['ok'] ? 'intact' : 'STILL BROKEN') . ".\n";
