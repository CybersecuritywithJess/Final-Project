<?php

require_once __DIR__ . '/Database.php';

/**
 * Runs a read-only SELECT that the AI wrote, safely.
 *
 * A model writing SQL against your database is only as safe as the gate in
 * front of it. Nothing here trusts the model: the statement must be a single
 * SELECT, it may not contain any writing or schema keyword, it may only touch
 * tables on an allow-list, and it runs inside a transaction that is ALWAYS
 * rolled back — so even a query that slipped past every check cannot leave a
 * mark on the database.
 */
class SqlGuard
{
    /** The only tables the assistant is ever allowed to read. */
    private const ALLOWED_TABLES = [
        'users', 'accounts', 'transactions', 'audit_events',
        'alerts', 'alert_notes', 'devices', 'risk_rules',
    ];

    /** Whole-word tokens that must never appear in a read-only query. */
    private const FORBIDDEN = [
        'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate',
        'replace', 'rename', 'grant', 'revoke', 'commit', 'rollback', 'merge',
        'call', 'execute', 'exec', 'into', 'load_file', 'outfile', 'dumpfile',
        'set', 'lock', 'unlock', 'handler', 'attach', 'pragma',
    ];

    private const MAX_ROWS = 200;

    /**
     * Validate and execute. Returns the rows, or throws with a reason the UI
     * can show. The query is never committed.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function run(string $sql): array
    {
        $clean = self::validate($sql);

        $pdo = Database::connect();
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->query($clean);
            $rows = $stmt->fetchAll();
        } finally {
            // Read-only by construction: undo anything, always.
            $pdo->rollBack();
        }

        return array_slice($rows, 0, self::MAX_ROWS);
    }

    /**
     * Enforce every rule and return a normalised, row-capped query.
     * @throws RuntimeException on any violation
     */
    public static function validate(string $sql): string
    {
        $trimmed = trim(rtrim(trim($sql), ';'));

        if ($trimmed === '') {
            throw new RuntimeException('The assistant produced an empty query.');
        }

        // 1. Exactly one statement — no stacked queries.
        if (str_contains($trimmed, ';')) {
            throw new RuntimeException('Only a single query may be run.');
        }

        // 2. Must start with SELECT (or an opening parenthesis before it).
        if (!preg_match('/^\(*\s*select\b/i', $trimmed)) {
            throw new RuntimeException('Only read-only SELECT queries are allowed.');
        }

        // 3. No SQL comments — a common way to smuggle a second intent.
        if (preg_match('~(--|#|/\*)~', $trimmed)) {
            throw new RuntimeException('Comments are not allowed in a query.');
        }

        // 4. No writing / schema / control keyword, matched as a whole word.
        $lower = strtolower($trimmed);
        foreach (self::FORBIDDEN as $word) {
            if (preg_match('/\b' . preg_quote($word, '/') . '\b/', $lower)) {
                throw new RuntimeException("The query used a forbidden keyword: \"$word\".");
            }
        }

        // 5. Every referenced table must be on the allow-list. We look at the
        //    identifiers following FROM and JOIN.
        preg_match_all('/\b(?:from|join)\s+`?([a-z_][a-z0-9_]*)`?/i', $trimmed, $matches);
        foreach ($matches[1] as $table) {
            if (!in_array(strtolower($table), self::ALLOWED_TABLES, true)) {
                throw new RuntimeException("The query referenced a table it may not read: \"$table\".");
            }
        }

        // 6. Cap the rows even if the model forgot a LIMIT.
        if (!preg_match('/\blimit\s+\d+/i', $trimmed)) {
            $trimmed .= ' LIMIT ' . self::MAX_ROWS;
        }

        return $trimmed;
    }
}
