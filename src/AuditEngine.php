<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/RiskEngine.php';
require_once __DIR__ . '/FraudEngine.php';
require_once __DIR__ . '/Context.php';

/**
 * THE AUDIT ENGINE.
 *
 * The Demo Bank never writes to audit_events itself. It calls
 * AuditEngine::record() and this class decides the category, the risk level and
 * the score, saves the event, then hands it to the fraud rules.
 *
 * That single choke point is what makes the audit trail trustworthy: an action
 * cannot happen in the bank without leaving a row behind.
 */
class AuditEngine
{
    /**
     * Tamper-evidence. Every audit row stores a SHA-256 HMAC (row_hash) that binds
     * its own content to the previous row's hash (prev_hash), forming a chain. Edit,
     * insert or delete any historical row and every hash after it stops matching —
     * verifyChain() then reports the exact row where the trail was broken.
     *
     * The chain does not make the log impossible to edit for someone with raw
     * database access; it makes such an edit DETECTABLE. The HMAC key lives in
     * config (out of the database), so a DB-only attacker cannot forge a valid
     * replacement hash.
     */
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * The immutable content covered by row_hash, in a fixed order. `id` and
     * `audit_ref` are deliberately excluded: audit_ref is stamped by a follow-up
     * UPDATE and is derived from the auto-increment id, neither of which is content.
     */
    private const HASH_FIELDS = [
        'event_type', 'category', 'description', 'subject_user_id', 'actor_user_id',
        'actor_role', 'risk_level', 'risk_score', 'transaction_id', 'amount',
        'ip_address', 'browser', 'os', 'device_type', 'country', 'city', 'session_id',
        'metadata', 'created_at',
    ];

    /**
     * Record one audit event and run fraud detection over it.
     *
     * @param array $input {
     *   type:            string   key from RiskEngine::CATALOG, e.g. 'withdrawal'
     *   ctx:             Context  the device/location of the request
     *   subject_user_id: ?int     the user the event is ABOUT
     *   actor:           ?array   who performed it: ['id' => int, 'role' => string]
     *   description:     ?string  overrides the catalog wording
     *   amount:          ?float
     *   transaction_id:  ?int
     *   metadata:        array    extra detail (balances, old/new values)
     *   signals:         array    facts the rules need (failed_logins, is_new_device)
     * }
     * @return array{event_id: int, audit_ref: string, risk_level: string, alerts: array}
     */
    public static function record(array $input): array
    {
        $type = $input['type'];
        $ctx = $input['ctx'] ?? Context::fromRequest();
        $subjectId = $input['subject_user_id'] ?? null;
        $actor = $input['actor'] ?? null;
        $amount = $input['amount'] ?? null;
        $metadata = $input['metadata'] ?? [];
        $signals = $input['signals'] ?? [];

        $scored = RiskEngine::score($type, array_merge(['amount' => $amount], $signals));

        $actorId = $actor['id'] ?? $subjectId;
        $actorRole = $actor['role'] ?? null;

        // The exact values that will be stored — hashed here so the hash covers the
        // row as persisted. created_at is fixed in PHP (not SQL NOW()) so the hashed
        // timestamp equals the stored one exactly.
        $now = date('Y-m-d H:i:s');
        $metadataJson = json_encode($metadata);

        $rowForHash = [
            'event_type'      => $type,
            'category'        => $scored['category'],
            'description'     => $input['description'] ?? $scored['label'],
            'subject_user_id' => $subjectId,
            'actor_user_id'   => $actorId,
            'actor_role'      => $actorRole,
            'risk_level'      => $scored['level'],
            'risk_score'      => $scored['score'],
            'transaction_id'  => $input['transaction_id'] ?? null,
            'amount'          => $amount,
            'ip_address'      => $ctx->ip,
            'browser'         => $ctx->browser,
            'os'              => $ctx->os,
            'device_type'     => $ctx->deviceType,
            'country'         => $ctx->country,
            'city'            => $ctx->city,
            'session_id'      => $ctx->sessionId,
            'metadata'        => $metadata,
            'created_at'      => $now,
        ];

        // Link onto the head of the chain. `php -S` serves one request at a time and
        // audit rows are never deleted, so a plain read of the latest hash is safe.
        $prevHash = Database::value('SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1')
            ?? self::GENESIS_HASH;
        $rowHash = self::hashRow($rowForHash, $prevHash);

        $eventId = Database::insert(
            "INSERT INTO audit_events
                (audit_ref, event_type, category, description, subject_user_id, actor_user_id,
                 actor_role, risk_level, risk_score, transaction_id, amount, ip_address,
                 browser, os, device_type, country, city, session_id, metadata, created_at,
                 prev_hash, row_hash)
             VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                $type,
                $scored['category'],
                $input['description'] ?? $scored['label'],
                $subjectId,
                $actorId,
                $actorRole,
                $scored['level'],
                $scored['score'],
                $input['transaction_id'] ?? null,
                $amount,
                $ctx->ip,
                $ctx->browser,
                $ctx->os,
                $ctx->deviceType,
                $ctx->country,
                $ctx->city,
                $ctx->sessionId,
                $metadataJson,
                $now,
                $prevHash,
                $rowHash,
            ]
        );

        $auditRef = 'AUD-' . str_pad((string) $eventId, 6, '0', STR_PAD_LEFT);
        Database::run('UPDATE audit_events SET audit_ref = ? WHERE id = ?', [$auditRef, $eventId]);

        // Hand the event to the fraud rules.
        $event = [
            'id'              => $eventId,
            'type'            => $type,
            'subject_user_id' => $subjectId,
            'amount'          => $amount === null ? null : (float) $amount,
            'metadata'        => $metadata,
            'ip'              => $ctx->ip,
        ];

        $signals += [
            'browser'     => $ctx->browser,
            'os'          => $ctx->os,
            'device_type' => $ctx->deviceType,
            'country'     => $ctx->country,
            'city'        => $ctx->city,
        ];

        $alerts = self::persistAlerts(FraudEngine::evaluate($event, $signals), $eventId, $subjectId);

        return [
            'event_id'   => $eventId,
            'audit_ref'  => $auditRef,
            'risk_level' => $scored['level'],
            'alerts'     => $alerts,
        ];
    }

    /**
     * How long the same rule stays quiet about the same user after firing.
     * Without this, every retry against an already-locked account raises another
     * CRITICAL alert and the queue floods with duplicates of one incident.
     */
    private const DEDUPE_MINUTES = 60;

    /** Turn the fraud rules' descriptors into alert rows, suppressing repeats. */
    private static function persistAlerts(array $descriptors, int $eventId, ?int $userId): array
    {
        $saved = [];

        foreach ($descriptors as $d) {
            if (self::isDuplicate($d['rule_key'], $userId)) {
                continue;
            }

            $alertId = Database::insert(
                "INSERT INTO alerts (alert_ref, audit_event_id, user_id, rule_key, title,
                                     description, risk_level, created_at, updated_at)
                 VALUES ('PENDING', ?, ?, ?, ?, ?, ?, NOW(), NOW())",
                [$eventId, $userId, $d['rule_key'], $d['title'], $d['description'], $d['risk_level']]
            );

            $alertRef = 'ALR-' . str_pad((string) $alertId, 6, '0', STR_PAD_LEFT);
            Database::run('UPDATE alerts SET alert_ref = ? WHERE id = ?', [$alertRef, $alertId]);

            error_log("[ALERT] $alertRef {$d['risk_level']} — {$d['title']}");

            $saved[] = [
                'ref'        => $alertRef,
                'title'      => $d['title'],
                'risk_level' => $d['risk_level'],
            ];
        }

        return $saved;
    }

    /**
     * True when this rule already has an unresolved alert open against this
     * user. One incident should produce one alert, however many events it
     * generates — an auditor investigating a break-in wants a case, not a feed.
     */
    private static function isDuplicate(string $ruleKey, ?int $userId): bool
    {
        if ($userId === null) {
            return false;
        }

        return (int) Database::value(
            "SELECT COUNT(*) FROM alerts
              WHERE rule_key = ? AND user_id = ?
                AND status IN ('new', 'under_investigation')
                AND created_at >= (NOW() - INTERVAL ? MINUTE)",
            [$ruleKey, $userId, self::DEDUPE_MINUTES]
        ) > 0;
    }

    /**
     * Remember the device a user just logged in from, and report whether it —
     * or the country — is new. These answers feed the new_device / new_country
     * rules.
     */
    public static function trackDevice(int $userId, Context $ctx, string $homeCountry): array
    {
        $existing = Database::one(
            'SELECT id FROM devices WHERE user_id = ? AND fingerprint = ?',
            [$userId, $ctx->fingerprint]
        );

        $seenCountry = Database::one(
            'SELECT id FROM devices WHERE user_id = ? AND last_country = ?',
            [$userId, $ctx->country]
        );

        $hasHistory = (int) Database::value(
            'SELECT COUNT(*) FROM devices WHERE user_id = ?',
            [$userId]
        ) > 0;

        if ($existing) {
            Database::run(
                'UPDATE devices SET last_seen = NOW(), last_ip = ?, last_country = ? WHERE id = ?',
                [$ctx->ip, $ctx->country, $existing['id']]
            );
        } else {
            Database::run(
                'INSERT INTO devices (user_id, fingerprint, browser, os, device_type, last_ip, last_country)
                 VALUES (?, ?, ?, ?, ?, ?, ?)',
                [$userId, $ctx->fingerprint, $ctx->browser, $ctx->os, $ctx->deviceType, $ctx->ip, $ctx->country]
            );
        }

        return [
            // On a brand-new account the first device isn't "new" in a suspicious sense.
            'is_new_device'  => $hasHistory && !$existing,
            'is_new_country' => $hasHistory && !$seenCountry && $ctx->country !== $homeCountry,
            'home_country'   => $homeCountry,
        ];
    }

    // -------------------------------------------------------- INTEGRITY (hash chain)

    /**
     * The keyed hash of one row's content, bound to the previous row's hash.
     * Accepts either a freshly-built row (metadata as a PHP array, at record time)
     * or a row read back from the database (metadata as a JSON string, at verify
     * time) — canonicalisation makes both produce an identical digest.
     */
    public static function hashRow(array $row, string $prevHash): string
    {
        return hash_hmac('sha256', $prevHash . '|' . self::canonical($row), self::secret());
    }

    /**
     * Serialise the hashed fields into one deterministic string. Values are
     * normalised so the string is identical whether the data came straight from
     * PHP or was round-tripped through MySQL (amount → fixed 2dp, JSON metadata →
     * key-sorted, everything else → plain string, null → empty).
     */
    private static function canonical(array $row): string
    {
        $ordered = [];
        foreach (self::HASH_FIELDS as $field) {
            if ($field === 'amount') {
                $amount = $row['amount'] ?? null;
                $ordered[] = ($amount === null || $amount === '')
                    ? '' : number_format((float) $amount, 2, '.', '');
            } elseif ($field === 'metadata') {
                $ordered[] = self::canonicalMeta($row['metadata'] ?? null);
            } else {
                $value = $row[$field] ?? null;
                $ordered[] = $value === null ? '' : (string) $value;
            }
        }

        return json_encode($ordered, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Canonical form of the metadata column. MySQL's JSON type may reorder object
     * keys, so we decode (if it arrived as a stored string), sort keys recursively,
     * and re-encode — giving the same result on both the write and verify sides.
     */
    private static function canonicalMeta($metadata): string
    {
        if (is_string($metadata)) {
            $metadata = json_decode($metadata, true);
        }
        if (!is_array($metadata)) {
            $metadata = [];
        }
        self::ksortRecursive($metadata);

        return json_encode($metadata, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private static function ksortRecursive(array &$array): void
    {
        foreach ($array as &$value) {
            if (is_array($value)) {
                self::ksortRecursive($value);
            }
        }
        unset($value);
        ksort($array);
    }

    private static function secret(): string
    {
        static $key = null;
        if ($key === null) {
            $config = require __DIR__ . '/../config/config.php';
            $key = (string) ($config['audit']['hmac_key'] ?? 'audit-chain-key');
        }
        return $key;
    }

    /**
     * Walk the whole chain from the genesis hash and report the first place it
     * breaks — a row whose content was altered (row_hash no longer matches) or a
     * broken link (prev_hash no longer points at the real previous row, which is
     * what an inserted or deleted row leaves behind).
     *
     * @return array{ok: bool, checked: int, first_broken: ?array, head_hash: string}
     */
    public static function verifyChain(): array
    {
        $stmt = Database::connect()->query('SELECT * FROM audit_events ORDER BY id ASC');

        $expectedPrev = self::GENESIS_HASH;
        $head = self::GENESIS_HASH;
        $checked = 0;
        $firstBroken = null;

        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $storedPrev = (string) ($row['prev_hash'] ?? '');
            $storedHash = (string) ($row['row_hash'] ?? '');
            $recomputed = self::hashRow($row, $storedPrev);

            $reason = null;
            if ($storedPrev !== $expectedPrev) {
                $reason = 'Broken chain link — a row was inserted or removed here.';
            } elseif ($storedHash !== $recomputed) {
                $reason = 'Contents altered — this row no longer matches its hash.';
            }

            if ($reason !== null) {
                $firstBroken = [
                    'audit_ref' => $row['audit_ref'],
                    'id'        => (int) $row['id'],
                    'reason'    => $reason,
                ];
                break;
            }

            $checked++;
            $expectedPrev = $storedHash;
            $head = $storedHash;
        }

        return [
            'ok'           => $firstBroken === null,
            'checked'      => $checked,
            'first_broken' => $firstBroken,
            'head_hash'    => $head,
        ];
    }
}
