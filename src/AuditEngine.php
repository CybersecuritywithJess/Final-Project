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

        $eventId = Database::insert(
            "INSERT INTO audit_events
                (audit_ref, event_type, category, description, subject_user_id, actor_user_id,
                 actor_role, risk_level, risk_score, transaction_id, amount, ip_address,
                 browser, os, device_type, country, city, session_id, metadata, created_at)
             VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
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
                json_encode($metadata),
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
}
