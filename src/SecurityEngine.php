<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/RiskEngine.php';
require_once __DIR__ . '/AuditEngine.php';
require_once __DIR__ . '/Context.php';

/**
 * THE SECURITY ENGINE.
 *
 * Where the FraudEngine *detects* and raises alerts for an auditor to read, this
 * class *enforces*: it restricts accounts that keep breaching their transaction
 * limit, locks accounts that are being guessed at, and gives an administrator the
 * one supported way to undo either.
 *
 * Two rules hold everywhere in here:
 *
 *   1. A control never touches money. Restricting an account or locking a login
 *      changes access only — balances and history are left exactly as they were.
 *   2. A control never acts silently. Every flag raised and every recovery an
 *      admin performs goes through AuditEngine::record(), so the trail explains
 *      itself without anyone having to read this file.
 *
 * Thresholds all come from risk_rules, so an administrator retunes them at
 * runtime — nothing here is hard-coded to a particular number.
 */
class SecurityEngine
{
    // Flag types. Strings rather than an enum so a new control can raise a new
    // kind of flag without a schema change.
    public const FLAG_LIMIT_VIOLATION = 'DAILY_LIMIT_VIOLATION';
    public const FLAG_ACCOUNT_RESTRICTED = 'ACCOUNT_RESTRICTED';
    public const FLAG_LOGIN_LOCKOUT = 'LOGIN_LOCKOUT';
    public const FLAG_BRUTE_FORCE = 'BRUTE_FORCE_ATTACK';

    // ---------------------------------------------------------- SECURITY FLAGS

    /**
     * Raise a security flag and record the audit event behind it.
     *
     * @param array $input {
     *   flag_type:   string   one of the FLAG_* constants
     *   severity:    string   LOW | MEDIUM | HIGH | CRITICAL
     *   description: string   what happened, in words an admin can act on
     *   user_id:     ?int
     *   account_id:  ?int
     *   event_type:  ?string  audit catalog key; omit to skip the audit event
     *   ctx:         ?Context
     *   metadata:    array    extra detail for the audit row
     *   amount:      ?float
     * }
     * @return array{flag_id: int, flag_ref: string, audit_ref: ?string}
     */
    public static function flag(array $input): array
    {
        $auditEventId = null;
        $auditRef = null;

        // Record the audit event first so the flag can point at it.
        if (!empty($input['event_type'])) {
            $recorded = AuditEngine::record([
                'type'            => $input['event_type'],
                'ctx'             => $input['ctx'] ?? Context::fromRequest(),
                'subject_user_id' => $input['user_id'] ?? null,
                'actor'           => $input['actor'] ?? null,
                'amount'          => $input['amount'] ?? null,
                'description'     => $input['description'],
                'metadata'        => ($input['metadata'] ?? []) + [
                    'flag_type' => $input['flag_type'],
                    'severity'  => $input['severity'],
                ],
            ]);
            $auditEventId = $recorded['event_id'];
            $auditRef = $recorded['audit_ref'];
        }

        $flagId = Database::insert(
            "INSERT INTO security_flags
                (flag_ref, user_id, account_id, flag_type, severity, description,
                 status, audit_event_id, created_at)
             VALUES ('PENDING', ?, ?, ?, ?, ?, 'open', ?, NOW())",
            [
                $input['user_id'] ?? null,
                $input['account_id'] ?? null,
                $input['flag_type'],
                $input['severity'],
                $input['description'],
                $auditEventId,
            ]
        );

        $flagRef = 'SEC-' . str_pad((string) $flagId, 6, '0', STR_PAD_LEFT);
        Database::run('UPDATE security_flags SET flag_ref = ? WHERE id = ?', [$flagRef, $flagId]);

        error_log("[SECURITY] $flagRef {$input['severity']} — {$input['flag_type']}");

        return ['flag_id' => $flagId, 'flag_ref' => $flagRef, 'audit_ref' => $auditRef];
    }

    /** Close every open flag of the given types for a user or account. */
    public static function resolveFlags(array $types, ?int $userId, ?int $accountId, int $adminId): int
    {
        if (!$types) {
            return 0;
        }

        // resolved_by is bound first because it appears first in the statement.
        $params = [$adminId, ...$types];
        $placeholders = implode(', ', array_fill(0, count($types), '?'));
        $where = "status = 'open' AND flag_type IN ($placeholders)";

        // Scope to the account when we have one, otherwise to the whole user.
        if ($accountId !== null) {
            $where .= ' AND account_id = ?';
            $params[] = $accountId;
        } elseif ($userId !== null) {
            $where .= ' AND user_id = ?';
            $params[] = $userId;
        }

        return Database::run(
            "UPDATE security_flags
                SET status = 'resolved', resolved_at = NOW(), resolved_by = ?
              WHERE $where",
            $params
        );
    }

    // ----------------------------------------------------- ACCOUNT RESTRICTION

    /**
     * Stop an account from transacting after repeated limit breaches.
     * The customer keeps their login and their money; only the ability to move
     * it is suspended until an administrator reviews the account.
     */
    public static function restrictAccount(array $account, array $user, Context $ctx, string $reason): array
    {
        Database::run(
            "UPDATE accounts SET account_status = 'restricted' WHERE id = ?",
            [$account['id']]
        );

        return self::flag([
            'flag_type'   => self::FLAG_ACCOUNT_RESTRICTED,
            'severity'    => 'CRITICAL',
            'user_id'     => (int) $user['id'],
            'account_id'  => (int) $account['id'],
            'event_type'  => 'account_restricted',
            'ctx'         => $ctx,
            'description' => "Account {$account['account_number']} (\"{$user['username']}\") was restricted "
                             . "from transacting: $reason",
            'metadata'    => [
                'account_number'  => $account['account_number'],
                'reason'          => $reason,
                'violation_count' => (int) $account['limit_violation_count'] + 1,
            ],
        ]);
    }

    /**
     * Admin recovery: let a restricted account transact again.
     * Resets the violation counter so the customer starts from a clean slate.
     */
    public static function activateAccount(array $account, array $admin, Context $ctx): void
    {
        Database::run(
            "UPDATE accounts SET account_status = 'active', limit_violation_count = 0 WHERE id = ?",
            [$account['id']]
        );

        self::resolveFlags(
            [self::FLAG_ACCOUNT_RESTRICTED, self::FLAG_LIMIT_VIOLATION],
            (int) $account['user_id'],
            (int) $account['id'],
            (int) $admin['id']
        );

        $owner = Database::one('SELECT username FROM users WHERE id = ?', [$account['user_id']]);

        AuditEngine::record([
            'type'            => 'account_reactivated',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $account['user_id'],
            'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
            'description'     => "Admin \"{$admin['username']}\" reactivated account "
                                 . "{$account['account_number']} (\"" . ($owner['username'] ?? '?') . "\") "
                                 . 'and cleared its limit violations',
            'metadata'        => [
                'account_number'  => $account['account_number'],
                'previous_status' => $account['account_status'],
            ],
        ]);
    }

    // ------------------------------------------------------------ LOGIN LOCKS

    /**
     * Where a user stands with the login controls, right now.
     *
     * A timed lock that has run its course is cleared here rather than by a
     * scheduled job: the next login attempt is the only moment the answer
     * matters, so that is where the expiry is applied.
     *
     * @return array{locked: bool, permanent: bool, seconds_left: int}
     */
    public static function checkLockout(array $user): array
    {
        $clear = ['locked' => false, 'permanent' => false, 'seconds_left' => 0];

        if ($user['status'] === 'brute_force_locked') {
            return ['locked' => true, 'permanent' => true, 'seconds_left' => 0];
        }

        if ($user['status'] !== 'locked') {
            return $clear;
        }

        // Locked with no expiry — an administrator locked it by hand.
        if (empty($user['locked_until'])) {
            return ['locked' => true, 'permanent' => true, 'seconds_left' => 0];
        }

        $secondsLeft = strtotime((string) $user['locked_until']) - time();

        if ($secondsLeft > 0) {
            return ['locked' => true, 'permanent' => false, 'seconds_left' => $secondsLeft];
        }

        // The lock has expired: give the account its chance back.
        Database::run(
            "UPDATE users SET status = 'active', failed_logins = 0, locked_until = NULL WHERE id = ?",
            [$user['id']]
        );

        return $clear;
    }

    /**
     * The threshold this account is currently judged against.
     *
     * A clean account gets the full allowance — people mistype passwords. An
     * account that has already been locked out once has been warned, and is
     * held to a shorter one from then on.
     */
    public static function failureThreshold(array $user): int
    {
        return self::hasBeenWarned($user)
            ? max(1, (int) RiskEngine::rule('post_lockout_failures'))
            : max(1, (int) RiskEngine::rule('max_failed_logins'));
    }

    /** True once this account has been locked out at least once before. */
    public static function hasBeenWarned(array $user): bool
    {
        return (int) ($user['lockout_count'] ?? 0) > 0;
    }

    /**
     * Lock the account, in one of two stages.
     *
     * The first time, it is a timed lockout — a customer who has forgotten their
     * password waits a couple of minutes and tries again. But that lockout is
     * also a warning, and it is remembered: an account that comes back and keeps
     * failing after being warned is no longer behaving like a forgetful
     * customer, so the second lockout is permanent and only an administrator can
     * lift it.
     *
     * @return array{permanent: bool, minutes: int, cycle: int}
     */
    public static function lockUser(array $user, Context $ctx, int $attempts): array
    {
        $minutes = max(1, (int) RiskEngine::rule('login_lockout_minutes'));
        $cycle = (int) $user['lockout_count'] + 1;

        // Already warned once — this is the escalation.
        if (self::hasBeenWarned($user)) {
            Database::run(
                "UPDATE users
                    SET status = 'brute_force_locked', locked_at = NOW(),
                        locked_until = NULL, lockout_count = ?
                  WHERE id = ?",
                [$cycle, $user['id']]
            );

            self::flag([
                'flag_type'   => self::FLAG_BRUTE_FORCE,
                'severity'    => 'CRITICAL',
                'user_id'     => (int) $user['id'],
                'event_type'  => 'brute_force_locked',
                'ctx'         => $ctx,
                'description' => "Account \"{$user['username']}\" was locked for security: after being "
                                 . "temporarily locked once already, it failed a further $attempts login "
                                 . "attempts from IP {$ctx->ip}. Continued failure after a warning is "
                                 . 'treated as a possible attack — only an administrator can restore access.',
                'metadata'    => [
                    'stage'            => 'permanent',
                    'lockout_history'  => $cycle,
                    'failed_attempts'  => $attempts,
                    'ip'               => $ctx->ip,
                ],
            ]);

            return ['permanent' => true, 'minutes' => $minutes, 'cycle' => $cycle];
        }

        // The expiry is computed in PHP, not with MySQL's NOW(): checkLockout()
        // compares it against PHP's clock, and the two do not necessarily agree
        // on the timezone. One clock writes it, the same clock reads it.
        $until = date('Y-m-d H:i:s', time() + $minutes * 60);

        Database::run(
            "UPDATE users
                SET status = 'locked', locked_at = NOW(),
                    locked_until = ?, lockout_count = ?
              WHERE id = ?",
            [$until, $cycle, $user['id']]
        );

        self::flag([
            'flag_type'   => self::FLAG_LOGIN_LOCKOUT,
            'severity'    => 'HIGH',
            'user_id'     => (int) $user['id'],
            'event_type'  => 'login_lockout',
            'ctx'         => $ctx,
            'description' => "Account \"{$user['username']}\" was locked for $minutes minute(s) after "
                             . "$attempts consecutive failed logins from IP {$ctx->ip}. This is a warning: "
                             . 'further failures after the lock expires will secure the account permanently.',
            'metadata'    => [
                'stage'           => 'temporary',
                'failed_attempts' => $attempts,
                'lockout_minutes' => $minutes,
                'lockout_history' => $cycle,
                'next_threshold'  => (int) RiskEngine::rule('post_lockout_failures'),
            ],
        ]);

        return ['permanent' => false, 'minutes' => $minutes, 'cycle' => $cycle];
    }

    /**
     * Admin recovery: restore login access.
     * Balances, transactions and history are untouched — this only reopens the door.
     */
    public static function unlockUser(array $user, array $admin, Context $ctx): void
    {
        Database::run(
            "UPDATE users
                SET status = 'active', failed_logins = 0, lockout_count = 0,
                    locked_until = NULL, locked_at = NULL
              WHERE id = ?",
            [$user['id']]
        );

        self::resolveFlags(
            [self::FLAG_BRUTE_FORCE, self::FLAG_LOGIN_LOCKOUT],
            (int) $user['id'],
            null,
            (int) $admin['id']
        );

        AuditEngine::record([
            'type'            => 'account_unlocked',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
            'description'     => "Admin \"{$admin['username']}\" restored login access for "
                                 . "\"{$user['username']}\" (was {$user['status']})",
            'metadata'        => [
                'previous_status'         => $user['status'],
                'previous_failed_logins'  => (int) $user['failed_logins'],
                'previous_lockout_cycles' => (int) $user['lockout_count'],
            ],
        ]);
    }

    // --------------------------------------------------------- LOGIN ATTEMPTS

    /**
     * Record one login attempt. Called for successes and failures alike — a
     * brute-force pattern is only visible when you can see both.
     */
    public static function recordLoginAttempt(
        ?int $userId,
        string $username,
        Context $ctx,
        string $status,
        ?string $reason = null
    ): void {
        Database::run(
            'INSERT INTO login_attempts (user_id, username, ip_address, user_agent, status, reason, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())',
            [
                $userId,
                mb_substr($username, 0, 150),
                $ctx->ip,
                mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255) ?: null,
                $status,
                $reason,
            ]
        );
    }

    /** Recent login attempts, newest first — powers the admin security view. */
    public static function recentAttempts(int $limit = 50, ?int $userId = null): array
    {
        $limit = max(1, min($limit, 200));

        if ($userId !== null) {
            return Database::all(
                "SELECT * FROM login_attempts WHERE user_id = ?
                  ORDER BY created_at DESC, id DESC LIMIT $limit",
                [$userId]
            );
        }

        return Database::all(
            "SELECT la.*, u.full_name
               FROM login_attempts la
               LEFT JOIN users u ON u.id = la.user_id
              ORDER BY la.created_at DESC, la.id DESC LIMIT $limit"
        );
    }
}
