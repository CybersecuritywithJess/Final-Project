<?php

require_once __DIR__ . '/Database.php';

/**
 * THE RISK ENGINE.
 *
 * Decides what an event *means*: which compliance category it belongs to and
 * how dangerous it is. A single failed login is a typo; ten of them is an
 * attack — so a base risk can be escalated using the event's own details and
 * the thresholds an administrator has configured.
 */
class RiskEngine
{
    public const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

    public const SCORES = [
        'LOW'      => 10,
        'MEDIUM'   => 40,
        'HIGH'     => 70,
        'CRITICAL' => 95,
    ];

    public const CATEGORIES = [
        'Authentication',
        'Financial Transaction',
        'User Management',
        'Security',
        'Data Integrity',
        'Access Control',
        'Administration',
    ];

    /**
     * Everything the bank can emit. Each entry fixes a compliance category and
     * a baseline risk. Entries with 'escalate' can raise that baseline.
     */
    public const CATALOG = [
        // -- Authentication ---------------------------------------------------
        'user_registered'     => ['User Management',        'LOW',      'User registered'],
        'login_success'       => ['Authentication',         'LOW',      'Successful login'],
        'login_failed'        => ['Authentication',         'MEDIUM',   'Failed login',        'failed_logins'],
        'logout'              => ['Authentication',         'LOW',      'Logout'],
        'session_timeout'     => ['Authentication',         'LOW',      'Session timed out'],

        // -- Security ---------------------------------------------------------
        'password_changed'    => ['Security',               'MEDIUM',   'Password changed'],
        'password_reset'      => ['Security',               'MEDIUM',   'Password reset'],
        'account_locked'      => ['Security',               'CRITICAL', 'Account locked'],
        'account_unlocked'    => ['Security',               'HIGH',     'Account unlocked'],
        'mfa_enabled'         => ['Security',               'LOW',      'MFA enabled'],
        'mfa_disabled'        => ['Security',               'HIGH',     'MFA disabled'],
        'new_device_login'    => ['Security',               'HIGH',     'Login from new device'],
        'new_location_login'  => ['Security',               'CRITICAL', 'Login from new country'],

        // -- Financial --------------------------------------------------------
        'deposit'             => ['Financial Transaction',  'LOW',      'Deposit'],
        'savings_deposit'     => ['Financial Transaction',  'LOW',      'Savings deposit'],
        'balance_inquiry'     => ['Financial Transaction',  'LOW',      'Balance inquiry'],
        'bill_payment'        => ['Financial Transaction',  'LOW',      'Bill payment'],
        'airtime'             => ['Financial Transaction',  'LOW',      'Airtime purchase'],
        'withdrawal'          => ['Financial Transaction',  'LOW',      'Withdrawal',          'withdrawal_amount'],
        'transfer'            => ['Financial Transaction',  'LOW',      'Money transfer',      'transfer_amount'],
        'transaction_failed'  => ['Financial Transaction',  'MEDIUM',   'Transaction failed'],

        // -- Administration / access control ----------------------------------
        'user_created_by_admin' => ['Administration',       'MEDIUM',   'Admin created user'],
        'user_modified'         => ['Administration',       'HIGH',     'Admin modified user'],
        'user_deleted'          => ['Administration',       'CRITICAL', 'Admin deleted user'],
        'admin_password_reset'  => ['Administration',       'HIGH',     'Admin reset password'],
        'risk_rule_changed'     => ['Administration',       'HIGH',     'Risk threshold changed'],
        'role_changed'          => ['Access Control',       'CRITICAL', 'User role changed'],
        'unauthorized_access'   => ['Access Control',       'CRITICAL', 'Unauthorized access attempt'],
        'audit_viewed'          => ['Access Control',       'LOW',      'Audit log viewed'],
        'report_exported'       => ['Data Integrity',       'MEDIUM',   'Report exported'],
        'alert_status_changed'  => ['Data Integrity',       'MEDIUM',   'Alert status changed'],
        'alert_note_added'      => ['Data Integrity',       'LOW',      'Investigation note added'],
    ];

    /** Read an admin-configured threshold. */
    public static function rule(string $key): float
    {
        static $cache = [];
        if (!isset($cache[$key])) {
            $value = Database::value('SELECT value FROM risk_rules WHERE rule_key = ?', [$key]);
            $cache[$key] = $value === null ? 0.0 : (float) $value;
        }
        return $cache[$key];
    }

    /**
     * Score one event.
     *
     * @param array $details  amount, failed_logins — whatever the escalators need
     * @return array{category: string, level: string, score: int, label: string}
     */
    public static function score(string $eventType, array $details = []): array
    {
        // Anything not in the catalog is still scored — nothing goes unaudited.
        if (!isset(self::CATALOG[$eventType])) {
            return [
                'category' => 'Security',
                'level'    => 'MEDIUM',
                'score'    => self::SCORES['MEDIUM'],
                'label'    => $eventType,
            ];
        }

        [$category, $base, $label] = self::CATALOG[$eventType];
        $escalator = self::CATALOG[$eventType][3] ?? null;

        $level = $base;
        if ($escalator !== null) {
            $escalated = self::escalate($escalator, $details);
            if (self::rank($escalated) > self::rank($level)) {
                $level = $escalated;
            }
        }

        return [
            'category' => $category,
            'level'    => $level,
            'score'    => self::SCORES[$level],
            'label'    => $label,
        ];
    }

    /** The escalation rules — where a baseline risk gets promoted. */
    private static function escalate(string $escalator, array $details): string
    {
        switch ($escalator) {
            case 'failed_logins':
                $attempts = (int) ($details['failed_logins'] ?? 0);
                $max = self::rule('max_failed_logins');
                if ($attempts >= $max)              return 'CRITICAL';
                if ($attempts >= ceil($max / 2))    return 'HIGH';
                return 'MEDIUM';

            case 'withdrawal_amount':
                $amount = (float) ($details['amount'] ?? 0);
                $threshold = self::rule('large_withdrawal_threshold');
                if ($amount >= $threshold)          return 'HIGH';
                if ($amount >= $threshold / 2)      return 'MEDIUM';
                return 'LOW';

            case 'transfer_amount':
                $amount = (float) ($details['amount'] ?? 0);
                $threshold = self::rule('large_transfer_threshold');
                if ($amount >= $threshold)          return 'HIGH';
                if ($amount >= $threshold / 2)      return 'MEDIUM';
                return 'LOW';
        }

        return 'LOW';
    }

    public static function rank(string $level): int
    {
        return array_search($level, self::LEVELS, true) ?: 0;
    }
}
