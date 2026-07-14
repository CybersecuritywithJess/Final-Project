<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/RiskEngine.php';

/**
 * THE FRAUD ENGINE.
 *
 * Rule-based detection — no machine learning, just the patterns a real SOC
 * analyst would write down, each reading its thresholds from risk_rules so an
 * administrator can retune them without touching code.
 *
 * Every rule is pure: it looks at the event that just happened plus the recent
 * history around it, and returns an alert or null. Persisting is the Audit
 * Engine's job.
 */
class FraudEngine
{
    /**
     * Run every rule against a freshly recorded event.
     *
     * @param array $event  the event: type, subject_user_id, amount, metadata, ip
     * @param array $signals  extra facts the rules need (is_new_device, ...)
     * @return array  zero or more alert descriptors
     */
    public static function evaluate(array $event, array $signals = []): array
    {
        $rules = [
            'bruteForce', 'largeWithdrawal', 'largeTransfer', 'rapidTransfers',
            'accountDrain', 'newDevice', 'newCountry', 'dailyTransferLimit',
        ];

        $alerts = [];
        foreach ($rules as $rule) {
            try {
                $alert = self::$rule($event, $signals);
                if ($alert !== null) {
                    $alerts[] = $alert;
                }
            } catch (Throwable $e) {
                // A broken detection rule must never take down a bank transaction.
                error_log("[fraud] rule $rule failed: " . $e->getMessage());
            }
        }
        return $alerts;
    }

    // ------------------------------------------------------------------ RULES

    /** More than N failed logins inside the configured window. */
    private static function bruteForce(array $e): ?array
    {
        if ($e['type'] !== 'login_failed' || empty($e['subject_user_id'])) {
            return null;
        }

        $max = (int) RiskEngine::rule('max_failed_logins');
        $window = (int) RiskEngine::rule('brute_force_window_minutes');

        $count = (int) Database::value(
            "SELECT COUNT(*) FROM audit_events
              WHERE subject_user_id = ? AND event_type = 'login_failed'
                AND created_at >= (NOW() - INTERVAL ? MINUTE)",
            [$e['subject_user_id'], $window]
        );

        if ($count < $max) {
            return null;
        }

        return [
            'rule_key'    => 'brute_force',
            'title'       => 'Possible brute-force attack',
            'description' => "$count failed login attempts in the last $window minutes from IP {$e['ip']}. The account has been locked.",
            'risk_level'  => 'CRITICAL',
        ];
    }

    /** A single withdrawal at or above the large-withdrawal threshold. */
    private static function largeWithdrawal(array $e): ?array
    {
        if ($e['type'] !== 'withdrawal' || empty($e['amount'])) {
            return null;
        }

        $threshold = RiskEngine::rule('large_withdrawal_threshold');
        if ($e['amount'] < $threshold) {
            return null;
        }

        return [
            'rule_key'    => 'large_withdrawal',
            'title'       => 'Large withdrawal detected',
            'description' => 'Withdrawal of KES ' . self::fmt($e['amount']) .
                             ' is at or above the KES ' . self::fmt($threshold) . ' review threshold.',
            'risk_level'  => $e['amount'] >= $threshold * 2 ? 'CRITICAL' : 'HIGH',
        ];
    }

    /** A single transfer at or above the large-transfer threshold. */
    private static function largeTransfer(array $e): ?array
    {
        if ($e['type'] !== 'transfer' || empty($e['amount'])) {
            return null;
        }

        $threshold = RiskEngine::rule('large_transfer_threshold');
        if ($e['amount'] < $threshold) {
            return null;
        }

        return [
            'rule_key'    => 'large_transfer',
            'title'       => 'Large transfer detected',
            'description' => 'Transfer of KES ' . self::fmt($e['amount']) .
                             ' is at or above the KES ' . self::fmt($threshold) . ' review threshold.',
            'risk_level'  => $e['amount'] >= $threshold * 2 ? 'CRITICAL' : 'HIGH',
        ];
    }

    /** Several transfers fired off within a minute — classic structuring. */
    private static function rapidTransfers(array $e): ?array
    {
        if ($e['type'] !== 'transfer' || empty($e['subject_user_id'])) {
            return null;
        }

        $limit = (int) RiskEngine::rule('rapid_transfer_count');
        $window = (int) RiskEngine::rule('rapid_transfer_window_minutes');

        $row = Database::one(
            "SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS total FROM audit_events
              WHERE subject_user_id = ? AND event_type = 'transfer'
                AND created_at >= (NOW() - INTERVAL ? MINUTE)",
            [$e['subject_user_id'], $window]
        );

        if ((int) $row['n'] < $limit) {
            return null;
        }

        return [
            'rule_key'    => 'rapid_transfers',
            'title'       => 'Rapid successive transfers',
            'description' => "{$row['n']} transfers totalling KES " . self::fmt($row['total']) .
                             " within $window minute(s). This pattern is consistent with account takeover or structuring.",
            'risk_level'  => 'HIGH',
        ];
    }

    /** One withdrawal that empties most of the account. */
    private static function accountDrain(array $e): ?array
    {
        if ($e['type'] !== 'withdrawal' || empty($e['amount'])) {
            return null;
        }

        $before = (float) ($e['metadata']['balance_before'] ?? 0);
        if ($before <= 0) {
            return null;
        }

        $percent = RiskEngine::rule('account_drain_percent');
        $share = ($e['amount'] / $before) * 100;
        if ($share < $percent) {
            return null;
        }

        return [
            'rule_key'    => 'account_drain',
            'title'       => 'Account nearly emptied',
            'description' => 'Withdrawal of KES ' . self::fmt($e['amount']) . ' removed ' .
                             number_format($share, 1) . '% of the available balance (KES ' .
                             self::fmt($before) . ').',
            'risk_level'  => 'HIGH',
        ];
    }

    /** First time we have seen this browser/OS/device for the user. */
    private static function newDevice(array $e, array $s): ?array
    {
        if ($e['type'] !== 'login_success' || empty($s['is_new_device'])) {
            return null;
        }

        return [
            'rule_key'    => 'new_device',
            'title'       => 'Login from a new device',
            'description' => "First login from {$s['browser']} on {$s['os']} ({$s['device_type']}) at IP {$e['ip']}.",
            'risk_level'  => 'MEDIUM',
        ];
    }

    /** Login from a country the user has never logged in from. */
    private static function newCountry(array $e, array $s): ?array
    {
        if ($e['type'] !== 'login_success' || empty($s['is_new_country'])) {
            return null;
        }

        return [
            'rule_key'    => 'new_country',
            'title'       => 'Login from a new country',
            'description' => "Login from {$s['city']}, {$s['country']} — the account's home country is " .
                             "{$s['home_country']}. Impossible-travel risk.",
            'risk_level'  => 'CRITICAL',
        ];
    }

    /** Cumulative transfers today exceed the configured daily ceiling. */
    private static function dailyTransferLimit(array $e): ?array
    {
        if ($e['type'] !== 'transfer' || empty($e['subject_user_id'])) {
            return null;
        }

        $limit = RiskEngine::rule('daily_transfer_limit');
        $total = (float) Database::value(
            "SELECT COALESCE(SUM(amount), 0) FROM audit_events
              WHERE subject_user_id = ? AND event_type = 'transfer'
                AND DATE(created_at) = CURDATE()",
            [$e['subject_user_id']]
        );

        if ($total < $limit) {
            return null;
        }

        return [
            'rule_key'    => 'daily_limit_exceeded',
            'title'       => 'Daily transfer limit exceeded',
            'description' => 'Transfers today total KES ' . self::fmt($total) .
                             ', above the KES ' . self::fmt($limit) . ' daily limit.',
            'risk_level'  => 'HIGH',
        ];
    }

    private static function fmt(float $n): string
    {
        return number_format($n, 0);
    }
}
