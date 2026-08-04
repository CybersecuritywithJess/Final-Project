<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/RiskEngine.php';

/** Account and transaction plumbing for the Demo Bank. */
class Bank
{
    /** Transaction types that take money OUT of an account and so count against the daily limit. */
    private const OUTBOUND_TYPES = ['withdrawal', 'transfer', 'bill_payment', 'airtime'];

    /** Every new customer gets a checking and a savings account. */
    public static function openAccounts(int $userId): array
    {
        $base = 1000000000 + $userId * 100;

        Database::run(
            "INSERT INTO accounts (user_id, account_number, type, balance) VALUES (?, ?, 'checking', 0)",
            [$userId, (string) ($base + 1)]
        );
        Database::run(
            "INSERT INTO accounts (user_id, account_number, type, balance) VALUES (?, ?, 'savings', 0)",
            [$userId, (string) ($base + 2)]
        );

        return self::accountsOf($userId);
    }

    /** @return array{checking: array, savings: array, all: array} */
    public static function accountsOf(int $userId): array
    {
        $rows = Database::all('SELECT * FROM accounts WHERE user_id = ? ORDER BY type', [$userId]);

        $byType = [];
        foreach ($rows as $row) {
            $byType[$row['type']] = $row;
        }

        return [
            'checking' => $byType['checking'] ?? null,
            'savings'  => $byType['savings'] ?? null,
            'all'      => $rows,
        ];
    }

    public static function accountByNumber(string $number): ?array
    {
        return Database::one('SELECT * FROM accounts WHERE account_number = ?', [trim($number)]);
    }

    /** Write a transaction row and return the saved record. */
    public static function createTransaction(array $t): array
    {
        $id = Database::insert(
            "INSERT INTO transactions
                (reference, user_id, type, amount, from_account_id, to_account_id,
                 counterparty, status, failure_reason, description, ip_address, created_at)
             VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
            [
                $t['user_id'],
                $t['type'],
                $t['amount'],
                $t['from_account_id'] ?? null,
                $t['to_account_id'] ?? null,
                $t['counterparty'] ?? null,
                $t['status'] ?? 'completed',
                $t['failure_reason'] ?? null,
                $t['description'] ?? null,
                $t['ip'] ?? null,
            ]
        );

        $ref = 'TXN-' . str_pad((string) $id, 6, '0', STR_PAD_LEFT);
        Database::run('UPDATE transactions SET reference = ? WHERE id = ?', [$ref, $id]);

        return Database::one('SELECT * FROM transactions WHERE id = ?', [$id]);
    }

    public static function adjustBalance(int $accountId, float $delta): void
    {
        Database::run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [$delta, $accountId]);
    }

    // --------------------------------------------------- DAILY TRANSACTION LIMIT

    /**
     * How much this account may move in a day: a configured share of whatever it
     * currently holds. Recomputed from the live balance every time it is asked
     * for — a customer who deposits more can immediately transact more, and one
     * who spends down carries a proportionally smaller ceiling.
     *
     * The result is written back to accounts.daily_limit so reports and the admin
     * views can read the number without recalculating it.
     */
    public static function dailyLimit(array $account): float
    {
        $percent = (float) RiskEngine::rule('daily_limit_percent');
        $limit = round(((float) $account['balance']) * $percent / 100, 2);

        if ((float) ($account['daily_limit'] ?? -1) !== $limit) {
            Database::run('UPDATE accounts SET daily_limit = ? WHERE id = ?', [$limit, $account['id']]);
        }

        return $limit;
    }

    /**
     * What this account has already moved out today. Only money that actually
     * left counts — declined and failed attempts never consumed any limit.
     */
    public static function usedToday(int $accountId): float
    {
        $types = implode("', '", self::OUTBOUND_TYPES);

        return (float) Database::value(
            "SELECT COALESCE(SUM(amount), 0) FROM transactions
              WHERE from_account_id = ?
                AND type IN ('$types')
                AND status IN ('completed', 'flagged')
                AND DATE(created_at) = CURDATE()",
            [$accountId]
        );
    }

    /**
     * Decide whether one outbound transaction fits inside today's limit.
     *
     * @return array{allowed: bool, limit: float, used: float, remaining: float, requested: float}
     */
    public static function limitCheck(array $account, float $amount): array
    {
        $limit = self::dailyLimit($account);
        $used = self::usedToday((int) $account['id']);
        $remaining = max(0, round($limit - $used, 2));

        return [
            'allowed'   => round($used + $amount, 2) <= $limit,
            'limit'     => $limit,
            'used'      => $used,
            'remaining' => $remaining,
            'requested' => $amount,
        ];
    }

    /** True once any deposit has ever landed on this account. */
    public static function hasEverDeposited(int $accountId): bool
    {
        return (int) Database::value(
            "SELECT COUNT(*) FROM transactions
              WHERE to_account_id = ?
                AND type IN ('deposit', 'savings_deposit')
                AND status IN ('completed', 'flagged')",
            [$accountId]
        ) > 0;
    }

    /**
     * Amounts must be positive, finite and sanely sized.
     *
     * @return array{amount: ?float, error: ?string}
     */
    public static function validateAmount($raw): array
    {
        if (!is_numeric($raw)) {
            return ['amount' => null, 'error' => 'Amount must be a number'];
        }

        $amount = (float) $raw;

        if ($amount <= 0) {
            return ['amount' => null, 'error' => 'Amount must be greater than zero'];
        }
        if ($amount > 100000000) {
            return ['amount' => null, 'error' => 'Amount exceeds the maximum single transaction size'];
        }

        return ['amount' => round($amount, 2), 'error' => null];
    }
}
