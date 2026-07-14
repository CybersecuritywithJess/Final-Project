<?php

require_once __DIR__ . '/Database.php';

/** Account and transaction plumbing for the Demo Bank. */
class Bank
{
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
                 counterparty, status, description, ip_address, created_at)
             VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
            [
                $t['user_id'],
                $t['type'],
                $t['amount'],
                $t['from_account_id'] ?? null,
                $t['to_account_id'] ?? null,
                $t['counterparty'] ?? null,
                $t['status'] ?? 'completed',
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
