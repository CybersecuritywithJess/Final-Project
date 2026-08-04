<?php

/**
 * THE DEMO BANK API.
 *
 *   GET  ?action=accounts       balances
 *   GET  ?action=transactions   recent statement
 *   POST ?action=deposit
 *   POST ?action=withdraw
 *   POST ?action=transfer
 *   POST ?action=pay            bill payment / airtime
 *
 * Notice that no handler here writes to audit_events. Each one calls
 * AuditEngine::record() and the engine decides what the event means.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../../src/SecurityEngine.php';

$user = Auth::requireRole('customer');
$ctx = Context::fromRequest();
$uid = (int) $user['id'];

switch (action()) {
    case 'accounts':
        accounts($user, $ctx);
        break;

    case 'transactions':
        transactions($uid);
        break;

    case 'deposit':
        requireMethod('POST');
        deposit($user, $ctx);
        break;

    case 'withdraw':
        requireMethod('POST');
        withdraw($user, $ctx);
        break;

    case 'transfer':
        requireMethod('POST');
        transfer($user, $ctx);
        break;

    case 'pay':
        requireMethod('POST');
        pay($user, $ctx);
        break;

    default:
        Response::error('Unknown action', 404);
}

// ------------------------------------------------------- SECURITY CONTROLS

/**
 * The gate every outbound transaction passes through.
 *
 * Three checks, in the order that gives the customer the most useful answer:
 * an account that has been restricted, an account that has never been funded,
 * and finally the daily limit. Each refusal is recorded — a declined attempt is
 * evidence, and three of them are a pattern worth acting on.
 *
 * Returns normally when the transaction may proceed; otherwise it responds and
 * exits.
 */
function guardTransaction(array $user, array $account, Context $ctx, float $amount, string $type): void
{
    // 1. Already restricted — nothing moves until an administrator reviews it.
    if (($account['account_status'] ?? 'active') === 'restricted') {
        Response::error(
            'Your account is temporarily closed. Please visit your nearest branch for verification '
            . 'and account reactivation.',
            403,
            ['code' => 'ACCOUNT_RESTRICTED']
        );
    }

    // 2. A brand-new account has to be funded before it can be spent from.
    if (!Bank::hasEverDeposited((int) $account['id'])) {
        Response::error(
            'Your account has insufficient funds. Please make an initial deposit before '
            . 'performing transactions.',
            400,
            ['code' => 'NO_INITIAL_DEPOSIT']
        );
    }

    // 3. The daily ceiling, recalculated from the balance as it stands right now.
    $check = Bank::limitCheck($account, $amount);
    if (!$check['allowed']) {
        declineOverLimit($user, $account, $ctx, $amount, $type, $check);
    }
}

/**
 * Record an over-limit attempt and refuse it.
 *
 * The refusal leaves a full trail: a declined transaction row carrying the
 * reason, an audit event, and a security flag. Enough repeats and the account
 * itself is restricted.
 */
function declineOverLimit(
    array $user,
    array $account,
    Context $ctx,
    float $amount,
    string $type,
    array $check
): never {
    $reason = 'Exceeded daily transaction limit';

    $txn = Bank::createTransaction([
        'user_id'         => (int) $user['id'],
        'type'            => $type,
        'amount'          => $amount,
        'from_account_id' => (int) $account['id'],
        'status'          => 'declined',
        'failure_reason'  => $reason,
        'description'     => 'Declined — over daily limit',
        'ip'              => $ctx->ip,
    ]);

    $violations = (int) $account['limit_violation_count'] + 1;
    $allowed = max(1, (int) RiskEngine::rule('limit_violations_before_restriction'));

    Database::run(
        'UPDATE accounts SET limit_violation_count = ? WHERE id = ?',
        [$violations, $account['id']]
    );

    $money = fn(float $n): string => 'KES ' . number_format($n, 2);

    SecurityEngine::flag([
        'flag_type'   => SecurityEngine::FLAG_LIMIT_VIOLATION,
        'severity'    => 'HIGH',
        'user_id'     => (int) $user['id'],
        'account_id'  => (int) $account['id'],
        'event_type'  => 'limit_exceeded',
        'ctx'         => $ctx,
        'amount'      => $amount,
        'actor'       => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description' => "\"{$user['username']}\" attempted a $type of {$money($amount)} on account "
                         . "{$account['account_number']}, which would take today's total to "
                         . $money($check['used'] + $amount) . ' against a daily limit of '
                         . $money($check['limit']) . " (violation $violations of $allowed).",
        'metadata'    => [
            'account_number'  => $account['account_number'],
            'transaction_ref' => $txn['reference'],
            'daily_limit'     => $check['limit'],
            'used_today'      => $check['used'],
            'remaining'       => $check['remaining'],
            'requested'       => $amount,
            'violation_count' => $violations,
            'violations_allowed' => $allowed,
        ],
    ]);

    // Enough repeat attempts to stop treating it as a mistake.
    $restricted = false;
    if ($violations >= $allowed) {
        SecurityEngine::restrictAccount(
            $account + ['limit_violation_count' => $violations - 1],
            $user,
            $ctx,
            "$violations attempts to exceed the daily transaction limit"
        );
        $restricted = true;
    }

    Response::error(
        'You are unable to complete this transaction because it exceeds your daily transaction limit.',
        403,
        [
            'code'        => 'LIMIT_EXCEEDED',
            'daily_limit' => $check['limit'],
            'used_today'  => $check['used'],
            'remaining'   => $check['remaining'],
            'requested'   => $amount,
            'violations'  => $violations,
            'violations_allowed' => $allowed,
            'restricted'  => $restricted,
            'transaction' => $txn,
        ]
    );
}

/** Refuse any activity at all on a restricted account (deposits included). */
function requireActiveAccount(array $account): void
{
    if (($account['account_status'] ?? 'active') === 'restricted') {
        Response::error(
            'Your account is temporarily closed. Please visit your nearest branch for verification '
            . 'and account reactivation.',
            403,
            ['code' => 'ACCOUNT_RESTRICTED']
        );
    }
}

// ---------------------------------------------------------------- OVERVIEW

function accounts(array $user, Context $ctx): never
{
    $accounts = Bank::accountsOf((int) $user['id']);

    // Attach the live limit picture to each account so the customer always sees
    // the same numbers the guard will enforce.
    foreach ($accounts['all'] as &$account) {
        $limit = Bank::dailyLimit($account);
        $used = Bank::usedToday((int) $account['id']);

        $account['daily_limit']     = $limit;
        $account['used_today']      = $used;
        $account['remaining_today'] = max(0, round($limit - $used, 2));
        $account['funded']          = Bank::hasEverDeposited((int) $account['id']);
    }
    unset($account);

    AuditEngine::record([
        'type'            => 'balance_inquiry',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "\"{$user['username']}\" viewed their account balances",
    ]);

    Response::json([
        'accounts' => $accounts['all'],
        'limit_percent' => (float) RiskEngine::rule('daily_limit_percent'),
    ]);
}

function transactions(int $uid): never
{
    $limit = min((int) ($_GET['limit'] ?? 25), 100);

    $rows = Database::all(
        'SELECT * FROM transactions WHERE user_id = ?
          ORDER BY created_at DESC, id DESC LIMIT ' . $limit,
        [$uid]
    );

    Response::json(['transactions' => $rows]);
}

// ----------------------------------------------------------------- DEPOSIT

function deposit(array $user, Context $ctx): never
{
    $body = Response::body();
    ['amount' => $amount, 'error' => $error] = Bank::validateAmount($body['amount'] ?? null);
    if ($error) {
        Response::error($error);
    }

    $type = ($body['account_type'] ?? 'checking') === 'savings' ? 'savings' : 'checking';
    $account = Bank::accountsOf((int) $user['id'])[$type];
    if (!$account) {
        Response::error('Account not found', 404);
    }

    // A restricted account is frozen for everything, deposits included, until an
    // administrator reviews it.
    requireActiveAccount($account);

    $isSavings = $type === 'savings';
    $before = (float) $account['balance'];

    Bank::adjustBalance((int) $account['id'], $amount);

    // The ceiling moves with the balance, so refresh it against the new one.
    $account['balance'] = $before + $amount;
    $newLimit = Bank::dailyLimit($account);

    $txn = Bank::createTransaction([
        'user_id'       => (int) $user['id'],
        'type'          => $isSavings ? 'savings_deposit' : 'deposit',
        'amount'        => $amount,
        'to_account_id' => (int) $account['id'],
        'description'   => "Deposit to $type",
        'ip'            => $ctx->ip,
    ]);

    AuditEngine::record([
        'type'            => $isSavings ? 'savings_deposit' : 'deposit',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'amount'          => $amount,
        'transaction_id'  => (int) $txn['id'],
        'description'     => 'Deposited KES ' . number_format($amount, 2) .
                             " into $type account {$account['account_number']}",
        'metadata'        => [
            'balance_before' => $before,
            'balance_after'  => $before + $amount,
            'daily_limit'    => $newLimit,
            'reference'      => $txn['reference'],
        ],
    ]);

    Response::json([
        'transaction' => $txn,
        'balance'     => $before + $amount,
        'daily_limit' => $newLimit,
    ], 201);
}

// -------------------------------------------------------------- WITHDRAWAL

function withdraw(array $user, Context $ctx): never
{
    $body = Response::body();
    ['amount' => $amount, 'error' => $error] = Bank::validateAmount($body['amount'] ?? null);
    if ($error) {
        Response::error($error);
    }

    $type = ($body['account_type'] ?? 'checking') === 'savings' ? 'savings' : 'checking';
    $account = Bank::accountsOf((int) $user['id'])[$type];
    if (!$account) {
        Response::error('Account not found', 404);
    }

    // Restricted / unfunded / over-limit are all refused here.
    guardTransaction($user, $account, $ctx, $amount, 'withdrawal');

    $before = (float) $account['balance'];

    // A declined withdrawal is still an audit event — failed attempts matter.
    if ($before < $amount) {
        $txn = Bank::createTransaction([
            'user_id'         => (int) $user['id'],
            'type'            => 'withdrawal',
            'amount'          => $amount,
            'from_account_id' => (int) $account['id'],
            'status'          => 'failed',
            'failure_reason'  => 'Insufficient funds',
            'description'     => 'Insufficient funds',
            'ip'              => $ctx->ip,
        ]);

        AuditEngine::record([
            'type'            => 'transaction_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
            'amount'          => $amount,
            'transaction_id'  => (int) $txn['id'],
            'description'     => 'Withdrawal of KES ' . number_format($amount, 2) .
                                 ' declined — insufficient funds (balance KES ' .
                                 number_format($before, 2) . ')',
            'metadata'        => ['reason' => 'insufficient_funds', 'balance' => $before],
        ]);

        Response::error('Insufficient funds');
    }

    Bank::adjustBalance((int) $account['id'], -$amount);

    $txn = Bank::createTransaction([
        'user_id'         => (int) $user['id'],
        'type'            => 'withdrawal',
        'amount'          => $amount,
        'from_account_id' => (int) $account['id'],
        'description'     => "Withdrawal from $type",
        'ip'              => $ctx->ip,
    ]);

    $result = AuditEngine::record([
        'type'            => 'withdrawal',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'amount'          => $amount,
        'transaction_id'  => (int) $txn['id'],
        'description'     => 'Withdrew KES ' . number_format($amount, 2) .
                             " from $type account {$account['account_number']}",
        'metadata'        => [
            'balance_before' => $before,
            'balance_after'  => $before - $amount,
            'reference'      => $txn['reference'],
        ],
    ]);

    // If the engine raised anything, flag the transaction itself.
    if ($result['alerts']) {
        Database::run("UPDATE transactions SET status = 'flagged' WHERE id = ?", [$txn['id']]);
        $txn['status'] = 'flagged';
    }

    Response::json([
        'transaction' => $txn,
        'balance'     => $before - $amount,
        'flagged'     => (bool) $result['alerts'],
        'alerts'      => $result['alerts'],
    ], 201);
}

// ---------------------------------------------------------------- TRANSFER

function transfer(array $user, Context $ctx): never
{
    $body = Response::body();
    ['amount' => $amount, 'error' => $error] = Bank::validateAmount($body['amount'] ?? null);
    if ($error) {
        Response::error($error);
    }

    $toNumber = trim((string) ($body['to_account_number'] ?? ''));
    if ($toNumber === '') {
        Response::error('A recipient account number is required');
    }

    $from = Bank::accountsOf((int) $user['id'])['checking'];
    $to = Bank::accountByNumber($toNumber);

    if (!$to) {
        Response::error('That recipient account does not exist', 404);
    }
    if ((int) $to['id'] === (int) $from['id']) {
        Response::error('You cannot transfer to your own checking account');
    }

    guardTransaction($user, $from, $ctx, $amount, 'transfer');

    $before = (float) $from['balance'];

    if ($before < $amount) {
        $txn = Bank::createTransaction([
            'user_id'         => (int) $user['id'],
            'type'            => 'transfer',
            'amount'          => $amount,
            'from_account_id' => (int) $from['id'],
            'to_account_id'   => (int) $to['id'],
            'status'          => 'failed',
            'failure_reason'  => 'Insufficient funds',
            'description'     => 'Insufficient funds',
            'ip'              => $ctx->ip,
        ]);

        AuditEngine::record([
            'type'            => 'transaction_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
            'amount'          => $amount,
            'transaction_id'  => (int) $txn['id'],
            'description'     => 'Transfer of KES ' . number_format($amount, 2) .
                                 ' declined — insufficient funds',
            'metadata'        => ['reason' => 'insufficient_funds', 'balance' => $before],
        ]);

        Response::error('Insufficient funds');
    }

    $recipient = Database::one('SELECT full_name FROM users WHERE id = ?', [$to['user_id']]);
    $recipientName = $recipient['full_name'] ?? $to['account_number'];

    // Both legs move or neither does.
    Database::begin();
    try {
        Bank::adjustBalance((int) $from['id'], -$amount);
        Bank::adjustBalance((int) $to['id'], $amount);
        Database::commit();
    } catch (Throwable $e) {
        Database::rollback();
        throw $e;
    }

    $txn = Bank::createTransaction([
        'user_id'         => (int) $user['id'],
        'type'            => 'transfer',
        'amount'          => $amount,
        'from_account_id' => (int) $from['id'],
        'to_account_id'   => (int) $to['id'],
        'counterparty'    => $recipientName,
        'description'     => "Transfer to {$to['account_number']}",
        'ip'              => $ctx->ip,
    ]);

    $result = AuditEngine::record([
        'type'            => 'transfer',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'amount'          => $amount,
        'transaction_id'  => (int) $txn['id'],
        'description'     => 'Transferred KES ' . number_format($amount, 2) .
                             " to $recipientName ({$to['account_number']})",
        'metadata'        => [
            'balance_before'    => $before,
            'balance_after'     => $before - $amount,
            'recipient_account' => $to['account_number'],
            'recipient_name'    => $recipientName,
            'reference'         => $txn['reference'],
        ],
    ]);

    if ($result['alerts']) {
        Database::run("UPDATE transactions SET status = 'flagged' WHERE id = ?", [$txn['id']]);
        $txn['status'] = 'flagged';
    }

    Response::json([
        'transaction' => $txn,
        'balance'     => $before - $amount,
        'flagged'     => (bool) $result['alerts'],
        'alerts'      => $result['alerts'],
    ], 201);
}

// ------------------------------------------------- BILL PAYMENT / AIRTIME

function pay(array $user, Context $ctx): never
{
    $body = Response::body();
    ['amount' => $amount, 'error' => $error] = Bank::validateAmount($body['amount'] ?? null);
    if ($error) {
        Response::error($error);
    }

    $kind = ($body['kind'] ?? 'bill_payment') === 'airtime' ? 'airtime' : 'bill_payment';
    $biller = trim((string) ($body['biller'] ?? '')) ?: ($kind === 'airtime' ? 'Airtime top-up' : 'Biller');

    $from = Bank::accountsOf((int) $user['id'])['checking'];

    guardTransaction($user, $from, $ctx, $amount, $kind);

    $before = (float) $from['balance'];

    if ($before < $amount) {
        Response::error('Insufficient funds');
    }

    Bank::adjustBalance((int) $from['id'], -$amount);

    $txn = Bank::createTransaction([
        'user_id'         => (int) $user['id'],
        'type'            => $kind,
        'amount'          => $amount,
        'from_account_id' => (int) $from['id'],
        'counterparty'    => $biller,
        'description'     => $kind === 'airtime' ? 'Airtime purchase' : "Bill payment: $biller",
        'ip'              => $ctx->ip,
    ]);

    AuditEngine::record([
        'type'            => $kind,
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'amount'          => $amount,
        'transaction_id'  => (int) $txn['id'],
        'description'     => 'Paid KES ' . number_format($amount, 2) . " — $biller",
        'metadata'        => [
            'balance_before' => $before,
            'balance_after'  => $before - $amount,
            'reference'      => $txn['reference'],
        ],
    ]);

    Response::json(['transaction' => $txn, 'balance' => $before - $amount], 201);
}
