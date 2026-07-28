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

// ---------------------------------------------------------------- OVERVIEW

function accounts(array $user, Context $ctx): never
{
    $accounts = Bank::accountsOf((int) $user['id']);

    AuditEngine::record([
        'type'            => 'balance_inquiry',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "\"{$user['username']}\" viewed their account balances",
    ]);

    Response::json(['accounts' => $accounts['all']]);
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

    $isSavings = $type === 'savings';
    $before = (float) $account['balance'];

    Bank::adjustBalance((int) $account['id'], $amount);

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
            'reference'      => $txn['reference'],
        ],
    ]);

    Response::json(['transaction' => $txn, 'balance' => $before + $amount], 201);
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

    $before = (float) $account['balance'];

    // A declined withdrawal is still an audit event — failed attempts matter.
    if ($before < $amount) {
        $txn = Bank::createTransaction([
            'user_id'         => (int) $user['id'],
            'type'            => 'withdrawal',
            'amount'          => $amount,
            'from_account_id' => (int) $account['id'],
            'status'          => 'failed',
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

    $before = (float) $from['balance'];

    if ($before < $amount) {
        $txn = Bank::createTransaction([
            'user_id'         => (int) $user['id'],
            'type'            => 'transfer',
            'amount'          => $amount,
            'from_account_id' => (int) $from['id'],
            'to_account_id'   => (int) $to['id'],
            'status'          => 'failed',
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
