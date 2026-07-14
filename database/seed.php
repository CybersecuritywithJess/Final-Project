<?php

/**
 * Seeds a believable two weeks of banking history: ordinary activity for most
 * customers, plus five planted incidents so the auditor dashboard has something
 * real to investigate the moment you open it.
 *
 *   php database/seed.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/RiskEngine.php';
require_once __DIR__ . '/../src/Context.php';
require_once __DIR__ . '/../src/Auth.php';

const PASSWORD = 'Password123!';

$pdo = Database::connect();

echo "Clearing existing data...\n";
$pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
foreach (['alert_notes', 'alerts', 'audit_events', 'transactions', 'devices', 'accounts', 'users'] as $table) {
    $pdo->exec("TRUNCATE TABLE $table");
}
$pdo->exec('SET FOREIGN_KEY_CHECKS = 1');

$hash = password_hash(PASSWORD, PASSWORD_BCRYPT, ['cost' => 10]);  // cost 10 keeps seeding quick

// ------------------------------------------------------------------ helpers

$DEVICES = [
    ['browser' => 'Chrome',  'os' => 'Windows', 'device_type' => 'desktop'],
    ['browser' => 'Safari',  'os' => 'iOS',     'device_type' => 'mobile'],
    ['browser' => 'Firefox', 'os' => 'Linux',   'device_type' => 'desktop'],
    ['browser' => 'Edge',    'os' => 'Windows', 'device_type' => 'desktop'],
    ['browser' => 'Chrome',  'os' => 'Android', 'device_type' => 'mobile'],
];

function pick(array $a) { return $a[array_rand($a)]; }
function money(int $min, int $max): float { return (float) (round(random_int($min, $max) / 50) * 50); }

/** A timestamp `$daysAgo` days back, at the given hour — MySQL DATETIME format. */
function at(int $daysAgo, ?int $hour = null, ?int $minute = null): string
{
    $hour ??= random_int(7, 21);
    $minute ??= random_int(0, 59);
    $ts = strtotime("-$daysAgo days");
    return date('Y-m-d', $ts) . sprintf(' %02d:%02d:%02d', $hour, $minute, random_int(0, 59));
}

/** Like AuditEngine::record(), but backdated — history has to look like history. */
function emit(array $e): int
{
    $scored = RiskEngine::score($e['type'], [
        'amount'        => $e['amount'] ?? null,
        'failed_logins' => $e['failed_logins'] ?? 0,
    ]);

    $device = $e['device'] ?? ['browser' => 'Chrome', 'os' => 'Windows', 'device_type' => 'desktop'];
    $actor = $e['actor'] ?? $e['user'] ?? null;

    $id = Database::insert(
        "INSERT INTO audit_events
            (audit_ref, event_type, category, description, subject_user_id, actor_user_id,
             actor_role, risk_level, risk_score, transaction_id, amount, ip_address,
             browser, os, device_type, country, city, metadata, created_at)
         VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            $e['type'],
            $scored['category'],
            $e['description'] ?? $scored['label'],
            $e['user']['id'] ?? null,
            $actor['id'] ?? null,
            $actor['role'] ?? null,
            $scored['level'],
            $scored['score'],
            $e['transaction_id'] ?? null,
            $e['amount'] ?? null,
            $e['ip'] ?? '41.90.64.12',
            $device['browser'],
            $device['os'],
            $device['device_type'],
            $e['country'] ?? 'Kenya',
            $e['city'] ?? 'Nairobi',
            json_encode($e['metadata'] ?? []),
            $e['when'],
        ]
    );

    Database::run('UPDATE audit_events SET audit_ref = ? WHERE id = ?',
        ['AUD-' . str_pad((string) $id, 6, '0', STR_PAD_LEFT), $id]);

    return $id;
}

function raiseAlert(array $a): int
{
    $id = Database::insert(
        "INSERT INTO alerts (alert_ref, audit_event_id, user_id, rule_key, title, description,
                             risk_level, status, assigned_to, created_at, updated_at)
         VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            $a['event_id'],
            $a['user']['id'],
            $a['rule_key'],
            $a['title'],
            $a['description'],
            $a['risk_level'],
            $a['status'] ?? 'new',
            $a['assigned_to'] ?? null,
            $a['when'],
            $a['when'],
        ]
    );

    Database::run('UPDATE alerts SET alert_ref = ? WHERE id = ?',
        ['ALR-' . str_pad((string) $id, 6, '0', STR_PAD_LEFT), $id]);

    return $id;
}

function txn(array $t): int
{
    $id = Database::insert(
        "INSERT INTO transactions (reference, user_id, type, amount, from_account_id, to_account_id,
                                   counterparty, status, description, ip_address, created_at)
         VALUES ('PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            $t['user']['id'],
            $t['type'],
            $t['amount'],
            $t['from'] ?? null,
            $t['to'] ?? null,
            $t['counterparty'] ?? null,
            $t['status'] ?? 'completed',
            $t['description'] ?? null,
            $t['ip'] ?? '41.90.64.12',
            $t['when'],
        ]
    );

    Database::run('UPDATE transactions SET reference = ? WHERE id = ?',
        ['TXN-' . str_pad((string) $id, 6, '0', STR_PAD_LEFT), $id]);

    return $id;
}

// -------------------------------------------------------------------- users

echo "Creating users...\n";

$makeUser = function (array $u) use ($hash): array {
    $id = Database::insert(
        'INSERT INTO users (username, full_name, email, phone, password_hash, role, status,
                            home_country, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
            $u['username'], $u['full_name'], $u['email'], $u['phone'], $hash,
            $u['role'], $u['status'] ?? 'active', $u['home_country'] ?? 'Kenya',
            at(random_int(20, 60)), at(random_int(0, 2)),
        ]
    );

    $user = ['id' => $id, 'username' => $u['username'], 'full_name' => $u['full_name'], 'role' => $u['role']];

    if ($u['role'] === 'customer') {
        $base = 1000000000 + $id * 100;
        Database::run(
            "INSERT INTO accounts (user_id, account_number, type, balance) VALUES (?, ?, 'checking', ?)",
            [$id, (string) ($base + 1), money(80000, 900000)]
        );
        Database::run(
            "INSERT INTO accounts (user_id, account_number, type, balance) VALUES (?, ?, 'savings', ?)",
            [$id, (string) ($base + 2), money(10000, 400000)]
        );

        foreach (Database::all('SELECT * FROM accounts WHERE user_id = ?', [$id]) as $a) {
            $user[$a['type']] = $a;
        }
    }

    return $user;
};

$admin = $makeUser([
    'username' => 'admin', 'full_name' => 'Grace Wanjiru',
    'email' => 'admin@demobank.co.ke', 'phone' => '+254700000001', 'role' => 'admin',
]);

$auditor = $makeUser([
    'username' => 'auditor', 'full_name' => 'Samuel Otieno',
    'email' => 'auditor@demobank.co.ke', 'phone' => '+254700000002', 'role' => 'auditor',
]);

$customers = [
    $makeUser(['username' => 'john123', 'full_name' => 'John Kamau',    'email' => 'john@example.com',  'phone' => '+254712345678', 'role' => 'customer']),
    $makeUser(['username' => 'mary_w',  'full_name' => 'Mary Wambui',   'email' => 'mary@example.com',  'phone' => '+254723456789', 'role' => 'customer']),
    $makeUser(['username' => 'peter_o', 'full_name' => 'Peter Ochieng', 'email' => 'peter@example.com', 'phone' => '+254734567890', 'role' => 'customer']),
    $makeUser(['username' => 'faith_n', 'full_name' => 'Faith Njeri',   'email' => 'faith@example.com', 'phone' => '+254745678901', 'role' => 'customer']),
    $makeUser(['username' => 'david_k', 'full_name' => 'David Kiptoo',  'email' => 'david@example.com', 'phone' => '+254756789012', 'role' => 'customer']),
    $makeUser(['username' => 'aisha_h', 'full_name' => 'Aisha Hassan',  'email' => 'aisha@example.com', 'phone' => '+254767890123', 'role' => 'customer']),
];

// Registration event + a known device, so every timeline starts at the beginning.
foreach ($customers as $i => $c) {
    emit([
        'type' => 'user_registered',
        'user' => $c,
        'description' => "New customer \"{$c['username']}\" registered and was issued account " .
                         $c['checking']['account_number'],
        'when' => at(random_int(20, 40)),
        'metadata' => ['accounts' => [$c['checking']['account_number'], $c['savings']['account_number']]],
    ]);

    $d = $DEVICES[$i % count($DEVICES)];
    Database::run(
        "INSERT INTO devices (user_id, fingerprint, browser, os, device_type, last_ip, last_country, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, '41.90.64.12', 'Kenya', ?, ?)",
        [
            $c['id'],
            Context::fingerprint($d['browser'], $d['os'], $d['device_type']),
            $d['browser'], $d['os'], $d['device_type'],
            at(30), at(0),
        ]
    );
    $customers[$i]['device'] = $d;
}

// ------------------------------------------------- 14 days of normal activity

echo "Generating 14 days of normal banking activity...\n";

$BILLERS = ['KPLC Prepaid', 'Nairobi Water', 'DSTV', 'Safaricom Home', 'NHIF'];

for ($day = 13; $day >= 0; $day--) {
    foreach ($customers as $c) {
        if (random_int(1, 100) <= 25) {
            continue;   // not everyone banks every day
        }

        $hour = random_int(7, 21);

        emit([
            'type' => 'login_success',
            'user' => $c,
            'actor' => $c,
            'description' => "customer \"{$c['username']}\" signed in from Nairobi, Kenya",
            'when' => at($day, $hour, 0),
            'device' => $c['device'],
            'metadata' => ['role' => 'customer'],
        ]);

        // The occasional fat-fingered password.
        if (random_int(1, 100) <= 12) {
            emit([
                'type' => 'login_failed',
                'user' => $c,
                'description' => "Failed login for \"{$c['username']}\" (attempt 1 of 5)",
                'when' => at($day, $hour, random_int(0, 4)),
                'device' => $c['device'],
                'failed_logins' => 1,
                'metadata' => ['reason' => 'bad_password', 'attempt' => 1],
            ]);
        }

        for ($i = 0, $n = random_int(1, 3); $i < $n; $i++) {
            $when = at($day, $hour, random_int(5, 55));
            $roll = random_int(1, 100);

            if ($roll <= 30) {
                $amount = money(2000, 60000);
                $id = txn(['user' => $c, 'type' => 'deposit', 'amount' => $amount,
                           'to' => $c['checking']['id'], 'description' => 'Deposit to checking', 'when' => $when]);
                emit(['type' => 'deposit', 'user' => $c, 'amount' => $amount, 'transaction_id' => $id,
                      'when' => $when, 'device' => $c['device'],
                      'description' => 'Deposited KES ' . number_format($amount, 2) .
                                       " into checking account {$c['checking']['account_number']}"]);

            } elseif ($roll <= 55) {
                $amount = money(1000, 40000);
                $id = txn(['user' => $c, 'type' => 'withdrawal', 'amount' => $amount,
                           'from' => $c['checking']['id'], 'description' => 'Withdrawal from checking', 'when' => $when]);
                emit(['type' => 'withdrawal', 'user' => $c, 'amount' => $amount, 'transaction_id' => $id,
                      'when' => $when, 'device' => $c['device'],
                      'description' => 'Withdrew KES ' . number_format($amount, 2) .
                                       " from checking account {$c['checking']['account_number']}",
                      'metadata' => ['balance_before' => (float) $c['checking']['balance']]]);

            } elseif ($roll <= 75) {
                $others = array_values(array_filter($customers, fn($x) => $x['id'] !== $c['id']));
                $to = pick($others);
                $amount = money(500, 45000);
                $id = txn(['user' => $c, 'type' => 'transfer', 'amount' => $amount,
                           'from' => $c['checking']['id'], 'to' => $to['checking']['id'],
                           'counterparty' => $to['full_name'],
                           'description' => "Transfer to {$to['checking']['account_number']}", 'when' => $when]);
                emit(['type' => 'transfer', 'user' => $c, 'amount' => $amount, 'transaction_id' => $id,
                      'when' => $when, 'device' => $c['device'],
                      'description' => 'Transferred KES ' . number_format($amount, 2) .
                                       " to {$to['full_name']} ({$to['checking']['account_number']})",
                      'metadata' => ['recipient_account' => $to['checking']['account_number'],
                                     'recipient_name' => $to['full_name']]]);

            } elseif ($roll <= 85) {
                $amount = money(500, 15000);
                $biller = pick($BILLERS);
                $id = txn(['user' => $c, 'type' => 'bill_payment', 'amount' => $amount,
                           'from' => $c['checking']['id'], 'counterparty' => $biller,
                           'description' => "Bill payment: $biller", 'when' => $when]);
                emit(['type' => 'bill_payment', 'user' => $c, 'amount' => $amount, 'transaction_id' => $id,
                      'when' => $when, 'device' => $c['device'],
                      'description' => 'Paid KES ' . number_format($amount, 2) . " — $biller"]);

            } elseif ($roll <= 93) {
                $amount = money(100, 2000);
                $id = txn(['user' => $c, 'type' => 'airtime', 'amount' => $amount,
                           'from' => $c['checking']['id'], 'counterparty' => 'Airtime top-up',
                           'description' => 'Airtime purchase', 'when' => $when]);
                emit(['type' => 'airtime', 'user' => $c, 'amount' => $amount, 'transaction_id' => $id,
                      'when' => $when, 'device' => $c['device'],
                      'description' => 'Paid KES ' . number_format($amount, 2) . ' — airtime']);

            } else {
                $amount = money(5000, 50000);
                $id = txn(['user' => $c, 'type' => 'savings_deposit', 'amount' => $amount,
                           'to' => $c['savings']['id'], 'description' => 'Deposit to savings', 'when' => $when]);
                emit(['type' => 'savings_deposit', 'user' => $c, 'amount' => $amount, 'transaction_id' => $id,
                      'when' => $when, 'device' => $c['device'],
                      'description' => 'Deposited KES ' . number_format($amount, 2) .
                                       " into savings account {$c['savings']['account_number']}"]);
            }
        }

        emit(['type' => 'logout', 'user' => $c, 'actor' => $c,
              'description' => "\"{$c['username']}\" signed out",
              'when' => at($day, $hour, random_int(56, 59)), 'device' => $c['device']]);
    }
}

// Staff do their rounds too.
for ($day = 6; $day >= 0; $day--) {
    emit(['type' => 'login_success', 'user' => $auditor, 'actor' => $auditor,
          'description' => 'auditor "auditor" signed in from Nairobi, Kenya', 'when' => at($day, 8, 30)]);
    emit(['type' => 'login_success', 'user' => $admin, 'actor' => $admin,
          'description' => 'admin "admin" signed in from Nairobi, Kenya', 'when' => at($day, 9, 0)]);
}

// -------------------------------------------------------- planted incidents

echo "Planting security incidents...\n";

[$john, $mary, $peter, $faith, $david] = $customers;

// --- 1. Brute force from a foreign IP, ending in an automatic lockout.
$bruteIp = '185.220.101.34';
$bruteDevice = ['browser' => 'Firefox', 'os' => 'Linux', 'device_type' => 'desktop'];
$lastFail = 0;

for ($i = 1; $i <= 6; $i++) {
    $lastFail = emit([
        'type' => 'login_failed',
        'user' => $john,
        'description' => "Failed login for \"john123\" (attempt $i of 5)",
        'when' => at(0, 9, 15 + $i),
        'ip' => $bruteIp, 'country' => 'Russia', 'city' => 'Moscow', 'device' => $bruteDevice,
        'failed_logins' => $i,
        'metadata' => ['reason' => 'bad_password', 'attempt' => $i],
    ]);
}

emit([
    'type' => 'account_locked',
    'user' => $john,
    'description' => 'Account "john123" locked automatically after 6 consecutive failed logins',
    'when' => at(0, 9, 22),
    'ip' => $bruteIp, 'country' => 'Russia', 'city' => 'Moscow', 'device' => $bruteDevice,
    'metadata' => ['failed_attempts' => 6, 'threshold' => 5],
]);

Database::run(
    "UPDATE users SET status = 'locked', failed_logins = 6, locked_at = ? WHERE id = ?",
    [at(0, 9, 22), $john['id']]
);

raiseAlert([
    'event_id' => $lastFail, 'user' => $john, 'rule_key' => 'brute_force',
    'title' => 'Possible brute-force attack',
    'description' => "6 failed login attempts in the last 10 minutes from IP $bruteIp. The account has been locked.",
    'risk_level' => 'CRITICAL', 'when' => at(0, 9, 22),
]);

// --- 2. Impossible travel, then the account is drained.
$foreignDevice = ['browser' => 'Chrome', 'os' => 'Android', 'device_type' => 'mobile'];

$travelEvent = emit([
    'type' => 'new_location_login',
    'user' => $mary,
    'description' => "Login from Nigeria, but the account's home country is Kenya",
    'when' => at(0, 2, 14),
    'ip' => '105.112.44.9', 'country' => 'Nigeria', 'city' => 'Lagos', 'device' => $foreignDevice,
    'metadata' => ['country' => 'Nigeria', 'home_country' => 'Kenya'],
]);

raiseAlert([
    'event_id' => $travelEvent, 'user' => $mary, 'rule_key' => 'new_country',
    'title' => 'Login from a new country',
    'description' => "Login from Lagos, Nigeria — the account's home country is Kenya. Impossible-travel risk.",
    'risk_level' => 'CRITICAL', 'status' => 'under_investigation',
    'assigned_to' => $auditor['id'], 'when' => at(0, 2, 14),
]);

$drain = 850000.0;
$drainTxn = txn([
    'user' => $mary, 'type' => 'withdrawal', 'amount' => $drain,
    'from' => $mary['checking']['id'], 'status' => 'flagged',
    'description' => 'Withdrawal from checking', 'when' => at(0, 2, 19), 'ip' => '105.112.44.9',
]);

$drainEvent = emit([
    'type' => 'withdrawal',
    'user' => $mary,
    'amount' => $drain,
    'transaction_id' => $drainTxn,
    'description' => 'Withdrew KES ' . number_format($drain, 2) .
                     " from checking account {$mary['checking']['account_number']}",
    'when' => at(0, 2, 19),
    'ip' => '105.112.44.9', 'country' => 'Nigeria', 'city' => 'Lagos', 'device' => $foreignDevice,
    'metadata' => ['balance_before' => 900000, 'balance_after' => 50000],
]);

raiseAlert([
    'event_id' => $drainEvent, 'user' => $mary, 'rule_key' => 'large_withdrawal',
    'title' => 'Large withdrawal detected',
    'description' => 'Withdrawal of KES 850,000 is at or above the KES 500,000 review threshold.',
    'risk_level' => 'CRITICAL', 'status' => 'under_investigation',
    'assigned_to' => $auditor['id'], 'when' => at(0, 2, 19),
]);

raiseAlert([
    'event_id' => $drainEvent, 'user' => $mary, 'rule_key' => 'account_drain',
    'title' => 'Account nearly emptied',
    'description' => 'Withdrawal of KES 850,000 removed 94.4% of the available balance (KES 900,000).',
    'risk_level' => 'HIGH', 'when' => at(0, 2, 19),
]);

// --- 3. Rapid transfers — structuring behaviour.
$rapidEvent = 0;
for ($i = 0; $i < 4; $i++) {
    $amount = 95000.0;
    $id = txn([
        'user' => $peter, 'type' => 'transfer', 'amount' => $amount,
        'from' => $peter['checking']['id'], 'to' => $faith['checking']['id'],
        'counterparty' => $faith['full_name'], 'status' => 'flagged',
        'description' => "Transfer to {$faith['checking']['account_number']}",
        'when' => at(1, 23, 40 + $i),
    ]);

    $rapidEvent = emit([
        'type' => 'transfer', 'user' => $peter, 'amount' => $amount, 'transaction_id' => $id,
        'description' => 'Transferred KES ' . number_format($amount, 2) .
                         " to {$faith['full_name']} ({$faith['checking']['account_number']})",
        'when' => at(1, 23, 40 + $i), 'device' => $peter['device'],
        'metadata' => ['recipient_account' => $faith['checking']['account_number'],
                       'recipient_name' => $faith['full_name']],
    ]);
}

raiseAlert([
    'event_id' => $rapidEvent, 'user' => $peter, 'rule_key' => 'rapid_transfers',
    'title' => 'Rapid successive transfers',
    'description' => '4 transfers totalling KES 380,000 within 1 minute(s). ' .
                     'This pattern is consistent with account takeover or structuring.',
    'risk_level' => 'HIGH', 'when' => at(1, 23, 44),
]);

// --- 4. A new-device login that turned out to be benign. Auditors need a
//        false positive to close — that is what real triage looks like.
$newDevEvent = emit([
    'type' => 'new_device_login',
    'user' => $david,
    'description' => 'First seen: Safari on macOS (desktop)',
    'when' => at(3, 14, 5),
    'device' => ['browser' => 'Safari', 'os' => 'macOS', 'device_type' => 'desktop'],
    'metadata' => ['fingerprint' => Context::fingerprint('Safari', 'macOS', 'desktop')],
]);

$fpAlert = raiseAlert([
    'event_id' => $newDevEvent, 'user' => $david, 'rule_key' => 'new_device',
    'title' => 'Login from a new device',
    'description' => 'First login from Safari on macOS (desktop) at IP 41.90.64.12.',
    'risk_level' => 'MEDIUM', 'status' => 'false_positive',
    'assigned_to' => $auditor['id'], 'when' => at(3, 14, 5),
]);

Database::run(
    'INSERT INTO alert_notes (alert_id, auditor_id, finding, recommendation, created_at)
     VALUES (?, ?, ?, ?, ?)',
    [
        $fpAlert,
        $auditor['id'],
        'Contacted the customer by phone. He confirmed he had bought a new MacBook and signed in ' .
        'from home. The IP address and location match his usual pattern, and no unusual transactions ' .
        'followed the login.',
        'No action required. Recommend the customer enables MFA so future device changes are ' .
        'self-verifying.',
        at(3, 16, 30),
    ]
);

// --- 5. An admin action worth auditing.
emit([
    'type' => 'risk_rule_changed',
    'user' => $admin,
    'actor' => $admin,
    'description' => 'Admin "admin" changed "Large withdrawal threshold" from 750000 to 500000 KES',
    'when' => at(5, 11, 20),
    'metadata' => ['rule' => 'large_withdrawal_threshold', 'from' => 750000, 'to' => 500000],
]);

// ----------------------------------------------------------------- summary

$count = fn(string $t) => Database::value("SELECT COUNT(*) FROM $t");

echo "\n  Seed complete.\n\n";
echo "    Users .............. " . $count('users') . "\n";
echo "    Accounts ........... " . $count('accounts') . "\n";
echo "    Transactions ....... " . $count('transactions') . "\n";
echo "    Audit events ....... " . $count('audit_events') . "\n";
echo "    Fraud alerts ....... " . $count('alerts') . "\n\n";
echo "  Sign in with any of these — the password for every account is: " . PASSWORD . "\n\n";
echo "    admin      Administrator — manage users, tune risk thresholds\n";
echo "    auditor    Auditor — dashboard, audit log, investigations\n";
echo "    mary_w     Customer — 2 CRITICAL alerts against her (impossible travel + drained account)\n";
echo "    peter_o    Customer — flagged for rapid transfers\n";
echo "    john123    Customer — LOCKED by the brute-force rule (unlock him as admin)\n";
echo "    faith_n    Customer — clean history, good for making fresh transactions\n\n";
