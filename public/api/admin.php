<?php

/**
 * ADMINISTRATION API.
 *
 *   GET    ?action=users              every user + their risk score
 *   POST   ?action=users              create a user of any role
 *   PATCH  ?action=user&id=           modify / lock / unlock / change role
 *   DELETE ?action=user&id=           delete a user
 *   POST   ?action=reset-password&id=
 *   GET    ?action=rules              the configurable risk thresholds
 *   PATCH  ?action=rule&key=          retune a threshold
 *   GET    ?action=health             system health
 *   GET    ?action=integrity          verify the audit-log hash chain
 *   GET    ?action=analytics
 *
 * Everything here is high-risk by definition, so every route records an audit
 * event. An admin deleting a user is precisely what an auditor must be able to see.
 */

require_once __DIR__ . '/bootstrap.php';

$user = Auth::requireRole('admin');
$ctx = Context::fromRequest();

switch (action()) {
    case 'users':
        method() === 'POST' ? createUser($user, $ctx) : listUsers();
        break;

    case 'user':
        if (method() === 'DELETE') {
            deleteUser($user, $ctx);
        } else {
            requireMethod('PATCH', 'POST');
            updateUser($user, $ctx);
        }
        break;

    case 'reset-password':
        requireMethod('POST');
        resetPassword($user, $ctx);
        break;

    case 'rules':
        listRules();
        break;

    case 'rule':
        requireMethod('PATCH', 'POST');
        updateRule($user, $ctx);
        break;

    case 'health':
        health();
        break;

    case 'integrity':
        verifyIntegrity($user, $ctx);
        break;

    case 'analytics':
        analytics();
        break;

    default:
        Response::error('Unknown action', 404);
}

// ------------------------------------------------------------------- USERS

function listUsers(): never
{
    $users = Database::all("
        SELECT u.id, u.username, u.full_name, u.email, u.phone, u.role, u.status,
               u.failed_logins, u.last_login_at, u.created_at, u.home_country,
               COALESCE(SUM(a.balance), 0) AS total_balance,
               (SELECT COALESCE(MAX(risk_score), 0) FROM audit_events
                 WHERE subject_user_id = u.id
                   AND created_at >= (NOW() - INTERVAL 30 DAY)) AS risk_score
          FROM users u
          LEFT JOIN accounts a ON a.user_id = u.id
         GROUP BY u.id
         ORDER BY u.created_at DESC
    ");

    Response::json(['users' => $users]);
}

function createUser(array $admin, Context $ctx): never
{
    $body = Response::body();

    $username = trim($body['username'] ?? '');
    $fullName = trim($body['full_name'] ?? '');
    $email    = trim($body['email'] ?? '');
    $phone    = trim($body['phone'] ?? '');
    $password = $body['password'] ?? '';
    $role     = $body['role'] ?? 'customer';

    if ($username === '' || $fullName === '' || $email === '' || $password === '') {
        Response::error('Username, full name, email and password are all required');
    }
    if (!in_array($role, ['customer', 'auditor', 'admin'], true)) {
        Response::error('Unknown role');
    }
    if (strlen($password) < 8) {
        Response::error('Password must be at least 8 characters');
    }
    if (Database::one('SELECT id FROM users WHERE username = ? OR email = ?', [$username, $email])) {
        Response::error('That username or email already exists', 409);
    }

    $userId = Database::insert(
        'INSERT INTO users (username, full_name, email, phone, password_hash, role)
         VALUES (?, ?, ?, ?, ?, ?)',
        [$username, $fullName, $email, $phone ?: null, Auth::hash($password), $role]
    );

    if ($role === 'customer') {
        Bank::openAccounts($userId);
    }

    AuditEngine::record([
        'type'            => 'user_created_by_admin',
        'ctx'             => $ctx,
        'subject_user_id' => $userId,
        'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
        'description'     => "Admin \"{$admin['username']}\" created $role account \"$username\"",
        'metadata'        => ['role' => $role, 'email' => $email],
    ]);

    Response::json(['message' => 'User created', 'id' => $userId], 201);
}

function updateUser(array $admin, Context $ctx): never
{
    $id = (int) ($_GET['id'] ?? 0);
    $user = Database::one('SELECT * FROM users WHERE id = ?', [$id]);
    if (!$user) {
        Response::error('User not found', 404);
    }

    $body = Response::body();
    $changes = [];

    if (!empty($body['full_name']) && $body['full_name'] !== $user['full_name']) {
        $changes['full_name'] = trim($body['full_name']);
    }
    if (!empty($body['email']) && $body['email'] !== $user['email']) {
        if (!filter_var($body['email'], FILTER_VALIDATE_EMAIL)) {
            Response::error('That email address is not valid');
        }
        $changes['email'] = trim($body['email']);
    }
    if (isset($body['phone']) && $body['phone'] !== $user['phone']) {
        $changes['phone'] = trim($body['phone']) ?: null;
    }
    if (!empty($body['home_country']) && $body['home_country'] !== $user['home_country']) {
        $changes['home_country'] = trim($body['home_country']);
    }
    if (!empty($body['status']) && $body['status'] !== $user['status']) {
        if (!in_array($body['status'], ['active', 'locked', 'closed'], true)) {
            Response::error('Unknown status');
        }
        $changes['status'] = $body['status'];
    }
    if (!empty($body['role']) && $body['role'] !== $user['role']) {
        if (!in_array($body['role'], ['customer', 'auditor', 'admin'], true)) {
            Response::error('Unknown role');
        }
        $changes['role'] = $body['role'];
    }

    if (!$changes) {
        Response::json(['message' => 'Nothing to change']);
    }

    $sets = implode(', ', array_map(fn($c) => "$c = :$c", array_keys($changes)));

    // Clearing a lock must also reset the counter, or the user re-locks instantly.
    if (($changes['status'] ?? null) === 'active') {
        $sets .= ', failed_logins = 0, locked_at = NULL';
    }

    Database::run("UPDATE users SET $sets WHERE id = :id", $changes + ['id' => $id]);

    // A role change gets its own CRITICAL event — privilege escalation is the
    // single most valuable thing for an auditor to spot.
    if (isset($changes['role'])) {
        AuditEngine::record([
            'type'            => 'role_changed',
            'ctx'             => $ctx,
            'subject_user_id' => $id,
            'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
            'description'     => "Admin \"{$admin['username']}\" changed \"{$user['username']}\" " .
                                 "from {$user['role']} to {$changes['role']}",
            'metadata'        => ['from' => $user['role'], 'to' => $changes['role']],
        ]);
    }

    if (($changes['status'] ?? null) === 'active' && $user['status'] === 'locked') {
        AuditEngine::record([
            'type'            => 'account_unlocked',
            'ctx'             => $ctx,
            'subject_user_id' => $id,
            'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
            'description'     => "Admin \"{$admin['username']}\" unlocked account \"{$user['username']}\"",
            'metadata'        => ['previous_failed_logins' => (int) $user['failed_logins']],
        ]);
    }

    $other = array_diff(array_keys($changes), ['role']);
    if ($other) {
        AuditEngine::record([
            'type'            => 'user_modified',
            'ctx'             => $ctx,
            'subject_user_id' => $id,
            'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
            'description'     => "Admin \"{$admin['username']}\" modified \"{$user['username']}\": " .
                                 implode(', ', $other),
            'metadata'        => [
                'fields' => array_values($other),
                'before' => array_intersect_key($user, array_flip($other)),
                'after'  => array_intersect_key($changes, array_flip($other)),
            ],
        ]);
    }

    Response::json(['message' => 'User updated']);
}

function deleteUser(array $admin, Context $ctx): never
{
    $id = (int) ($_GET['id'] ?? 0);
    $user = Database::one('SELECT * FROM users WHERE id = ?', [$id]);

    if (!$user) {
        Response::error('User not found', 404);
    }
    if ($id === (int) $admin['id']) {
        Response::error('You cannot delete your own account');
    }

    // Record BEFORE the delete. The foreign key is ON DELETE SET NULL, so the
    // audit row survives with the identity preserved in the description.
    AuditEngine::record([
        'type'            => 'user_deleted',
        'ctx'             => $ctx,
        'subject_user_id' => $id,
        'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
        'description'     => "Admin \"{$admin['username']}\" deleted {$user['role']} account " .
                             "\"{$user['username']}\" ({$user['email']})",
        'metadata'        => [
            'deleted_user' => [
                'username'   => $user['username'],
                'full_name'  => $user['full_name'],
                'email'      => $user['email'],
                'role'       => $user['role'],
                'created_at' => $user['created_at'],
            ],
        ],
    ]);

    Database::run('DELETE FROM users WHERE id = ?', [$id]);
    Response::json(['message' => 'User deleted']);
}

function resetPassword(array $admin, Context $ctx): never
{
    $id = (int) ($_GET['id'] ?? 0);
    $user = Database::one('SELECT * FROM users WHERE id = ?', [$id]);
    if (!$user) {
        Response::error('User not found', 404);
    }

    $new = Response::body()['new_password'] ?? '';
    if (strlen($new) < 8) {
        Response::error('Password must be at least 8 characters');
    }

    Database::run(
        "UPDATE users SET password_hash = ?, failed_logins = 0, status = 'active', locked_at = NULL
          WHERE id = ?",
        [Auth::hash($new), $id]
    );

    AuditEngine::record([
        'type'            => 'admin_password_reset',
        'ctx'             => $ctx,
        'subject_user_id' => $id,
        'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
        'description'     => "Admin \"{$admin['username']}\" reset the password for \"{$user['username']}\"",
    ]);

    Response::json(['message' => 'Password reset']);
}

// -------------------------------------------------------------- RISK RULES

function listRules(): never
{
    Response::json(['rules' => Database::all('SELECT * FROM risk_rules ORDER BY rule_key')]);
}

function updateRule(array $admin, Context $ctx): never
{
    $key = $_GET['key'] ?? '';
    $rule = Database::one('SELECT * FROM risk_rules WHERE rule_key = ?', [$key]);
    if (!$rule) {
        Response::error('Unknown rule', 404);
    }

    $value = Response::body()['value'] ?? null;
    if (!is_numeric($value) || (float) $value < 0) {
        Response::error('Value must be a positive number');
    }
    $value = (float) $value;

    Database::run(
        'UPDATE risk_rules SET value = ?, updated_at = NOW(), updated_by = ? WHERE rule_key = ?',
        [$value, $admin['id'], $key]
    );

    AuditEngine::record([
        'type'            => 'risk_rule_changed',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $admin['id'],
        'actor'           => ['id' => (int) $admin['id'], 'role' => $admin['role']],
        'description'     => "Admin \"{$admin['username']}\" changed \"{$rule['label']}\" from " .
                             rtrim(rtrim($rule['value'], '0'), '.') . ' to ' . $value . ' ' . ($rule['unit'] ?? ''),
        'metadata'        => ['rule' => $key, 'from' => (float) $rule['value'], 'to' => $value],
    ]);

    Response::json(['message' => 'Threshold updated']);
}

// ------------------------------------------------------------------ HEALTH

function health(): never
{
    $config = require __DIR__ . '/../../config/config.php';
    $dbName = $config['db']['name'];

    $sizeBytes = (float) Database::value(
        'SELECT COALESCE(SUM(data_length + index_length), 0)
           FROM information_schema.TABLES WHERE table_schema = ?',
        [$dbName]
    );

    $count = fn(string $t) => (int) Database::value("SELECT COUNT(*) FROM $t");

    Response::json([
        'database' => [
            'status'     => 'connected',
            'engine'     => 'MySQL / MariaDB',
            'version'    => Database::value('SELECT VERSION()'),
            'name'       => $dbName,
            'size_bytes' => $sizeBytes,
        ],
        'server' => [
            'status'      => 'running',
            'php_version' => PHP_VERSION,
            'memory_mb'   => round(memory_get_usage(true) / 1048576, 1),
        ],
        'tables' => [
            'users'        => $count('users'),
            'accounts'     => $count('accounts'),
            'transactions' => $count('transactions'),
            'audit_events' => $count('audit_events'),
            'alerts'       => $count('alerts'),
            'devices'      => $count('devices'),
        ],
        'active_sessions' => (int) Database::value(
            'SELECT COUNT(DISTINCT session_id) FROM audit_events
              WHERE session_id IS NOT NULL AND created_at >= (NOW() - INTERVAL 30 MINUTE)'
        ),
    ]);
}

// --------------------------------------------------------------- INTEGRITY

/**
 * Recompute the audit-log hash chain and report whether it is intact. The check
 * is itself an audit event — verifying the log is an accountable action too.
 */
function verifyIntegrity(array $admin, Context $ctx): never
{
    $result = AuditEngine::verifyChain();

    AuditEngine::record([
        'type'        => 'integrity_verified',
        'ctx'         => $ctx,
        'actor'       => ['id' => (int) $admin['id'], 'role' => $admin['role']],
        'description' => $result['ok']
            ? "Admin \"{$admin['username']}\" verified the audit log — {$result['checked']} events intact"
            : "Admin \"{$admin['username']}\" ran an integrity check — TAMPERING DETECTED at "
              . ($result['first_broken']['audit_ref'] ?? 'unknown'),
        'metadata'    => [
            'checked'      => $result['checked'],
            'ok'           => $result['ok'],
            'first_broken' => $result['first_broken'],
        ],
    ]);

    Response::json($result);
}

// --------------------------------------------------------------- ANALYTICS

function analytics(): never
{
    Response::json([
        'totals' => [
            'deposits' => (float) Database::value(
                "SELECT COALESCE(SUM(amount), 0) FROM transactions
                  WHERE type IN ('deposit', 'savings_deposit') AND status <> 'failed'"
            ),
            'withdrawals' => (float) Database::value(
                "SELECT COALESCE(SUM(amount), 0) FROM transactions
                  WHERE type = 'withdrawal' AND status <> 'failed'"
            ),
            'transfers' => (float) Database::value(
                "SELECT COALESCE(SUM(amount), 0) FROM transactions
                  WHERE type = 'transfer' AND status <> 'failed'"
            ),
        ],

        'fraud_trend' => Database::all("
            SELECT DATE(created_at) AS day, COUNT(*) AS alerts,
                   SUM(risk_level = 'CRITICAL') AS critical
              FROM alerts WHERE created_at >= (NOW() - INTERVAL 13 DAY)
             GROUP BY day ORDER BY day
        "),

        'alerts_by_rule' => Database::all("
            SELECT rule_key, COUNT(*) AS count,
                   SUM(status = 'confirmed_fraud') AS confirmed,
                   SUM(status = 'false_positive')  AS false_positives
              FROM alerts GROUP BY rule_key ORDER BY count DESC
        "),

        'busiest_staff' => Database::all("
            SELECT u.username, u.role, COUNT(e.id) AS actions
              FROM audit_events e JOIN users u ON u.id = e.actor_user_id
             WHERE u.role IN ('auditor', 'admin')
             GROUP BY u.id ORDER BY actions DESC LIMIT 5
        "),
    ]);
}
