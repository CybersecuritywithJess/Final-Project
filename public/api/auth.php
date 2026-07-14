<?php

/**
 * Authentication API.
 *
 *   POST ?action=register          create a customer account
 *   POST ?action=login             sign in
 *   POST ?action=logout            sign out
 *   GET  ?action=me                the current session's user
 *   POST ?action=change-password
 */

require_once __DIR__ . '/bootstrap.php';

$ctx = Context::fromRequest();

switch (action()) {
    case 'register':
        requireMethod('POST');
        register($ctx);
        break;

    case 'login':
        requireMethod('POST');
        login($ctx);
        break;

    case 'logout':
        requireMethod('POST');
        logout($ctx);
        break;

    case 'me':
        me();
        break;

    case 'change-password':
        requireMethod('POST');
        changePassword($ctx);
        break;

    default:
        Response::error('Unknown action', 404);
}

// ---------------------------------------------------------------- REGISTER

function register(Context $ctx): never
{
    $body = Response::body();

    $username = trim($body['username'] ?? '');
    $fullName = trim($body['full_name'] ?? '');
    $email    = trim($body['email'] ?? '');
    $phone    = trim($body['phone'] ?? '');
    $password = $body['password'] ?? '';

    if ($username === '' || $fullName === '' || $email === '' || $password === '') {
        Response::error('Username, full name, email and password are all required');
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        Response::error('That email address is not valid');
    }
    if (strlen($password) < 8) {
        Response::error('Password must be at least 8 characters');
    }

    $taken = Database::one(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [$username, $email]
    );
    if ($taken) {
        Response::error('That username or email is already registered', 409);
    }

    $userId = Database::insert(
        "INSERT INTO users (username, full_name, email, phone, password_hash, role)
         VALUES (?, ?, ?, ?, ?, 'customer')",
        [$username, $fullName, $email, $phone ?: null, Auth::hash($password)]
    );

    $accounts = Bank::openAccounts($userId);

    AuditEngine::record([
        'type'            => 'user_registered',
        'ctx'             => $ctx,
        'subject_user_id' => $userId,
        'actor'           => ['id' => $userId, 'role' => 'customer'],
        'description'     => "New customer \"$username\" registered and was issued account " .
                             $accounts['checking']['account_number'],
        'metadata'        => [
            'email'    => $email,
            'accounts' => [
                $accounts['checking']['account_number'],
                $accounts['savings']['account_number'],
            ],
        ],
    ]);

    Response::json(['message' => 'Account created. You can sign in now.'], 201);
}

// ------------------------------------------------------------------- LOGIN

function login(Context $ctx): never
{
    $body = Response::body();
    $username = trim($body['username'] ?? '');
    $password = $body['password'] ?? '';

    $user = Database::one(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [$username, $username]
    );

    // Unknown username: still audited, but there is no account to attribute it to.
    if (!$user) {
        AuditEngine::record([
            'type'        => 'login_failed',
            'ctx'         => $ctx,
            'description' => "Failed login for unknown username \"$username\"",
            'metadata'    => ['attempted_username' => $username, 'reason' => 'no_such_user'],
        ]);
        Response::error('Invalid username or password', 401);
    }

    if ($user['status'] === 'locked') {
        AuditEngine::record([
            'type'            => 'login_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "Login attempt on locked account \"{$user['username']}\"",
            'metadata'        => ['reason' => 'account_locked'],
            'signals'         => ['failed_logins' => (int) $user['failed_logins']],
        ]);
        Response::error('This account is locked. Contact an administrator.', 403);
    }

    if ($user['status'] === 'closed') {
        Response::error('This account is closed.', 403);
    }

    // --- wrong password
    if (!Auth::verify($password, $user['password_hash'])) {
        $attempts = (int) $user['failed_logins'] + 1;
        $max = (int) RiskEngine::rule('max_failed_logins');

        Database::run('UPDATE users SET failed_logins = ? WHERE id = ?', [$attempts, $user['id']]);

        AuditEngine::record([
            'type'            => 'login_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "Failed login for \"{$user['username']}\" (attempt $attempts of $max)",
            'metadata'        => ['reason' => 'bad_password', 'attempt' => $attempts],
            'signals'         => ['failed_logins' => $attempts],
        ]);

        // The brute-force rule has already raised its alert; now enforce the lock.
        if ($attempts >= $max) {
            Database::run(
                "UPDATE users SET status = 'locked', locked_at = NOW() WHERE id = ?",
                [$user['id']]
            );

            AuditEngine::record([
                'type'            => 'account_locked',
                'ctx'             => $ctx,
                'subject_user_id' => (int) $user['id'],
                'description'     => "Account \"{$user['username']}\" locked automatically after " .
                                     "$attempts consecutive failed logins",
                'metadata'        => ['failed_attempts' => $attempts, 'threshold' => $max],
            ]);

            Response::error('Account locked after too many failed attempts.', 403);
        }

        Response::error('Invalid username or password', 401);
    }

    // --- success
    $signals = AuditEngine::trackDevice((int) $user['id'], $ctx, $user['home_country']);

    Database::run(
        'UPDATE users SET failed_logins = 0, last_login_at = NOW() WHERE id = ?',
        [$user['id']]
    );

    Auth::login($user);
    $ctx->sessionId = session_id();

    AuditEngine::record([
        'type'            => 'login_success',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "{$user['role']} \"{$user['username']}\" signed in from {$ctx->city}, {$ctx->country}",
        'metadata'        => ['role' => $user['role']],
        'signals'         => $signals,
    ]);

    // The rules above raise the alerts; these events give the timeline its detail.
    if ($signals['is_new_device']) {
        AuditEngine::record([
            'type'            => 'new_device_login',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "First seen: {$ctx->browser} on {$ctx->os} ({$ctx->deviceType})",
            'metadata'        => ['fingerprint' => $ctx->fingerprint],
        ]);
    }
    if ($signals['is_new_country']) {
        AuditEngine::record([
            'type'            => 'new_location_login',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "Login from {$ctx->country}, but the account's home country is " .
                                 $user['home_country'],
            'metadata'        => ['country' => $ctx->country, 'home_country' => $user['home_country']],
        ]);
    }

    Response::json([
        'user' => [
            'id'        => (int) $user['id'],
            'username'  => $user['username'],
            'full_name' => $user['full_name'],
            'email'     => $user['email'],
            'role'      => $user['role'],
        ],
    ]);
}

// ------------------------------------------------------------------ LOGOUT

function logout(Context $ctx): never
{
    $user = Auth::user();

    if ($user) {
        AuditEngine::record([
            'type'            => 'logout',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
            'description'     => "\"{$user['username']}\" signed out",
        ]);
    }

    Auth::logout();
    Response::json(['message' => 'Signed out']);
}

// ---------------------------------------------------------------------- ME

function me(): never
{
    $user = Auth::user();
    if (!$user) {
        Response::error('Not signed in', 401, ['code' => 'NOT_AUTHENTICATED']);
    }
    Response::json(['user' => $user]);
}

// -------------------------------------------------------- CHANGE PASSWORD

function changePassword(Context $ctx): never
{
    $user = Auth::require();
    $body = Response::body();

    $current = $body['current_password'] ?? '';
    $new = $body['new_password'] ?? '';

    if (strlen($new) < 8) {
        Response::error('New password must be at least 8 characters');
    }

    $row = Database::one('SELECT password_hash FROM users WHERE id = ?', [$user['id']]);
    if (!Auth::verify($current, $row['password_hash'])) {
        Response::error('Your current password is incorrect', 401);
    }

    Database::run(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        [Auth::hash($new), $user['id']]
    );

    AuditEngine::record([
        'type'            => 'password_changed',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "\"{$user['username']}\" changed their password",
    ]);

    Response::json(['message' => 'Password updated']);
}
