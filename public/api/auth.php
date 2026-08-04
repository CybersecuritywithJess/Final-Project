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
require_once __DIR__ . '/../../src/GoogleAuth.php';
require_once __DIR__ . '/../../src/SecurityEngine.php';

$ctx = Context::fromRequest();

switch (action()) {
    case 'config':
        // The login page asks this before deciding whether to draw the Google button.
        Response::json([
            'google' => [
                'enabled'   => GoogleAuth::enabled(),
                'client_id' => GoogleAuth::clientId(),
            ],
        ]);
        break;

    case 'google':
        requireMethod('POST');
        googleSignIn($ctx);
        break;

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
    $role     = $body['role'] ?? 'customer';

    if ($username === '' || $fullName === '' || $email === '' || $password === '') {
        Response::error('Username, full name, email and password are all required');
    }
    if (!in_array($role, ['customer', 'auditor', 'admin'], true)) {
        Response::error('Please choose a valid role');
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
        'INSERT INTO users (username, full_name, email, phone, password_hash, role)
         VALUES (?, ?, ?, ?, ?, ?)',
        [$username, $fullName, $email, $phone ?: null, Auth::hash($password), $role]
    );

    // Only Demo Bank users get accounts; auditors and admins never bank here.
    $accounts = $role === 'customer' ? Bank::openAccounts($userId) : null;

    $descr = $role === 'customer'
        ? "New customer \"$username\" registered and was issued account " . $accounts['checking']['account_number']
        : "New $role \"$username\" registered";

    AuditEngine::record([
        'type'            => 'user_registered',
        'ctx'             => $ctx,
        'subject_user_id' => $userId,
        'actor'           => ['id' => $userId, 'role' => $role],
        'description'     => $descr,
        'metadata'        => array_filter([
            'role'     => $role,
            'email'    => $email,
            'accounts' => $accounts ? [
                $accounts['checking']['account_number'],
                $accounts['savings']['account_number'],
            ] : null,
        ]),
    ]);

    // Sign them straight in so they land on their role's home page.
    $user = Database::one('SELECT * FROM users WHERE id = ?', [$userId]);
    Auth::login($user);

    Response::json([
        'user' => [
            'id'        => $userId,
            'username'  => $username,
            'full_name' => $fullName,
            'email'     => $email,
            'role'      => $role,
        ],
    ], 201);
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
        SecurityEngine::recordLoginAttempt(null, $username, $ctx, 'FAILED', 'no_such_user');
        AuditEngine::record([
            'type'        => 'login_failed',
            'ctx'         => $ctx,
            'description' => "Failed login for unknown username \"$username\"",
            'metadata'    => ['attempted_username' => $username, 'reason' => 'no_such_user'],
        ]);
        Response::error('Invalid username or password', 401);
    }

    // Where the login controls currently stand. An expired timed lock is cleared
    // inside here, so the account gets its chance back without anyone's help.
    $lock = SecurityEngine::checkLockout($user);

    if ($lock['locked']) {
        SecurityEngine::recordLoginAttempt(
            (int) $user['id'],
            $username,
            $ctx,
            'FAILED',
            $lock['permanent'] ? 'security_locked' : 'locked_out'
        );

        AuditEngine::record([
            'type'            => 'login_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "Login attempt on locked account \"{$user['username']}\"",
            'metadata'        => [
                'reason'       => $lock['permanent'] ? 'security_locked' : 'temporarily_locked',
                'seconds_left' => $lock['seconds_left'],
            ],
            'signals'         => ['failed_logins' => (int) $user['failed_logins']],
        ]);

        if ($lock['permanent']) {
            Response::error(
                'Your account has been secured due to repeated unsuccessful login attempts. '
                . 'Please visit your nearest bank branch for verification.',
                403,
                ['code' => 'SECURITY_LOCKED']
            );
        }

        $minutes = (int) ceil($lock['seconds_left'] / 60);
        Response::error(
            'Too many unsuccessful login attempts have been detected. Please try again in '
            . ($minutes <= 1 ? 'a moment' : "$minutes minutes") . '.',
            403,
            ['code' => 'TEMPORARILY_LOCKED', 'seconds_left' => $lock['seconds_left']]
        );
    }

    // checkLockout may have just cleared an expired lock — work from fresh state.
    $user = Database::one('SELECT * FROM users WHERE id = ?', [$user['id']]);

    if ($user['status'] === 'closed') {
        SecurityEngine::recordLoginAttempt((int) $user['id'], $username, $ctx, 'FAILED', 'account_closed');
        Response::error('This account is closed.', 403);
    }

    // A Google-only account has no password to check against. Point them at the
    // right door instead of letting an empty password compare against NULL.
    if ($user['password_hash'] === null) {
        Response::error('This account uses Google sign-in. Please use "Continue with Google".', 400);
    }

    // --- wrong password
    if (!Auth::verify($password, $user['password_hash'])) {
        $attempts = (int) $user['failed_logins'] + 1;

        // An account that has been locked out before is held to a shorter leash.
        $max = SecurityEngine::failureThreshold($user);
        $warned = SecurityEngine::hasBeenWarned($user);

        Database::run('UPDATE users SET failed_logins = ? WHERE id = ?', [$attempts, $user['id']]);
        SecurityEngine::recordLoginAttempt((int) $user['id'], $username, $ctx, 'FAILED', 'bad_password');

        AuditEngine::record([
            'type'            => 'login_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "Failed login for \"{$user['username']}\" (attempt $attempts of $max"
                                 . ($warned ? ', after a previous lockout' : '') . ')',
            'metadata'        => [
                'reason'  => 'bad_password',
                'attempt' => $attempts,
                'stage'   => $warned ? 'post_lockout' : 'initial',
            ],
            'signals'         => ['failed_logins' => $attempts],
        ]);

        // The brute-force rule has already raised its alert; now enforce the lock.
        // A first offence buys a couple of minutes and a warning; failing again
        // after that warning earns a lock only an administrator can lift.
        if ($attempts >= $max) {
            $lock = SecurityEngine::lockUser($user, $ctx, $attempts);

            AuditEngine::record([
                'type'            => 'account_locked',
                'ctx'             => $ctx,
                'subject_user_id' => (int) $user['id'],
                'description'     => "Account \"{$user['username']}\" locked automatically after " .
                                     "$attempts consecutive failed logins",
                'metadata'        => [
                    'failed_attempts' => $attempts,
                    'threshold'       => $max,
                    'permanent'       => $lock['permanent'],
                    'lockout_cycle'   => $lock['cycle'],
                ],
            ]);

            if ($lock['permanent']) {
                Response::error(
                    'Your account has been secured due to repeated unsuccessful login attempts. '
                    . 'Please visit your nearest bank branch for verification.',
                    403,
                    ['code' => 'SECURITY_LOCKED']
                );
            }

            Response::error(
                'Too many unsuccessful login attempts have been detected. Your account has been '
                . "temporarily locked. Please try again after {$lock['minutes']} minutes.",
                403,
                [
                    'code'         => 'TEMPORARILY_LOCKED',
                    'seconds_left' => $lock['minutes'] * 60,
                    // What it costs them to keep going once the lock lifts.
                    'next_threshold' => (int) RiskEngine::rule('post_lockout_failures'),
                ]
            );
        }

        // Once an account has been warned, tell it how little room is left —
        // the next lock is permanent, so a silent countdown would be unfair.
        if ($warned) {
            $left = $max - $attempts;
            Response::error(
                'Invalid username or password. ' . ($left === 1
                    ? 'One more failed attempt will secure your account and require branch verification.'
                    : "$left more failed attempts will secure your account."),
                401,
                ['code' => 'POST_LOCKOUT_WARNING', 'attempts_left' => $left]
            );
        }

        Response::error('Invalid username or password', 401);
    }

    // The password is correct. If they declared a role, it must be the account's
    // real role — checked only after authentication, so it never leaks a role to
    // someone who doesn't already hold the password. No session is created on a
    // mismatch, and it is not treated as a failed password (no lockout).
    $declaredRole = $body['role'] ?? '';
    if ($declaredRole !== '' && $declaredRole !== $user['role']) {
        AuditEngine::record([
            'type'            => 'login_failed',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "\"{$user['username']}\" signed in as \"$declaredRole\" but the account is \"{$user['role']}\"",
            'metadata'        => ['reason' => 'role_mismatch', 'declared' => $declaredRole, 'actual' => $user['role']],
        ]);
        Response::error(
            "That account's role is \"{$user['role']}\". Please select \"{$user['role']}\" and try again.",
            403,
            ['code' => 'ROLE_MISMATCH', 'actual_role' => $user['role']]
        );
    }

    // --- success
    $signals = AuditEngine::trackDevice((int) $user['id'], $ctx, $user['home_country']);

    // A correct password clears the failed-attempt counter — it proves the person
    // knows the password. It deliberately does NOT clear lockout_count: having
    // been locked out is a security warning about this account, and one correct
    // password should not erase it. Only an administrator lifts that.
    Database::run(
        'UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = NOW()
          WHERE id = ?',
        [$user['id']]
    );

    Auth::login($user);
    $ctx->sessionId = session_id();
    SecurityEngine::recordLoginAttempt((int) $user['id'], $username, $ctx, 'SUCCESS');

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

// ----------------------------------------------------------- GOOGLE SIGN-IN

/**
 * Sign in (or transparently sign up) with a Google ID token.
 *
 * Three cases, and they are audited differently because they mean different
 * things to a security team:
 *   - a returning Google user            -> login_success
 *   - an existing password user's email  -> we link Google to that account
 *   - a brand-new email                  -> user_registered, then login_success
 */
function googleSignIn(Context $ctx): never
{
    if (!GoogleAuth::enabled()) {
        Response::error('Google sign-in is not configured on this server', 400);
    }

    $token = Response::body()['credential'] ?? '';

    try {
        $profile = GoogleAuth::verify($token);
    } catch (RuntimeException $e) {
        // A rejected Google token is a security-relevant event: record it.
        AuditEngine::record([
            'type'        => 'login_failed',
            'ctx'         => $ctx,
            'description' => 'Google sign-in rejected: ' . $e->getMessage(),
            'metadata'    => ['provider' => 'google', 'reason' => 'token_verification_failed'],
        ]);
        Response::error($e->getMessage(), 401);
    }

    $user = Database::one('SELECT * FROM users WHERE google_id = ?', [$profile['sub']]);
    $isNewUser = false;

    if (!$user) {
        // No Google link yet. Does the verified email already belong to someone?
        $existing = Database::one('SELECT * FROM users WHERE email = ?', [$profile['email']]);

        if ($existing) {
            // Link Google to the existing account. Google has verified the email,
            // so we know this really is the same person.
            Database::run(
                'UPDATE users SET google_id = ?, avatar_url = ? WHERE id = ?',
                [$profile['sub'], $profile['picture'], $existing['id']]
            );
            $user = Database::one('SELECT * FROM users WHERE id = ?', [$existing['id']]);

            AuditEngine::record([
                'type'            => 'user_modified',
                'ctx'             => $ctx,
                'subject_user_id' => (int) $user['id'],
                'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
                'description'     => "\"{$user['username']}\" linked their Google account for sign-in",
                'metadata'        => ['provider' => 'google', 'linked' => true],
            ]);
        } else {
            // Brand-new customer, created straight from the Google profile.
            $username = GoogleAuth::suggestUsername($profile['email']);

            $userId = Database::insert(
                "INSERT INTO users (username, full_name, email, google_id, avatar_url, auth_provider, role)
                 VALUES (?, ?, ?, ?, ?, 'google', 'customer')",
                [$username, $profile['name'], $profile['email'], $profile['sub'], $profile['picture']]
            );

            $accounts = Bank::openAccounts($userId);
            $user = Database::one('SELECT * FROM users WHERE id = ?', [$userId]);
            $isNewUser = true;

            AuditEngine::record([
                'type'            => 'user_registered',
                'ctx'             => $ctx,
                'subject_user_id' => $userId,
                'actor'           => ['id' => $userId, 'role' => 'customer'],
                'description'     => "New customer \"$username\" registered with Google and was issued account "
                                     . $accounts['checking']['account_number'],
                'metadata'        => [
                    'provider' => 'google',
                    'email'    => $profile['email'],
                    'accounts' => [
                        $accounts['checking']['account_number'],
                        $accounts['savings']['account_number'],
                    ],
                ],
            ]);
        }
    }

    // The same login controls apply however you arrive — Google verifies who you
    // are, not whether this account is currently allowed in.
    $lock = SecurityEngine::checkLockout($user);
    if ($lock['locked']) {
        SecurityEngine::recordLoginAttempt(
            (int) $user['id'],
            $user['username'],
            $ctx,
            'FAILED',
            $lock['permanent'] ? 'security_locked' : 'locked_out'
        );

        if ($lock['permanent']) {
            Response::error(
                'Your account has been secured due to repeated unsuccessful login attempts. '
                . 'Please visit your nearest bank branch for verification.',
                403,
                ['code' => 'SECURITY_LOCKED']
            );
        }

        $minutes = (int) ceil($lock['seconds_left'] / 60);
        Response::error(
            'Too many unsuccessful login attempts have been detected. Please try again in '
            . ($minutes <= 1 ? 'a moment' : "$minutes minutes") . '.',
            403,
            ['code' => 'TEMPORARILY_LOCKED', 'seconds_left' => $lock['seconds_left']]
        );
    }

    if ($user['status'] === 'closed') {
        Response::error('This account is closed.', 403);
    }

    // From here it is an ordinary successful login.
    $signals = AuditEngine::trackDevice((int) $user['id'], $ctx, $user['home_country']);
    // As with a password login: the attempt counter clears, the lockout history
    // does not.
    Database::run(
        'UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = NOW()
          WHERE id = ?',
        [$user['id']]
    );

    Auth::login($user);
    $ctx->sessionId = session_id();
    SecurityEngine::recordLoginAttempt((int) $user['id'], $user['username'], $ctx, 'SUCCESS');

    if (!$isNewUser) {
        AuditEngine::record([
            'type'            => 'login_success',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
            'description'     => "{$user['role']} \"{$user['username']}\" signed in with Google from {$ctx->city}, {$ctx->country}",
            'metadata'        => ['role' => $user['role'], 'provider' => 'google'],
            'signals'         => $signals,
        ]);
    }

    if ($signals['is_new_country']) {
        AuditEngine::record([
            'type'            => 'new_location_login',
            'ctx'             => $ctx,
            'subject_user_id' => (int) $user['id'],
            'description'     => "Google sign-in from {$ctx->country}, but the account's home country is "
                                 . $user['home_country'],
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
