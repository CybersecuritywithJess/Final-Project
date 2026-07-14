<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Response.php';
require_once __DIR__ . '/AuditEngine.php';
require_once __DIR__ . '/RiskEngine.php';

/**
 * Session handling and role-based access control.
 *
 * Passwords are hashed with bcrypt (cost 12) — never stored, never reversible.
 * Sessions expire after the admin-configured timeout.
 */
class Auth
{
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_set_cookie_params([
                'httponly' => true,   // JavaScript cannot read the session cookie
                'samesite' => 'Lax',  // blocks cross-site request forgery
            ]);
            session_start();
        }
    }

    public static function hash(string $password): string
    {
        $config = require __DIR__ . '/../config/config.php';
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => $config['app']['bcrypt_cost']]);
    }

    public static function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public static function login(array $user): void
    {
        self::start();
        session_regenerate_id(true);   // defeats session fixation
        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['last_activity'] = time();
    }

    public static function logout(): void
    {
        self::start();
        $_SESSION = [];
        session_destroy();
    }

    /** The signed-in user, or null. Expired sessions are torn down here. */
    public static function user(): ?array
    {
        self::start();

        if (empty($_SESSION['user_id'])) {
            return null;
        }

        $timeout = (int) RiskEngine::rule('session_timeout_minutes') * 60;
        if ($timeout > 0 && time() - ($_SESSION['last_activity'] ?? 0) > $timeout) {
            self::logout();
            return null;
        }
        $_SESSION['last_activity'] = time();

        $user = Database::one(
            'SELECT id, username, full_name, email, phone, role, status, home_country
               FROM users WHERE id = ?',
            [$_SESSION['user_id']]
        );

        // The account was deleted or locked while the session was still alive.
        if (!$user || $user['status'] !== 'active') {
            self::logout();
            return null;
        }

        return $user;
    }

    /** Require any signed-in user. Halts with 401 otherwise. */
    public static function require(): array
    {
        $user = self::user();
        if ($user === null) {
            Response::error('Please sign in to continue', 401, ['code' => 'NOT_AUTHENTICATED']);
        }
        return $user;
    }

    /**
     * Require one of the given roles.
     *
     * A rejected attempt is itself a CRITICAL audit event — an auditor poking
     * at admin endpoints is exactly what this system exists to catch.
     */
    public static function requireRole(string ...$roles): array
    {
        $user = self::require();

        if (in_array($user['role'], $roles, true)) {
            return $user;
        }

        $path = $_SERVER['REQUEST_URI'] ?? 'unknown';
        AuditEngine::record([
            'type'            => 'unauthorized_access',
            'ctx'             => Context::fromRequest(),
            'subject_user_id' => (int) $user['id'],
            'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
            'description'     => "{$user['role']} \"{$user['username']}\" attempted to access $path, " .
                                 'which requires: ' . implode(' or ', $roles),
            'metadata'        => ['path' => $path, 'required_roles' => $roles],
        ]);

        Response::error('You do not have permission to do that', 403);
    }
}
