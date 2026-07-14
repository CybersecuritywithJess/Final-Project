<?php
/**
 * Database and app configuration.
 *
 * Defaults match a stock XAMPP install (root, no password). Override any of
 * them with environment variables rather than editing this file.
 */
return [
    'db' => [
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => getenv('DB_PORT') ?: '3306',
        'name' => getenv('DB_NAME') ?: 'audit_tracking',
        'user' => getenv('DB_USER') ?: 'root',
        'pass' => getenv('DB_PASS') ?: '',
        'charset' => 'utf8mb4',
    ],
    'app' => [
        'currency' => 'KES',
        'bcrypt_cost' => 12,
    ],
];
