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

    /**
     * "Continue with Google".
     *
     * Leave the client id blank and the Google button simply does not appear —
     * the rest of the app is unaffected. To switch it on, create an OAuth 2.0
     * Client ID (type: Web application) at
     * https://console.cloud.google.com/apis/credentials with
     *
     *   Authorised JavaScript origin:  http://localhost:8000
     *
     * then paste the client id below, or set GOOGLE_CLIENT_ID in the environment.
     *
     * The client id is public by design — it ships to the browser. There is no
     * client SECRET here, because this flow does not need one.
     */
    'google' => [
        'client_id' => getenv('GOOGLE_CLIENT_ID') ?: '',
    ],

    /**
     * AI Audit Assistant.
     *
     * The assistant always works: with no key it answers from a built-in rule
     * engine that maps plain-English questions to safe, pre-built SQL. Add an
     * Anthropic API key and it upgrades to Claude, which understands free-form
     * phrasing and writes its own read-only queries (every one is sandboxed and
     * validated before it runs).
     *
     * Get a key at https://console.anthropic.com/ and paste it below, or set
     * ANTHROPIC_API_KEY in the environment. Unlike the Google client id this is
     * a SECRET — it never reaches the browser and must not be committed.
     */
    'ai' => [
        'api_key' => getenv('ANTHROPIC_API_KEY') ?: '',
        'model'   => getenv('ANTHROPIC_MODEL') ?: 'claude-opus-4-8',
    ],
];
