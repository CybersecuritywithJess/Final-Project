<?php

/**
 * Shared bootstrap for every API endpoint: loads the classes, starts the
 * session, and makes sure an unexpected crash still answers in JSON rather
 * than dumping a PHP stack trace into the browser.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../src/Database.php';
require_once __DIR__ . '/../../src/Context.php';
require_once __DIR__ . '/../../src/Response.php';
require_once __DIR__ . '/../../src/RiskEngine.php';
require_once __DIR__ . '/../../src/FraudEngine.php';
require_once __DIR__ . '/../../src/AuditEngine.php';
require_once __DIR__ . '/../../src/Auth.php';
require_once __DIR__ . '/../../src/Bank.php';

Auth::start();

// Never leak internals to the client; log them instead.
set_exception_handler(function (Throwable $e): void {
    error_log('[api] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    Response::error('Something went wrong on our end', 500);
});

/** The ?action= on the query string decides which handler runs. */
function action(): string
{
    return $_GET['action'] ?? '';
}

function method(): string
{
    return $_SERVER['REQUEST_METHOD'] ?? 'GET';
}

/** Halt unless the request uses the expected HTTP verb. */
function requireMethod(string ...$allowed): void
{
    if (!in_array(method(), $allowed, true)) {
        Response::error('Method not allowed', 405);
    }
}
