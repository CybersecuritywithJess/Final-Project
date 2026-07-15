<?php

/**
 * THE AI AUDIT ASSISTANT API.
 *
 *   GET  ?action=config       is Claude configured? + example questions
 *   POST ?action=ask          answer a plain-English question
 *
 * Auditor/admin only. The assistant reads the audit data and answers questions
 * about it; it can never move money or change a record. Every question is
 * itself written to the audit log — an auditor using the assistant is
 * accountable like anyone else.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../../src/AuditAssistant.php';
require_once __DIR__ . '/../../src/ClaudeAssistant.php';

$user = Auth::requireRole('auditor', 'admin');
$ctx  = Context::fromRequest();

switch (action()) {
    case 'config':
        Response::json([
            'claude_enabled' => ClaudeAssistant::enabled(),
            'suggestions'    => AuditAssistant::suggestions(),
        ]);
        break;

    case 'ask':
        requireMethod('POST');
        ask($user, $ctx);
        break;

    default:
        Response::error('Unknown action', 404);
}

function ask(array $user, Context $ctx): never
{
    $question = trim(Response::body()['question'] ?? '');
    if ($question === '') {
        Response::error('Please type a question.');
    }
    if (mb_strlen($question) > 500) {
        Response::error('That question is too long — keep it under 500 characters.');
    }

    // Prefer Claude when configured; fall back to the built-in engine both when
    // no key is set and when a live call fails, so the assistant never dies.
    $usedClaude = false;
    try {
        if (ClaudeAssistant::enabled()) {
            $result = ClaudeAssistant::answer($question);
            $usedClaude = true;
        } else {
            $result = AuditAssistant::answer($question);
        }
    } catch (Throwable $e) {
        error_log('[assistant] Claude path failed, using built-in: ' . $e->getMessage());
        $result = AuditAssistant::answer($question);
        $result['fallback_note'] = 'The AI service was unavailable, so this was answered by the built-in engine.';
    }

    // Audit the question — who asked what, and which engine answered.
    AuditEngine::record([
        'type'            => 'assistant_query',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "{$user['role']} \"{$user['username']}\" asked the AI assistant: \"$question\"",
        'metadata'        => [
            'question'  => $question,
            'engine'    => $result['engine'] ?? ($usedClaude ? 'claude' : 'built-in'),
            'row_count' => $result['row_count'] ?? 0,
            'sql'       => $result['sql'] ?? null,
        ],
    ]);

    Response::json($result);
}
