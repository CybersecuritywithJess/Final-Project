<?php

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/SqlGuard.php';

/**
 * THE CLAUDE-POWERED AI AUDIT ASSISTANT.
 *
 * When an Anthropic API key is configured, the assistant upgrades from the
 * built-in rule engine to Claude. It works in two steps:
 *
 *   1. Claude is given the database schema and the auditor's question, and
 *      writes a single read-only SELECT that would answer it.
 *   2. We validate that SQL through SqlGuard (single statement, SELECT only,
 *      allow-listed tables, run-and-rollback) and execute it.
 *   3. Claude is shown the rows it got back and writes the plain-English answer.
 *
 * The model never touches the database directly and never sees a credential —
 * it only proposes SQL, which our own gate decides whether to run. Calls go
 * over raw HTTPS with curl, the same dependency-free approach used elsewhere in
 * this project, so there is no Composer package to install.
 */
class ClaudeAssistant
{
    private const ENDPOINT = 'https://api.anthropic.com/v1/messages';
    private const VERSION  = '2023-06-01';

    public static function enabled(): bool
    {
        return self::apiKey() !== '';
    }

    private static function apiKey(): string
    {
        $config = require __DIR__ . '/../config/config.php';
        return trim($config['ai']['api_key'] ?? '');
    }

    private static function model(): string
    {
        $config = require __DIR__ . '/../config/config.php';
        return $config['ai']['model'] ?? 'claude-opus-4-8';
    }

    /**
     * Answer a question with Claude. Returns the same shape the built-in engine
     * uses, plus the SQL that ran, so an auditor can see exactly what was asked.
     *
     * @throws RuntimeException if the API is unreachable or the model misbehaves
     */
    public static function answer(string $question): array
    {
        // --- step 1: ask Claude for a read-only SELECT
        $sqlReply = self::call([
            ['role' => 'user', 'content' => self::sqlPrompt($question)],
        ], 1024);

        $plan = self::extractJson($sqlReply);
        $sql = trim($plan['sql'] ?? '');

        if ($sql === '' || strtoupper(substr(ltrim($sql), 0, 6)) !== 'SELECT') {
            // Claude decided no query fits (e.g. an off-topic question).
            return [
                'engine'         => 'claude',
                'answer'         => $plan['answer'] ?? "I can only answer questions about this system's audit data.",
                'interpretation' => 'No query run',
                'rows'           => [],
                'row_count'      => 0,
                'sql'            => null,
            ];
        }

        // --- step 2: validate and run behind the guard
        $rows = SqlGuard::run($sql);           // throws on any violation

        // --- step 3: have Claude read the rows and answer in words
        $answer = self::summarise($question, $rows);

        return [
            'engine'         => 'claude',
            'answer'         => $answer,
            'interpretation' => $plan['intent'] ?? 'Claude query',
            'rows'           => array_slice($rows, 0, 50),
            'row_count'      => count($rows),
            'sql'            => $sql,
        ];
    }

    // ------------------------------------------------------------- prompts

    private static function schema(): string
    {
        // A compact, hand-written schema keeps the prompt cheap and the model
        // accurate. It mirrors database/schema.sql.
        return <<<SCHEMA
        Tables (MySQL / MariaDB):

        users(id, username, full_name, email, phone, role[customer|auditor|admin],
              status[active|locked|closed], failed_logins, locked_at, home_country,
              last_login_at, created_at)
        accounts(id, user_id->users.id, account_number, type[checking|savings], balance, created_at)
        transactions(id, reference, user_id->users.id,
              type[deposit|withdrawal|transfer|savings_deposit|bill_payment|airtime],
              amount, from_account_id, to_account_id, counterparty,
              status[completed|failed|pending|flagged], description, ip_address, created_at)
        audit_events(id, audit_ref, event_type, category, description,
              subject_user_id->users.id, actor_user_id->users.id, actor_role,
              risk_level[LOW|MEDIUM|HIGH|CRITICAL], risk_score(0-100),
              transaction_id, amount, ip_address, browser, os, device_type,
              country, city, session_id, created_at)
        alerts(id, alert_ref, audit_event_id, user_id->users.id, rule_key, title,
              description, risk_level[LOW|MEDIUM|HIGH|CRITICAL],
              status[new|under_investigation|confirmed_fraud|false_positive|resolved|closed],
              assigned_to, created_at, updated_at)
        alert_notes(id, alert_id->alerts.id, auditor_id, finding, recommendation, created_at)
        devices(id, user_id->users.id, fingerprint, browser, os, device_type, last_ip, last_country, last_seen)
        risk_rules(rule_key, label, value, unit, description)

        Common event_type values in audit_events: login_success, login_failed,
        account_locked, new_location_login, new_device_login, deposit, withdrawal,
        transfer, bill_payment, airtime, password_changed, role_changed,
        user_deleted, user_modified, report_exported.
        SCHEMA;
    }

    private static function sqlPrompt(string $question): string
    {
        $schema = self::schema();
        return <<<PROMPT
        You are the query planner for a bank's audit system. Given the schema and
        an auditor's question, write ONE read-only MySQL SELECT that answers it.

        $schema

        Rules:
        - Output a SINGLE SELECT statement only. Never write to the database.
        - Use only the tables above. Always add a LIMIT (<= 200).
        - Prefer clear column aliases; show human-readable columns (username,
          created_at, risk_level, amount, description) rather than raw ids.
        - "this week" = created_at >= CURDATE() - INTERVAL 6 DAY; "today" = DATE(created_at)=CURDATE().
        - "high-risk"/"suspicious" = risk_level IN ('HIGH','CRITICAL').
        - If the question is not about this audit data, set sql to "".

        Auditor question: "$question"

        Reply with ONLY a JSON object, no prose, no code fences:
        {"intent": "<one sentence describing what you are querying>", "sql": "<the SELECT, or empty string>"}
        PROMPT;
    }

    private static function summarise(string $question, array $rows): string
    {
        // Cap the rows we send back so the summary call stays cheap.
        $sample = array_slice($rows, 0, 40);
        $json = json_encode($sample, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $count = count($rows);

        $reply = self::call([
            ['role' => 'user', 'content' =>
                "An auditor asked: \"$question\".\n\n" .
                "A read-only query returned $count row(s). Here are up to 40 of them as JSON:\n$json\n\n" .
                "Write a concise, factual answer (2-4 sentences) an auditor can act on. " .
                "Lead with the direct answer. Use real numbers and names from the data. " .
                "Amounts are in KES. Do not invent anything not in the rows. No preamble."
            ],
        ], 512);

        return trim($reply) ?: "The query returned $count row(s).";
    }

    // ------------------------------------------------------------ transport

    /**
     * One call to the Messages API. Returns the concatenated text of the reply.
     * @param array<int, array{role:string, content:string}> $messages
     * @throws RuntimeException
     */
    private static function call(array $messages, int $maxTokens): string
    {
        $payload = json_encode([
            'model'      => self::model(),
            'max_tokens' => $maxTokens,
            'messages'   => $messages,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $curl = curl_init(self::ENDPOINT);
        curl_setopt_array($curl, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 45,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'x-api-key: ' . self::apiKey(),
                'anthropic-version: ' . self::VERSION,
            ],
        ]);

        $body = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $error = curl_error($curl);
        curl_close($curl);

        if ($body === false) {
            throw new RuntimeException("Could not reach the AI service ($error).");
        }
        if ($status === 401) {
            throw new RuntimeException('The Anthropic API key was rejected. Check config.php.');
        }
        if ($status === 429) {
            throw new RuntimeException('The AI service is rate-limited right now. Try again shortly.');
        }
        if ($status < 200 || $status >= 300) {
            $decoded = json_decode($body, true);
            $msg = $decoded['error']['message'] ?? "HTTP $status";
            throw new RuntimeException("The AI service returned an error: $msg");
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded) || empty($decoded['content'])) {
            throw new RuntimeException('The AI service returned an unreadable response.');
        }

        // Concatenate every text block in the reply.
        $text = '';
        foreach ($decoded['content'] as $block) {
            if (($block['type'] ?? '') === 'text') {
                $text .= $block['text'];
            }
        }
        return $text;
    }

    /** Pull the first JSON object out of a model reply, tolerant of stray prose. */
    private static function extractJson(string $reply): array
    {
        $reply = trim($reply);
        // Strip a ```json fence if the model added one despite instructions.
        $reply = preg_replace('/^```(?:json)?|```$/m', '', $reply);

        $start = strpos($reply, '{');
        $end = strrpos($reply, '}');
        if ($start === false || $end === false || $end <= $start) {
            return [];
        }
        $json = substr($reply, $start, $end - $start + 1);
        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : [];
    }
}
