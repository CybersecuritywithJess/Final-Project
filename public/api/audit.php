<?php

/**
 * THE AUDITOR DASHBOARD API.
 *
 *   GET   ?action=dashboard        KPIs, risk summary, charts, live feed
 *   GET   ?action=events           searchable, filterable, paginated audit log
 *   GET   ?action=event&id=        one event in full
 *   GET   ?action=timeline&user=   a customer's chronological history
 *   GET   ?action=alerts           fraud alerts queue
 *   GET   ?action=alert&id=        one alert + its investigation notes
 *   PATCH ?action=alert-status&id= move an alert through the workflow
 *   POST  ?action=alert-note&id=   add an investigation note
 *   GET   ?action=export           download the filtered log as CSV
 *   GET   ?action=report           compliance-report figures (+ integrity status)
 *   GET   ?action=meta             values for the filter dropdowns
 *
 * Read-heavy by design: auditors investigate, they do not move money. The only
 * writes are the investigation workflow — and those are audited too, because
 * auditors are accountable as well.
 */

require_once __DIR__ . '/bootstrap.php';

// Declared before the dispatch below: PHP evaluates `const` when execution
// reaches it, so a constant defined lower down would not exist yet inside the
// handlers the switch calls.
const BASE_FROM = '
    FROM audit_events e
    LEFT JOIN users u        ON u.id = e.subject_user_id
    LEFT JOIN transactions t ON t.id = e.transaction_id
    LEFT JOIN accounts a     ON a.user_id = e.subject_user_id AND a.type = \'checking\'
';

const ALERT_STATUSES = [
    'new', 'under_investigation', 'confirmed_fraud',
    'false_positive', 'resolved', 'closed',
];

// What separates a "bank" audit row from a "system" one. Bank rows are the Demo
// Bank's own activity — a customer registering, logging in, moving money. System
// rows are the audit machinery and staff acting on it — admins managing users,
// auditors working alerts, report exports, AI assistant queries. Anything an
// admin or auditor actor performed is system activity too (e.g. a staff login).
// This one classifier drives the green/white colour split in the audit log.
const SYSTEM_EVENT_TYPES = [
    'user_created_by_admin', 'user_modified', 'user_deleted', 'admin_password_reset',
    'risk_rule_changed', 'role_changed', 'audit_viewed', 'assistant_query',
    'report_exported', 'report_generated', 'integrity_verified',
    'alert_status_changed', 'alert_note_added',
];

/** Classify an audit row as 'bank' (customer activity) or 'system' (staff/engine). */
function eventSource(array $event): string
{
    if (in_array($event['actor_role'] ?? '', ['admin', 'auditor'], true)) {
        return 'system';
    }
    if (in_array($event['event_type'] ?? '', SYSTEM_EVENT_TYPES, true)) {
        return 'system';
    }
    return 'bank';
}

$user = Auth::requireRole('auditor', 'admin');
$ctx = Context::fromRequest();

switch (action()) {
    case 'dashboard':     dashboard(); break;
    case 'events':        events(); break;
    case 'event':         event(); break;
    case 'timeline':      timeline(); break;
    case 'alerts':        alerts(); break;
    case 'alert':         alert(); break;
    case 'alert-status':  requireMethod('PATCH', 'POST'); alertStatus($user, $ctx); break;
    case 'alert-note':    requireMethod('POST'); alertNote($user, $ctx); break;
    case 'export':        export($user, $ctx); break;
    case 'report':        report($user, $ctx); break;
    case 'meta':          meta(); break;
    default:              Response::error('Unknown action', 404);
}

// ------------------------------------------------------------------ SEARCH

/**
 * Build the WHERE clause for the audit search.
 *
 * Every filter the auditor can use funnels through here, and every value is
 * bound as a positional parameter — the search box cannot inject SQL. Positional
 * rather than named, because the free-text search compares against eight columns
 * and native prepared statements will not accept the same named placeholder twice.
 *
 * @return array{0: string, 1: array}  [sql, params]
 */
function buildFilters(): array
{
    $where = [];
    $params = [];

    if (!empty($_GET['search'])) {
        $columns = [
            'e.audit_ref', 'e.description', 'u.username', 'u.email',
            'u.full_name', 'e.ip_address', 't.reference', 'a.account_number',
        ];
        $where[] = '(' . implode(' OR ', array_map(fn($c) => "$c LIKE ?", $columns)) . ')';

        $term = '%' . $_GET['search'] . '%';
        foreach ($columns as $_) {
            $params[] = $term;
        }
    }

    // query-string key => column
    $exact = [
        'event_type'  => 'e.event_type',
        'category'    => 'e.category',
        'risk_level'  => 'e.risk_level',
        'user_id'     => 'e.subject_user_id',
        'ip'          => 'e.ip_address',
        'country'     => 'e.country',
        'browser'     => 'e.browser',
        'device_type' => 'e.device_type',
    ];
    foreach ($exact as $key => $column) {
        if (!empty($_GET[$key])) {
            $where[] = "$column = ?";
            $params[] = $_GET[$key];
        }
    }

    $ranges = [
        'min_amount' => 'e.amount >= ?',
        'max_amount' => 'e.amount <= ?',
        'from'       => 'DATE(e.created_at) >= ?',
        'to'         => 'DATE(e.created_at) <= ?',
    ];
    foreach ($ranges as $key => $condition) {
        if (!empty($_GET[$key])) {
            $where[] = $condition;
            $params[] = str_contains($key, 'amount') ? (float) $_GET[$key] : $_GET[$key];
        }
    }

    // Filter to a single calendar month. The month picker sends "YYYY-MM";
    // anything else is ignored so a malformed value can't skew the results.
    if (!empty($_GET['month']) && preg_match('/^\d{4}-\d{2}$/', (string) $_GET['month'])) {
        $where[] = "DATE_FORMAT(e.created_at, '%Y-%m') = ?";
        $params[] = $_GET['month'];
    }

    return [$where ? 'WHERE ' . implode(' AND ', $where) : '', $params];
}

function events(): never
{
    [$clause, $params] = buildFilters();

    $page = max((int) ($_GET['page'] ?? 1), 1);
    $pageSize = min((int) ($_GET['page_size'] ?? 25), 200);
    $offset = ($page - 1) * $pageSize;

    $total = (int) Database::value('SELECT COUNT(*) ' . BASE_FROM . ' ' . $clause, $params);

    // LIMIT/OFFSET are cast to int above, so interpolating them is safe here.
    $rows = Database::all(
        'SELECT e.*, u.username, u.full_name, u.email, t.reference AS txn_ref '
        . BASE_FROM . ' ' . $clause .
        " ORDER BY e.created_at DESC, e.id DESC LIMIT $pageSize OFFSET $offset",
        $params
    );

    Response::json([
        'events'    => array_map('hydrate', $rows),
        'total'     => $total,
        'page'      => $page,
        'page_size' => $pageSize,
        'pages'     => (int) ceil($total / $pageSize),
    ]);
}

function event(): never
{
    $row = Database::one(
        'SELECT e.*, u.username, u.full_name, u.email, t.reference AS txn_ref '
        . BASE_FROM . ' WHERE e.id = ?',
        [(int) ($_GET['id'] ?? 0)]
    );

    if (!$row) {
        Response::error('Audit event not found', 404);
    }

    Response::json(['event' => hydrate($row)]);
}

// ---------------------------------------------------------------- TIMELINE

function timeline(): never
{
    $userId = (int) ($_GET['user'] ?? 0);

    $user = Database::one(
        'SELECT id, username, full_name, email, phone, role, status, created_at,
                last_login_at, home_country, failed_logins
           FROM users WHERE id = ?',
        [$userId]
    );
    if (!$user) {
        Response::error('User not found', 404);
    }

    $events = Database::all(
        'SELECT * FROM audit_events WHERE subject_user_id = ?
          ORDER BY created_at ASC, id ASC LIMIT 500',
        [$userId]
    );

    // A user's risk score is the worst thing they have done lately, not an average.
    $riskScore = (int) Database::value(
        'SELECT COALESCE(MAX(risk_score), 0) FROM audit_events
          WHERE subject_user_id = ? AND created_at >= (NOW() - INTERVAL 30 DAY)',
        [$userId]
    );

    Response::json([
        'user'       => $user,
        'accounts'   => Database::all('SELECT * FROM accounts WHERE user_id = ?', [$userId]),
        'devices'    => Database::all(
            'SELECT * FROM devices WHERE user_id = ? ORDER BY last_seen DESC',
            [$userId]
        ),
        'alerts'     => Database::all(
            'SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC',
            [$userId]
        ),
        'risk_score' => $riskScore,
        'events'     => array_map('hydrate', $events),
    ]);
}

// --------------------------------------------------------------- DASHBOARD

function dashboard(): never
{
    $v = fn(string $sql) => Database::value($sql);

    $kpis = [
        'total_users'          => (int) $v("SELECT COUNT(*) FROM users WHERE role = 'customer'"),
        'active_today'         => (int) $v("SELECT COUNT(DISTINCT subject_user_id) FROM audit_events
                                             WHERE event_type = 'login_success' AND DATE(created_at) = CURDATE()"),
        'logins_today'         => (int) $v("SELECT COUNT(*) FROM audit_events
                                             WHERE event_type = 'login_success' AND DATE(created_at) = CURDATE()"),
        'failed_logins_today'  => (int) $v("SELECT COUNT(*) FROM audit_events
                                             WHERE event_type = 'login_failed' AND DATE(created_at) = CURDATE()"),
        'transactions_today'   => (int) $v('SELECT COUNT(*) FROM transactions WHERE DATE(created_at) = CURDATE()'),
        'flagged_transactions' => (int) $v("SELECT COUNT(*) FROM transactions WHERE status = 'flagged'"),
        'critical_open'        => (int) $v("SELECT COUNT(*) FROM alerts
                                             WHERE risk_level = 'CRITICAL'
                                               AND status IN ('new', 'under_investigation')"),
        'pending_reviews'      => (int) $v("SELECT COUNT(*) FROM alerts
                                             WHERE status IN ('new', 'under_investigation')"),
        'locked_accounts'      => (int) $v("SELECT COUNT(*) FROM users WHERE status = 'locked'"),
        'total_transferred'    => (float) $v("SELECT COALESCE(SUM(amount), 0) FROM transactions
                                               WHERE type = 'transfer' AND status <> 'failed'"),
        'total_audits'         => (int) $v('SELECT COUNT(*) FROM audit_events'),
        'new_users_today'      => (int) $v('SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURDATE()'),
    ];

    // Risk summary — the "Critical: 2 / High: 12 / Medium: 38 / Low: 451" panel.
    $riskSummary = array_fill_keys(RiskEngine::LEVELS, 0);
    foreach (Database::all('SELECT risk_level, COUNT(*) AS n FROM audit_events GROUP BY risk_level') as $r) {
        $riskSummary[$r['risk_level']] = (int) $r['n'];
    }

    Response::json([
        'kpis'         => $kpis,
        'risk_summary' => $riskSummary,

        'login_trend' => Database::all("
            SELECT DATE(created_at) AS day,
                   SUM(event_type = 'login_success') AS successful,
                   SUM(event_type = 'login_failed')  AS failed
              FROM audit_events
             WHERE created_at >= (NOW() - INTERVAL 13 DAY)
               AND event_type IN ('login_success', 'login_failed')
             GROUP BY day ORDER BY day
        "),

        'transaction_trend' => Database::all("
            SELECT DATE(created_at) AS day, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS volume
              FROM transactions
             WHERE created_at >= (NOW() - INTERVAL 13 DAY) AND status <> 'failed'
             GROUP BY day ORDER BY day
        "),

        'transactions_by_type' => Database::all("
            SELECT type, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS volume
              FROM transactions WHERE status <> 'failed'
             GROUP BY type ORDER BY count DESC
        "),

        'category_breakdown' => Database::all('
            SELECT category, COUNT(*) AS count FROM audit_events
             GROUP BY category ORDER BY count DESC
        '),

        'top_active_users' => Database::all("
            SELECT u.id, u.username, u.full_name, COUNT(e.id) AS events,
                   COALESCE(MAX(e.risk_score), 0) AS peak_risk
              FROM audit_events e JOIN users u ON u.id = e.subject_user_id
             WHERE u.role = 'customer'
             GROUP BY u.id ORDER BY events DESC LIMIT 8
        "),

        // Activity by weekday and hour — the heatmap.
        'activity_heatmap' => Database::all('
            SELECT WEEKDAY(created_at) AS weekday, HOUR(created_at) AS hour, COUNT(*) AS count
              FROM audit_events
             WHERE created_at >= (NOW() - INTERVAL 30 DAY)
             GROUP BY weekday, hour
        '),

        'recent_feed' => Database::all('
            SELECT e.id, e.audit_ref, e.event_type, e.description, e.risk_level,
                   e.created_at, u.username
              FROM audit_events e LEFT JOIN users u ON u.id = e.subject_user_id
             ORDER BY e.created_at DESC, e.id DESC LIMIT 12
        '),
    ]);
}

// ------------------------------------------------------------------ ALERTS

function alerts(): never
{
    $where = [];
    $params = [];

    foreach (['status', 'risk_level'] as $key) {
        if (!empty($_GET[$key])) {
            $where[] = "al.$key = :$key";
            $params[$key] = $_GET[$key];
        }
    }

    $rows = Database::all(
        'SELECT al.*, u.username, u.full_name, e.audit_ref, assignee.username AS assignee_name
           FROM alerts al
           LEFT JOIN users u        ON u.id = al.user_id
           LEFT JOIN users assignee ON assignee.id = al.assigned_to
           LEFT JOIN audit_events e ON e.id = al.audit_event_id '
        . ($where ? 'WHERE ' . implode(' AND ', $where) : '') .
        " ORDER BY FIELD(al.risk_level, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'), al.created_at DESC",
        $params
    );

    Response::json(['alerts' => $rows]);
}

function alert(): never
{
    $id = (int) ($_GET['id'] ?? 0);

    $alert = Database::one(
        'SELECT al.*, u.username, u.full_name, u.email, u.id AS customer_id, e.audit_ref
           FROM alerts al
           LEFT JOIN users u        ON u.id = al.user_id
           LEFT JOIN audit_events e ON e.id = al.audit_event_id
          WHERE al.id = ?',
        [$id]
    );
    if (!$alert) {
        Response::error('Alert not found', 404);
    }

    $notes = Database::all(
        'SELECT n.*, u.username AS auditor_name FROM alert_notes n
           LEFT JOIN users u ON u.id = n.auditor_id
          WHERE n.alert_id = ? ORDER BY n.created_at DESC',
        [$id]
    );

    Response::json(['alert' => $alert, 'notes' => $notes]);
}

function alertStatus(array $user, Context $ctx): never
{
    $id = (int) ($_GET['id'] ?? 0);
    $status = Response::body()['status'] ?? '';

    if (!in_array($status, ALERT_STATUSES, true)) {
        Response::error('Status must be one of: ' . implode(', ', ALERT_STATUSES));
    }

    $alert = Database::one('SELECT * FROM alerts WHERE id = ?', [$id]);
    if (!$alert) {
        Response::error('Alert not found', 404);
    }

    Database::run(
        'UPDATE alerts SET status = ?, assigned_to = ?, updated_at = NOW() WHERE id = ?',
        [$status, $user['id'], $id]
    );

    // The auditor's own action is audited.
    AuditEngine::record([
        'type'            => 'alert_status_changed',
        'ctx'             => $ctx,
        'subject_user_id' => $alert['user_id'] ? (int) $alert['user_id'] : null,
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "{$user['role']} \"{$user['username']}\" moved alert {$alert['alert_ref']} " .
                             "from {$alert['status']} to $status",
        'metadata'        => [
            'alert_ref' => $alert['alert_ref'],
            'from'      => $alert['status'],
            'to'        => $status,
        ],
    ]);

    Response::json(['message' => 'Alert updated']);
}

function alertNote(array $user, Context $ctx): never
{
    $id = (int) ($_GET['id'] ?? 0);
    $body = Response::body();

    $finding = trim((string) ($body['finding'] ?? ''));
    $recommendation = trim((string) ($body['recommendation'] ?? ''));

    if ($finding === '') {
        Response::error('A finding is required');
    }

    $alert = Database::one('SELECT * FROM alerts WHERE id = ?', [$id]);
    if (!$alert) {
        Response::error('Alert not found', 404);
    }

    Database::run(
        'INSERT INTO alert_notes (alert_id, auditor_id, finding, recommendation) VALUES (?, ?, ?, ?)',
        [$id, $user['id'], $finding, $recommendation ?: null]
    );

    AuditEngine::record([
        'type'            => 'alert_note_added',
        'ctx'             => $ctx,
        'subject_user_id' => $alert['user_id'] ? (int) $alert['user_id'] : null,
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "{$user['role']} \"{$user['username']}\" added an investigation note to " .
                             $alert['alert_ref'],
        'metadata'        => ['alert_ref' => $alert['alert_ref']],
    ]);

    Response::json(['message' => 'Note added'], 201);
}

// ------------------------------------------------------------------ EXPORT

function export(array $user, Context $ctx): never
{
    [$clause, $params] = buildFilters();

    $rows = Database::all(
        'SELECT e.audit_ref, e.created_at, e.event_type, e.actor_role, e.category, e.description,
                u.username, u.email, e.risk_level, e.risk_score, e.amount,
                e.ip_address, e.browser, e.os, e.device_type, e.country, e.city,
                t.reference AS txn_ref '
        . BASE_FROM . ' ' . $clause .
        ' ORDER BY e.created_at DESC LIMIT 10000',
        $params
    );

    // Tag each row bank/system so the split survives into the exported file.
    foreach ($rows as &$exportRow) {
        $exportRow['source'] = eventSource($exportRow);
    }
    unset($exportRow);

    // Exporting data is itself an auditable act.
    AuditEngine::record([
        'type'            => 'report_exported',
        'ctx'             => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'           => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description'     => "\"{$user['username']}\" exported " . count($rows) . ' audit records to CSV',
        'metadata'        => ['row_count' => count($rows), 'filters' => $_GET],
    ]);

    Response::csv(
        $rows,
        ['audit_ref', 'created_at', 'source', 'event_type', 'category', 'description', 'username',
         'email', 'risk_level', 'risk_score', 'amount', 'ip_address', 'browser', 'os',
         'device_type', 'country', 'city', 'txn_ref'],
        'audit-report-' . date('Y-m-d') . '.csv'
    );
}

// ------------------------------------------------------------------ REPORT

/**
 * The figures behind the printable compliance report. Reuses the same aggregates
 * the dashboard shows, scoped to an optional reporting period, and attaches the
 * live result of the audit-log integrity check so the report can attest that the
 * evidence it summarises has not been tampered with.
 */
function report(array $user, Context $ctx): never
{
    // Optional reporting period. A "YYYY-MM" month is expanded to its full span;
    // otherwise explicit from/to dates are honoured. Anything malformed is ignored.
    $from = (!empty($_GET['from']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) $_GET['from'])) ? $_GET['from'] : null;
    $to   = (!empty($_GET['to'])   && preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) $_GET['to']))   ? $_GET['to']   : null;
    if (!empty($_GET['month']) && preg_match('/^\d{4}-\d{2}$/', (string) $_GET['month'])) {
        $from = $_GET['month'] . '-01';
        $to   = date('Y-m-t', strtotime($from));
    }

    // A period clause for any table with a created_at column, AND-appended safely.
    $period = function (array $extra = []) use ($from, $to): array {
        $clauses = $extra;
        $params  = [];
        if ($from) { $clauses[] = 'DATE(created_at) >= ?'; $params[] = $from; }
        if ($to)   { $clauses[] = 'DATE(created_at) <= ?'; $params[] = $to; }
        return [$clauses ? ' WHERE ' . implode(' AND ', $clauses) : '', $params];
    };

    [$evWhere, $evParams] = $period();

    $riskSummary = array_fill_keys(RiskEngine::LEVELS, 0);
    foreach (Database::all("SELECT risk_level, COUNT(*) n FROM audit_events$evWhere GROUP BY risk_level", $evParams) as $r) {
        $riskSummary[$r['risk_level']] = (int) $r['n'];
    }

    [$alWhere, $alParams] = $period();
    $alertsByStatus = Database::all("SELECT status, COUNT(*) n FROM alerts$alWhere GROUP BY status", $alParams);

    $money = function (string $typeClause) use ($period): float {
        [$where, $params] = $period(["status <> 'failed'", $typeClause]);
        return (float) Database::value("SELECT COALESCE(SUM(amount), 0) FROM transactions$where", $params);
    };

    [$userWhere, $userParams] = $period(["u.role = 'customer'"]);
    // The period clause uses a bare created_at; here it must be the event's column.
    $userWhere = str_replace('created_at', 'e.created_at', $userWhere);

    $result = [
        'meta' => [
            'generated_by' => ['username' => $user['username'], 'role' => $user['role'], 'full_name' => $user['full_name']],
            'generated_at' => date('Y-m-d H:i:s'),
            'from'         => $from,
            'to'           => $to,
        ],

        'totals' => [
            'events'      => (int) Database::value("SELECT COUNT(*) FROM audit_events$evWhere", $evParams),
            'alerts'      => (int) array_sum(array_column($alertsByStatus, 'n')),
            'deposits'    => $money("type IN ('deposit', 'savings_deposit')"),
            'withdrawals' => $money("type = 'withdrawal'"),
            'transfers'   => $money("type = 'transfer'"),
        ],

        'risk_summary'     => $riskSummary,
        'alerts_by_status' => $alertsByStatus,

        'category_breakdown' => Database::all(
            "SELECT category, COUNT(*) count FROM audit_events$evWhere GROUP BY category ORDER BY count DESC",
            $evParams
        ),

        'alerts_by_rule' => Database::all(
            "SELECT rule_key, COUNT(*) count,
                    SUM(status = 'confirmed_fraud') confirmed,
                    SUM(status = 'false_positive')  false_positives
               FROM alerts$alWhere GROUP BY rule_key ORDER BY count DESC",
            $alParams
        ),

        'top_risky_users' => Database::all(
            "SELECT u.username, u.full_name, COUNT(e.id) events,
                    COALESCE(MAX(e.risk_score), 0) peak_risk
               FROM audit_events e JOIN users u ON u.id = e.subject_user_id
              $userWhere
              GROUP BY u.id ORDER BY peak_risk DESC, events DESC LIMIT 10",
            $userParams
        ),

        // Integrity is a property of the whole chain, so it is never period-scoped.
        'integrity' => AuditEngine::verifyChain(),
    ];

    // Producing a compliance report is itself an auditable act.
    AuditEngine::record([
        'type'        => 'report_generated',
        'ctx'         => $ctx,
        'subject_user_id' => (int) $user['id'],
        'actor'       => ['id' => (int) $user['id'], 'role' => $user['role']],
        'description' => "\"{$user['username']}\" generated a compliance report"
                         . ($from || $to ? ' for ' . ($from ?? '…') . ' – ' . ($to ?? '…') : ''),
        'metadata'    => ['from' => $from, 'to' => $to, 'events' => $result['totals']['events']],
    ]);

    Response::json($result);
}

// -------------------------------------------------------------- REFERENCE

function meta(): never
{
    $eventTypes = [];
    foreach (RiskEngine::CATALOG as $key => $entry) {
        $eventTypes[] = ['key' => $key, 'label' => $entry[2], 'category' => $entry[0]];
    }

    Response::json([
        'event_types' => $eventTypes,
        'categories'  => RiskEngine::CATEGORIES,
        'risk_levels' => RiskEngine::LEVELS,
        'statuses'    => ALERT_STATUSES,
        'countries'   => array_column(
            Database::all('SELECT DISTINCT country FROM audit_events WHERE country IS NOT NULL ORDER BY country'),
            'country'
        ),
        'customers'   => Database::all(
            "SELECT id, username, full_name FROM users WHERE role = 'customer' ORDER BY username"
        ),
    ]);
}

/** Decode the JSON metadata column so the client doesn't have to. */
function hydrate(array $event): array
{
    $event['metadata'] = json_decode($event['metadata'] ?? '{}', true) ?: [];
    $event['source'] = eventSource($event);
    return $event;
}
