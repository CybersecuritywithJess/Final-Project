<?php

require_once __DIR__ . '/Database.php';

/**
 * THE BUILT-IN AI AUDIT ASSISTANT.
 *
 * A rule engine that turns a plain-English question from an auditor into a
 * safe, pre-built query against the audit database, then answers in words plus
 * a table of evidence. It understands the questions auditors actually ask —
 * "show me high-risk withdrawals this week", "why was John flagged", "which
 * customer has the highest risk score", "failed logins from the same IP" — by
 * pulling apart the question into signals (a time window, a risk level, a named
 * customer, an IP address, a transaction type, an intent) and routing to the
 * matcher that fits.
 *
 * Every query it can run is written here by hand and parameterised — the model
 * never gets to invent SQL. That is the trade-off versus the Claude layer:
 * this always works, offline and free, but only answers patterns it was taught.
 */
class AuditAssistant
{
    /** Answer a question. Always returns a result; never throws. */
    public static function answer(string $question): array
    {
        $q = strtolower(trim($question));
        if ($q === '') {
            return self::help('Ask me about logins, transactions, alerts, or a specific customer.');
        }

        $signals = self::parse($q);

        // Ordered most-specific first: the first matcher that fits wins.
        $matchers = [
            'whyFlagged', 'highestRisk', 'failedLoginsByIp', 'newCountryLogins',
            'lockedAccounts', 'rapidTransfers', 'largestTransactions',
            'suspiciousSummary', 'financialActivity', 'userActivity',
            'openAlerts', 'usersByRole', 'adminActions', 'totals',
            'failedLoginCount', 'recentActivity',
        ];

        foreach ($matchers as $matcher) {
            $result = self::$matcher($q, $signals);
            if ($result !== null) {
                $result['engine'] = 'built-in';
                return $result;
            }
        }

        return self::help("I couldn't match that to a report. Try one of the examples below.");
    }

    /** The example questions shown to the user. */
    public static function suggestions(): array
    {
        return [
            'Show all high-risk withdrawals this week',
            'Which customer has the highest risk score?',
            "Summarise today's suspicious activity",
            'Why was mary_w flagged?',
            'List failed login attempts by IP address',
            'Which accounts are locked?',
            'Show the largest transactions',
            'Who logged in from another country?',
            'List all open fraud alerts',
            'How many failed logins today?',
        ];
    }

    // ------------------------------------------------------------- parsing

    /** Pull the reusable signals out of a question once. */
    private static function parse(string $q): array
    {
        return [
            'window'   => self::window($q),
            'risk'     => self::riskLevels($q),
            'user'     => self::findUser($q),
            'ip'       => self::findIp($q),
            'country'  => self::findCountry($q),
        ];
    }

    /** A [sql, label] pair for the time window named in the question, or null. */
    private static function window(string $q): ?array
    {
        if (preg_match('/\btoday\b/', $q))                       return ["DATE(e.created_at) = CURDATE()", 'today'];
        if (preg_match('/\byesterday\b/', $q))                   return ["DATE(e.created_at) = CURDATE() - INTERVAL 1 DAY", 'yesterday'];
        if (preg_match('/\bthis week\b|\bpast week\b|\blast 7 days\b|\bweek\b/', $q))  return ["e.created_at >= CURDATE() - INTERVAL 6 DAY", 'this week'];
        if (preg_match('/\bthis month\b|\bpast month\b|\blast 30 days\b|\bmonth\b/', $q)) return ["e.created_at >= CURDATE() - INTERVAL 29 DAY", 'this month'];
        return null;
    }

    /** The risk levels implied by the wording. */
    private static function riskLevels(string $q): ?array
    {
        if (preg_match('/\bcritical\b/', $q))                      return ['CRITICAL'];
        if (preg_match('/\bhigh[- ]?risk\b|\bhigh risk\b|\bsuspicious\b|\brisky\b/', $q)) return ['HIGH', 'CRITICAL'];
        if (preg_match('/\bhigh\b/', $q))                          return ['HIGH', 'CRITICAL'];
        if (preg_match('/\bmedium\b/', $q))                        return ['MEDIUM'];
        if (preg_match('/\blow[- ]?risk\b|\blow\b/', $q))          return ['LOW'];
        return null;
    }

    /** The first known customer/username/full-name mentioned. */
    private static function findUser(string $q): ?array
    {
        $users = Database::all('SELECT id, username, full_name, role, status, home_country FROM users');
        foreach ($users as $u) {
            $needles = [strtolower($u['username'])];
            foreach (explode(' ', strtolower($u['full_name'])) as $part) {
                if (strlen($part) >= 3) $needles[] = $part;
            }
            foreach ($needles as $needle) {
                if (preg_match('/\b' . preg_quote($needle, '/') . '\b/', $q)) {
                    return $u;
                }
            }
        }
        return null;
    }

    private static function findIp(string $q): ?string
    {
        return preg_match('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', $q, $m) ? $m[0] : null;
    }

    private static function findCountry(string $q): ?string
    {
        $rows = Database::all("SELECT DISTINCT country FROM audit_events WHERE country IS NOT NULL");
        foreach ($rows as $r) {
            if ($r['country'] && preg_match('/\b' . preg_quote(strtolower($r['country']), '/') . '\b/', $q)) {
                return $r['country'];
            }
        }
        return null;
    }

    // ------------------------------------------------------------ matchers
    // Each returns a result array, or null if the question isn't for it.

    /** "Why was John flagged?" — the alerts raised against a customer. */
    private static function whyFlagged(string $q, array $s): ?array
    {
        if (!preg_match('/\bwhy\b|\bflag(ged)?\b|\bwhat did .* do\b/', $q)) return null;

        if ($s['user']) {
            $alerts = Database::all(
                "SELECT alert_ref, risk_level, status, title, description, created_at
                 FROM alerts WHERE user_id = ? ORDER BY created_at DESC",
                [$s['user']['id']]
            );
            $name = $s['user']['full_name'];
            if (!$alerts) {
                return self::result(
                    "$name has no fraud alerts on record — nothing has been flagged against this account.",
                    "Alerts for {$s['user']['username']}",
                    []
                );
            }
            $worst = $alerts[0]['risk_level'];
            return self::result(
                "$name has " . count($alerts) . " alert(s), the most serious rated $worst. "
                . "Each row below is a rule the account tripped.",
                "Alerts for {$s['user']['username']}",
                $alerts
            );
        }

        // No specific user — show the most recent flags across everyone.
        $alerts = Database::all(
            "SELECT al.alert_ref, u.username, al.risk_level, al.status, al.title, al.created_at
             FROM alerts al LEFT JOIN users u ON u.id = al.user_id
             ORDER BY al.created_at DESC LIMIT 15"
        );
        return self::result(
            'Here are the most recent accounts that were flagged, and why.',
            'Recent fraud alerts',
            $alerts
        );
    }

    /** "Which customer has the highest risk score?" */
    private static function highestRisk(string $q, array $s): ?array
    {
        if (!preg_match('/\b(highest|top|most|riskiest|greatest)\b/', $q)
            || !preg_match('/\brisk\b|\bscore\b|\bcustomer\b|\buser\b/', $q)) {
            return null;
        }
        if (preg_match('/transaction|withdraw|transfer|deposit|payment|amount/', $q)) {
            return null; // that's a "largest transaction" question
        }

        $rows = Database::all(
            "SELECT u.username, u.full_name, u.status,
                    COALESCE(MAX(e.risk_score), 0) AS peak_risk_score,
                    SUM(CASE WHEN e.risk_level IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS high_risk_events
             FROM users u
             LEFT JOIN audit_events e ON e.subject_user_id = u.id
                  AND e.created_at >= CURDATE() - INTERVAL 29 DAY
             WHERE u.role = 'customer'
             GROUP BY u.id
             ORDER BY peak_risk_score DESC, high_risk_events DESC
             LIMIT 10"
        );
        if (!$rows) return self::result('There are no customers to score yet.', 'Customer risk (30 days)', []);

        $top = $rows[0];
        return self::result(
            "{$top['full_name']} (@{$top['username']}) carries the highest risk score, "
            . "a peak of {$top['peak_risk_score']} over the last 30 days.",
            'Customers by peak risk score (last 30 days)',
            $rows
        );
    }

    /** "List failed login attempts from the same IP." */
    private static function failedLoginsByIp(string $q, array $s): ?array
    {
        $mentionsFailed = preg_match('/\bfailed\b|\bfailure\b|\bbrute\b|\bwrong password\b/', $q);
        if (!$mentionsFailed || !preg_match('/\blogin|\bsign[- ]?in|\battempt/', $q)) return null;

        // This matcher is about grouping by source, so it needs an IP cue.
        // A bare "how many failed logins" is a count — let it fall through.
        $ipCue = $s['ip'] || preg_match('/\bip\b|\baddress\b|\bsource\b|\bby ip\b|\bsame ip\b|\bwhere from\b/', $q);
        if (!$ipCue) return null;

        [$win, $winLabel] = $s['window'] ?? ["1=1", 'all time'];

        if ($s['ip']) {
            $rows = Database::all(
                "SELECT e.created_at, u.username, e.city, e.country, e.description
                 FROM audit_events e LEFT JOIN users u ON u.id = e.subject_user_id
                 WHERE e.event_type = 'login_failed' AND e.ip_address = ? AND $win
                 ORDER BY e.created_at DESC LIMIT 50",
                [$s['ip']]
            );
            return self::result(
                count($rows) . " failed login(s) came from {$s['ip']} ($winLabel).",
                "Failed logins from {$s['ip']}",
                $rows
            );
        }

        // Grouped by IP — the shape that exposes a brute-force source.
        $rows = Database::all(
            "SELECT e.ip_address, COUNT(*) AS failed_attempts,
                    COUNT(DISTINCT e.subject_user_id) AS accounts_targeted,
                    MAX(e.country) AS country, MAX(e.created_at) AS last_attempt
             FROM audit_events e
             WHERE e.event_type = 'login_failed' AND $win
             GROUP BY e.ip_address
             ORDER BY failed_attempts DESC LIMIT 25"
        );
        return self::result(
            'Failed logins grouped by source IP ' . "($winLabel). "
            . 'A single IP with many attempts across several accounts is a brute-force signature.',
            'Failed logins by IP',
            $rows
        );
    }

    /** "Who logged in from another country?" */
    private static function newCountryLogins(string $q, array $s): ?array
    {
        if (!preg_match('/\b(new|another|different|foreign|other)\b.*\b(country|location)\b|\bimpossible travel\b|\boverseas\b|\babroad\b/', $q)
            && !$s['country']) {
            return null;
        }

        [$win, $winLabel] = $s['window'] ?? ["1=1", 'all time'];

        if ($s['country']) {
            $rows = Database::all(
                "SELECT e.created_at, u.username, e.city, e.country, e.ip_address, e.browser
                 FROM audit_events e LEFT JOIN users u ON u.id = e.subject_user_id
                 WHERE e.event_type IN ('login_success','new_location_login') AND e.country = ? AND $win
                 ORDER BY e.created_at DESC LIMIT 50",
                [$s['country']]
            );
            return self::result(
                count($rows) . " login(s) came from {$s['country']} ($winLabel).",
                "Logins from {$s['country']}",
                $rows
            );
        }

        $rows = Database::all(
            "SELECT e.created_at, u.username, e.country, e.city, u.home_country, e.ip_address
             FROM audit_events e JOIN users u ON u.id = e.subject_user_id
             WHERE e.event_type = 'new_location_login' AND $win
             ORDER BY e.created_at DESC LIMIT 50"
        );
        return self::result(
            count($rows) . " login(s) came from a country other than the account's home ($winLabel) — "
            . 'the impossible-travel signal.',
            'Logins from a new country',
            $rows
        );
    }

    /** "Which accounts are locked?" */
    private static function lockedAccounts(string $q, array $s): ?array
    {
        if (!preg_match('/\block(ed)?\b|\bsuspended\b|\bfrozen\b/', $q)) return null;

        $rows = Database::all(
            "SELECT username, full_name, email, failed_logins, locked_at
             FROM users WHERE status = 'locked' ORDER BY locked_at DESC"
        );
        return self::result(
            count($rows) === 0
                ? 'No accounts are currently locked.'
                : count($rows) . ' account(s) are locked, each after too many failed logins. '
                  . 'An admin can unlock them from Administration.',
            'Locked accounts',
            $rows
        );
    }

    /** "Show rapid / structuring transfers." */
    private static function rapidTransfers(string $q, array $s): ?array
    {
        if (!preg_match('/\brapid\b|\bstructuring\b|\bsuccessive\b|\bmultiple transfers\b/', $q)) return null;

        $rows = Database::all(
            "SELECT al.alert_ref, u.username, al.risk_level, al.status, al.description, al.created_at
             FROM alerts al LEFT JOIN users u ON u.id = al.user_id
             WHERE al.rule_key = 'rapid_transfers' ORDER BY al.created_at DESC"
        );
        return self::result(
            count($rows) . ' rapid-transfer alert(s) — several transfers fired within the structuring window.',
            'Rapid-transfer alerts',
            $rows
        );
    }

    /** "Show the largest transactions / withdrawals / transfers." */
    private static function largestTransactions(string $q, array $s): ?array
    {
        if (!preg_match('/\b(largest|biggest|top|highest|greatest)\b/', $q)
            || !preg_match('/\btransaction|\bwithdraw|\btransfer|\bdeposit|\bpayment|\bamount\b/', $q)) {
            return null;
        }

        $type = self::txnType($q);
        $params = [];
        $where = "status != 'failed'";
        if ($type) {
            $where .= ' AND type = ?';
            $params[] = $type;
        }

        $rows = Database::all(
            "SELECT reference, type, amount, counterparty, status, created_at
             FROM transactions WHERE $where ORDER BY amount DESC LIMIT 15",
            $params
        );
        return self::result(
            'The largest ' . ($type ? "$type " : '') . 'transactions, biggest first.',
            'Largest transactions',
            $rows
        );
    }

    /** "Summarise today's suspicious activity." */
    private static function suspiciousSummary(string $q, array $s): ?array
    {
        if (!preg_match('/\bsummar/', $q) && !($s['risk'] && preg_match('/\bactivity\b|\bevents?\b/', $q))) {
            return null;
        }

        [$win, $winLabel] = $s['window'] ?? ["1=1", 'all time'];

        $counts = Database::one(
            "SELECT
               SUM(CASE WHEN e.risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
               SUM(CASE WHEN e.risk_level = 'HIGH' THEN 1 ELSE 0 END)     AS high,
               SUM(CASE WHEN e.event_type = 'login_failed' THEN 1 ELSE 0 END) AS failed_logins,
               COUNT(*) AS total_events
             FROM audit_events e WHERE $win"
        );
        $alerts = Database::value("SELECT COUNT(*) FROM alerts al WHERE " . str_replace('e.created_at', 'al.created_at', $win));

        $rows = Database::all(
            "SELECT e.created_at, u.username, e.event_type, e.risk_level, e.description
             FROM audit_events e LEFT JOIN users u ON u.id = e.subject_user_id
             WHERE e.risk_level IN ('HIGH','CRITICAL') AND $win
             ORDER BY e.risk_score DESC, e.created_at DESC LIMIT 25"
        );

        return self::result(
            "Activity $winLabel: {$counts['total_events']} audit events, "
            . "of which " . (int)$counts['critical'] . " critical and " . (int)$counts['high'] . " high risk. "
            . (int)$counts['failed_logins'] . " failed logins, and $alerts fraud alert(s) raised. "
            . 'The highest-risk events are listed below.',
            "High-risk activity ($winLabel)",
            $rows
        );
    }

    /** "Show high-risk withdrawals this week" and similar financial filters. */
    private static function financialActivity(string $q, array $s): ?array
    {
        $type = self::eventType($q);
        if (!$type && !$s['risk']) return null;
        // Only treat as financial when a financial type or a risk+activity is named.
        if (!$type && !preg_match('/\btransaction|\bactivity\b|\bevents?\b/', $q)) return null;

        [$win, $winLabel] = $s['window'] ?? ["1=1", 'all time'];
        $where = [$win];
        $params = [];

        if ($type) {
            $where[] = 'e.event_type = ?';
            $params[] = $type;
        }
        if ($s['risk']) {
            $in = implode(',', array_fill(0, count($s['risk']), '?'));
            $where[] = "e.risk_level IN ($in)";
            array_push($params, ...$s['risk']);
        }
        if ($s['user']) {
            $where[] = 'e.subject_user_id = ?';
            $params[] = $s['user']['id'];
        }

        $rows = Database::all(
            "SELECT e.audit_ref, e.created_at, u.username, e.event_type, e.risk_level,
                    e.amount, e.description
             FROM audit_events e LEFT JOIN users u ON u.id = e.subject_user_id
             WHERE " . implode(' AND ', $where) . "
             ORDER BY e.created_at DESC LIMIT 50",
            $params
        );

        $what = trim(
            ($s['risk'] ? strtolower(implode('/', $s['risk'])) . '-risk ' : '')
            . ($type ? str_replace('_', ' ', $type) . ' ' : '') . 'events'
        );
        return self::result(
            count($rows) . " $what found ($winLabel).",
            ucfirst($what) . " ($winLabel)",
            $rows
        );
    }

    /** "Show mary_w's activity / history / timeline." */
    private static function userActivity(string $q, array $s): ?array
    {
        if (!$s['user'] || !preg_match('/\bactivity\b|\bhistory\b|\btimeline\b|\bwhat has\b|\bshow\b/', $q)) {
            return null;
        }

        $rows = Database::all(
            "SELECT e.created_at, e.event_type, e.risk_level, e.amount, e.ip_address, e.country, e.description
             FROM audit_events e WHERE e.subject_user_id = ?
             ORDER BY e.created_at DESC LIMIT 50",
            [$s['user']['id']]
        );
        return self::result(
            "The most recent activity for {$s['user']['full_name']} (@{$s['user']['username']}).",
            "Activity for {$s['user']['username']}",
            $rows
        );
    }

    /** "List open fraud alerts" (optionally by status/risk). */
    private static function openAlerts(string $q, array $s): ?array
    {
        if (!preg_match('/\balert/', $q)) return null;

        $where = [];
        $params = [];
        if (preg_match('/\bopen\b|\bnew\b|\bpending\b|\bunresolved\b/', $q)) {
            $where[] = "al.status IN ('new','under_investigation')";
        }
        if (preg_match('/\bconfirmed\b/', $q))       $where[] = "al.status = 'confirmed_fraud'";
        if (preg_match('/\bresolved\b|\bclosed\b/', $q)) $where[] = "al.status IN ('resolved','closed')";
        if ($s['risk']) {
            $in = implode(',', array_fill(0, count($s['risk']), '?'));
            $where[] = "al.risk_level IN ($in)";
            array_push($params, ...$s['risk']);
        }

        $rows = Database::all(
            "SELECT al.alert_ref, u.username, al.risk_level, al.status, al.title, al.created_at
             FROM alerts al LEFT JOIN users u ON u.id = al.user_id
             " . ($where ? 'WHERE ' . implode(' AND ', $where) : '') . "
             ORDER BY
               FIELD(al.risk_level,'CRITICAL','HIGH','MEDIUM','LOW'), al.created_at DESC
             LIMIT 50",
            $params
        );
        return self::result(
            count($rows) . ' matching fraud alert(s), most serious first.',
            'Fraud alerts',
            $rows
        );
    }

    /** "List all admins / auditors / customers." */
    private static function usersByRole(string $q, array $s): ?array
    {
        $role = null;
        if (preg_match('/\bauditor/', $q))                 $role = 'auditor';
        elseif (preg_match('/\badmin/', $q))               $role = 'admin';
        elseif (preg_match('/\bcustomer|\bbank user/', $q)) $role = 'customer';
        if (!$role || !preg_match('/\blist\b|\bshow\b|\bhow many\b|\ball\b|\bwho are\b/', $q)) return null;

        $rows = Database::all(
            "SELECT u.username, u.full_name, u.email, u.status, u.last_login_at,
                    COALESCE(SUM(a.balance), 0) AS total_balance
             FROM users u LEFT JOIN accounts a ON a.user_id = u.id
             WHERE u.role = ? GROUP BY u.id ORDER BY u.created_at DESC",
            [$role]
        );
        return self::result(count($rows) . " {$role}(s) on the system.", ucfirst($role) . 's', $rows);
    }

    /** "What admin actions were taken?" */
    private static function adminActions(string $q, array $s): ?array
    {
        if (!preg_match('/\badmin(istrator)?\b/', $q) || !preg_match('/\baction|\bdid\b|\bchange|\bactivity\b/', $q)) {
            return null;
        }
        [$win, $winLabel] = $s['window'] ?? ["1=1", 'all time'];

        $rows = Database::all(
            "SELECT e.created_at, actor.username AS admin, e.event_type, e.risk_level, e.description
             FROM audit_events e LEFT JOIN users actor ON actor.id = e.actor_user_id
             WHERE e.actor_role = 'admin' AND $win
             ORDER BY e.created_at DESC LIMIT 50"
        );
        return self::result(
            count($rows) . " administrator action(s) recorded ($winLabel). "
            . 'Admins are audited exactly like customers.',
            "Administrator actions ($winLabel)",
            $rows
        );
    }

    /** "Total transferred / withdrawn / deposited". */
    private static function totals(string $q, array $s): ?array
    {
        if (!preg_match('/\btotal\b|\bsum\b|\bhow much\b/', $q)) return null;

        [$winE, $winLabel] = $s['window'] ?? ["1=1", 'all time'];
        $win = str_replace('e.created_at', 'created_at', $winE);
        $type = self::txnType($q);

        if ($type) {
            $total = Database::value(
                "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type = ? AND status != 'failed' AND $win",
                [$type]
            );
            return self::result(
                'Total ' . str_replace('_', ' ', $type) . " value ($winLabel): KES "
                . number_format((float)$total, 2) . '.',
                'Total ' . str_replace('_', ' ', $type),
                [['type' => $type, 'total_value' => (float)$total, 'window' => $winLabel]]
            );
        }

        $rows = Database::all(
            "SELECT type, COUNT(*) AS count, COALESCE(SUM(amount),0) AS total_value
             FROM transactions WHERE status != 'failed' AND $win
             GROUP BY type ORDER BY total_value DESC"
        );
        return self::result("Transaction value by type ($winLabel).", "Totals by type ($winLabel)", $rows);
    }

    /** "How many failed logins today?" */
    private static function failedLoginCount(string $q, array $s): ?array
    {
        if (!preg_match('/\bhow many\b|\bcount\b|\bnumber of\b/', $q)) return null;

        [$win, $winLabel] = $s['window'] ?? ["1=1", 'all time'];
        $type = self::eventType($q) ?? (preg_match('/\bfailed\b/', $q) ? 'login_failed' : null);

        if ($type) {
            $n = Database::value("SELECT COUNT(*) FROM audit_events e WHERE e.event_type = ? AND $win", [$type]);
            $label = str_replace('_', ' ', $type);
            return self::result("There were $n $label event(s) $winLabel.", "Count: $label", [['event' => $label, 'count' => (int)$n, 'window' => $winLabel]]);
        }

        $rows = Database::all(
            "SELECT e.event_type, COUNT(*) AS count FROM audit_events e WHERE $win
             GROUP BY e.event_type ORDER BY count DESC LIMIT 25"
        );
        return self::result("Event counts by type ($winLabel).", "Event counts ($winLabel)", $rows);
    }

    /** "Show recent / latest activity." */
    private static function recentActivity(string $q, array $s): ?array
    {
        if (!preg_match('/\brecent\b|\blatest\b|\blast\b|\bactivity\b|\bfeed\b|\bwhat.s happening\b/', $q)) {
            return null;
        }
        $rows = Database::all(
            "SELECT e.created_at, u.username, e.event_type, e.risk_level, e.description
             FROM audit_events e LEFT JOIN users u ON u.id = e.subject_user_id
             ORDER BY e.created_at DESC LIMIT 30"
        );
        return self::result('The most recent activity across the whole system.', 'Recent activity', $rows);
    }

    // -------------------------------------------------------------- helpers

    /** Map words in the question to an audit event_type. */
    private static function eventType(string $q): ?string
    {
        return match (true) {
            (bool) preg_match('/\bwithdraw/', $q)                 => 'withdrawal',
            (bool) preg_match('/\btransfer/', $q)                 => 'transfer',
            (bool) preg_match('/\bdeposit/', $q)                  => 'deposit',
            (bool) preg_match('/\bbill\b|\bpayment/', $q)         => 'bill_payment',
            (bool) preg_match('/\bairtime/', $q)                  => 'airtime',
            (bool) preg_match('/\bfailed login|\bfailed sign/', $q) => 'login_failed',
            (bool) preg_match('/\blogin|\bsign[- ]?in/', $q)      => 'login_success',
            (bool) preg_match('/\bpassword/', $q)                 => 'password_changed',
            default                                               => null,
        };
    }

    /** Map words in the question to a transactions.type. */
    private static function txnType(string $q): ?string
    {
        return match (true) {
            (bool) preg_match('/\bwithdraw/', $q) => 'withdrawal',
            (bool) preg_match('/\btransfer/', $q) => 'transfer',
            (bool) preg_match('/\bdeposit/', $q)  => 'deposit',
            (bool) preg_match('/\bbill\b/', $q)   => 'bill_payment',
            (bool) preg_match('/\bairtime/', $q)  => 'airtime',
            default                               => null,
        };
    }

    private static function result(string $answer, string $interpretation, array $rows): array
    {
        return [
            'answer'         => $answer,
            'interpretation' => $interpretation,
            'rows'           => array_slice($rows, 0, 50),
            'row_count'      => count($rows),
        ];
    }

    private static function help(string $answer): array
    {
        return [
            'engine'         => 'built-in',
            'answer'         => $answer,
            'interpretation' => 'No report matched',
            'rows'           => [],
            'row_count'      => 0,
            'suggestions'    => self::suggestions(),
        ];
    }
}
