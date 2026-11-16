<?php
/**
 * DVB-I signature validation report collector
 *
 * Receives reports defined in DVB BlueBook A177r8 (TS 103 770 v1.3.1) clause 7.6.2.5,
 * which are delivered using the W3C Reporting API (endpoint name "dvbi-signature-validation",
 * report type "signature-verification-issue"), and provides a web interface to list the
 * reports received from a given source IP address or hostname.
 *
 *   POST   - accept one or more reports (application/reports+json, a JSON array of reports;
 *            a single JSON object or application/json is also accepted for convenience)
 *   OPTIONS- CORS pre-flight (browser-based DVB-I clients send this before the POST)
 *   GET    - web interface; ?source=<ip-or-hostname>[&format=json]
 *
 * A DVB-I endpoint advertises this collector with a response header such as:
 *   Reporting-Endpoints: dvbi-signature-validation="https://example.com/dvbi-reports/index.php"
 *
 * Requirements: PHP 7.4+ with pdo_sqlite.
 * Configuration: edit the defaults below, or (preferably) create config.php next to this file
 * returning an array that overrides any of these keys, e.g.
 *   <?php return ['retention_days' => 90];
 *
 * Copyright (c) 2026, Paul Higgs
 * SPDX-License-Identifier: BSD-3-Clause - see the LICENSE file for details.
 *
 * Credits: developed with the assistance of Claude (Opus 5.5), an AI model by Anthropic,
 * using Claude Code - https://claude.com/claude-code
 */

declare(strict_types=1);

$CONFIG = [
    // How long reports are kept, in days. 183 days is approximately 6 months.
    'retention_days'      => 183,
    // SQLite database file. Keep it outside the web root, or protect the data/ directory.
    'db_path'             => __DIR__ . '/data/reports.sqlite',
    // Reject POST bodies larger than this many bytes.
    'max_body_bytes'      => 256 * 1024,
    // Maximum number of reports accepted from one POST.
    'max_reports_per_post'=> 100,
    // Only store reports whose "type" is "signature-verification-issue".
    // Set to false to also store (and flag) reports of other types.
    'strict_type'         => false,
    // Perform a reverse DNS lookup of the sender when a report is received, so reports can
    // later be found by hostname as well as by address.
    'reverse_dns'         => true,
    // If this script sits behind reverse proxies, list their addresses here so the client
    // address is taken from X-Forwarded-For. Leave empty when clients connect directly.
    'trusted_proxies'     => [],
    // Value of Access-Control-Allow-Origin sent to browser-based clients.
    'cors_allow_origin'   => '*',
    // Maximum number of reports shown for one lookup.
    'max_results'         => 1000,
];

if (is_file(__DIR__ . '/config.php')) {
    $override = require __DIR__ . '/config.php';
    if (is_array($override)) {
        $CONFIG = array_merge($CONFIG, $override);
    }
}
$CONFIG['retention_days'] = max(1, (int)$CONFIG['retention_days']);

const REPORT_TYPE   = 'signature-verification-issue';
const ENDPOINT_NAME = 'dvbi-signature-validation';

// ---------------------------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------------------------

function db(array $cfg): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $dir = dirname($cfg['db_path']);
    if (!is_dir($dir) && !mkdir($dir, 0770, true) && !is_dir($dir)) {
        throw new RuntimeException("Cannot create data directory $dir");
    }
    // Stop the web server serving the database directly (Apache); configure nginx/IIS separately.
    if (!is_file($dir . '/.htaccess')) {
        @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
    }
    $pdo = new PDO('sqlite:' . $cfg['db_path'], null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    $pdo->exec('CREATE TABLE IF NOT EXISTS reports (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at        INTEGER NOT NULL,   -- unix time (s) the POST arrived
        source_ip          TEXT    NOT NULL,
        source_host        TEXT,               -- reverse DNS of source_ip at receipt time
        http_user_agent    TEXT,               -- User-Agent header of the POST
        content_type       TEXT,
        report_type        TEXT,
        report_url         TEXT,
        report_user_agent  TEXT,
        report_age         INTEGER,            -- ms, from the report "age" property
        policy             TEXT,
        signature_present  TEXT,
        vendor_action      TEXT,
        issues             TEXT,               -- JSON array of conformance notes
        raw                TEXT    NOT NULL    -- the report object exactly as received
    )');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_reports_ip   ON reports (source_ip, received_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_reports_host ON reports (source_host, received_at)');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_reports_time ON reports (received_at)');
    return $pdo;
}

function purge_expired(array $cfg): void
{
    $cutoff = time() - $cfg['retention_days'] * 86400;
    $stmt = db($cfg)->prepare('DELETE FROM reports WHERE received_at < ?');
    $stmt->execute([$cutoff]);
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/** Canonical text form of an IP address; IPv4-mapped IPv6 addresses become plain IPv4. */
function normalise_ip(string $ip): ?string
{
    $ip = trim($ip, " \t[]");
    $bin = @inet_pton($ip);
    if ($bin === false) {
        return null;
    }
    if (strlen($bin) === 16 && substr($bin, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
        $bin = substr($bin, 12);
    }
    return inet_ntop($bin);
}

function client_ip(array $cfg): string
{
    $remote = normalise_ip($_SERVER['REMOTE_ADDR'] ?? '') ?? 'unknown';
    $trusted = array_filter(array_map('normalise_ip', (array)$cfg['trusted_proxies']));
    if ($trusted && in_array($remote, $trusted, true) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Walk right-to-left, skipping our own proxies; the first other address is the client.
        $hops = array_reverse(array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])));
        foreach ($hops as $hop) {
            $ip = normalise_ip($hop);
            if ($ip === null) {
                break;
            }
            if (!in_array($ip, $trusted, true)) {
                return $ip;
            }
        }
    }
    return $remote;
}

function is_hostname(string $s): bool
{
    return strlen($s) <= 253
        && (bool)preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i', $s);
}

/** All IPv4 and IPv6 addresses a hostname resolves to. */
function resolve_host(string $host): array
{
    $ips = [];
    foreach ((@gethostbynamel($host) ?: []) as $ip) {
        $ips[] = $ip;
    }
    foreach ((@dns_get_record($host, DNS_A | DNS_AAAA) ?: []) as $rr) {
        if (isset($rr['ip']))   { $ips[] = $rr['ip']; }
        if (isset($rr['ipv6'])) { $ips[] = $rr['ipv6']; }
    }
    return array_values(array_unique(array_filter(array_map('normalise_ip', $ips))));
}

function h($v): string
{
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function self_url(): string
{
    $https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path   = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
    return ($https ? 'https' : 'http') . '://' . $host . $path;
}

function send_cors(array $cfg): void
{
    header('Access-Control-Allow-Origin: ' . $cfg['cors_allow_origin']);
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Max-Age: 86400');
}

function fail(int $code, string $msg): void
{
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg, "\n";
    exit;
}

// ---------------------------------------------------------------------------------------------
// Report ingestion (A177r8 clause 7.6.2.5 / W3C Reporting API clause 2.1.3)
// ---------------------------------------------------------------------------------------------

/** First property present among the given names (the spec text and the W3C text differ in spelling). */
function prop(array $a, string ...$names)
{
    foreach ($names as $n) {
        if (array_key_exists($n, $a)) {
            return $a[$n];
        }
    }
    return null;
}

/** Extract the fields of one report and note any departures from clause 7.6.2.5. */
function parse_report($r, array $cfg): ?array
{
    $issues = [];
    if (!is_array($r) || array_is_list_compat($r)) {
        return ['skip' => true, 'issues' => ['report is not a JSON object']];
    }

    $type = prop($r, 'type');
    if ($type !== REPORT_TYPE) {
        if ($cfg['strict_type']) {
            return null;
        }
        $issues[] = 'type is ' . json_encode($type) . ', expected "' . REPORT_TYPE . '"';
    }

    $url = prop($r, 'url');
    if (!is_string($url) || $url === '') {
        $issues[] = 'url property missing or empty';
        $url = is_scalar($url) ? (string)$url : null;
    }

    $ua = prop($r, 'user-agent', 'user_agent');
    if (!is_string($ua) || $ua === '') {
        $issues[] = 'user-agent property missing or empty';
        $ua = is_scalar($ua) ? (string)$ua : null;
    }

    $age = prop($r, 'age');
    if ($age !== null && !is_int($age) && !is_float($age)) {
        $issues[] = 'age property is not a number';
        $age = null;
    }

    $policy = $sigPresent = $vendorAction = null;
    $body = prop($r, 'body');
    if (!is_array($body) || ($body !== [] && array_is_list_compat($body))) {
        $issues[] = 'body property missing or not an object';
    } else {
        $policy = prop($body, 'policy');
        if (!is_string($policy) || $policy === '') {
            $issues[] = 'body.policy missing or empty';
            $policy = is_scalar($policy) ? (string)$policy : null;
        }
        if (array_key_exists('signature-present', $body)) {
            $sp = $body['signature-present'];
            $sigPresent = is_bool($sp) ? ($sp ? 'true' : 'false') : (is_scalar($sp) ? (string)$sp : json_encode($sp));
            if ($sp !== 'false') {
                $issues[] = 'body.signature-present shall only be present with the value "false" (got ' . json_encode($sp) . ')';
            }
        }
        if (array_key_exists('vendor-action', $body)) {
            $va = $body['vendor-action'];
            $vendorAction = is_scalar($va) ? (string)$va : json_encode($va);
            if (!is_string($va)) {
                $issues[] = 'body.vendor-action is not a string';
            }
        }
    }

    return [
        'report_type'       => is_scalar($type) ? (string)$type : json_encode($type),
        'report_url'        => $url,
        'report_user_agent' => $ua,
        'report_age'        => $age === null ? null : (int)$age,
        'policy'            => $policy,
        'signature_present' => $sigPresent,
        'vendor_action'     => $vendorAction,
        'issues'            => $issues,
        'raw'               => json_encode($r, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
    ];
}

function array_is_list_compat(array $a): bool
{
    return function_exists('array_is_list') ? array_is_list($a) : $a === [] || array_keys($a) === range(0, count($a) - 1);
}

function handle_post(array $cfg): void
{
    send_cors($cfg);

    $len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > $cfg['max_body_bytes']) {
        fail(413, 'Report payload too large');
    }
    $raw = file_get_contents('php://input', false, null, 0, $cfg['max_body_bytes'] + 1);
    if ($raw === false || $raw === '') {
        fail(400, 'Empty request body');
    }
    if (strlen($raw) > $cfg['max_body_bytes']) {
        fail(413, 'Report payload too large');
    }

    $ctype = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    $data = json_decode($raw, true, 32);
    if (!is_array($data)) {
        fail(400, 'Request body is not valid JSON: ' . json_last_error_msg());
    }
    // The Reporting API delivers a JSON array of reports; tolerate a single report object.
    $reports = array_is_list_compat($data) ? $data : [$data];
    if (count($reports) === 0) {
        fail(400, 'No reports in request body');
    }
    if (count($reports) > $cfg['max_reports_per_post']) {
        fail(413, 'Too many reports in one request');
    }

    $ip   = client_ip($cfg);
    $host = null;
    if ($cfg['reverse_dns'] && $ip !== 'unknown') {
        $rev = @gethostbyaddr($ip);
        if (is_string($rev) && $rev !== '' && $rev !== $ip) {
            $host = strtolower(rtrim($rev, '.'));
        }
    }
    $envIssues = [];
    if ($ctype !== 'application/reports+json') {
        $envIssues[] = 'Content-Type is "' . $ctype . '", expected "application/reports+json"';
    }
    if (!array_is_list_compat($data)) {
        $envIssues[] = 'payload is a single object, expected a JSON array of reports';
    }

    $pdo = db($cfg);
    $stmt = $pdo->prepare('INSERT INTO reports
        (received_at, source_ip, source_host, http_user_agent, content_type, report_type, report_url,
         report_user_agent, report_age, policy, signature_present, vendor_action, issues, raw)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)');

    $now = time();
    $stored = 0;
    $pdo->beginTransaction();
    foreach ($reports as $r) {
        $p = parse_report($r, $cfg);
        if ($p === null || !empty($p['skip'])) {
            continue;
        }
        $stmt->execute([
            $now, $ip, $host, substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 1024), $ctype,
            $p['report_type'], $p['report_url'], $p['report_user_agent'], $p['report_age'],
            $p['policy'], $p['signature_present'], $p['vendor_action'],
            json_encode(array_merge($envIssues, $p['issues']), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $p['raw'],
        ]);
        $stored++;
    }
    $pdo->commit();
    purge_expired($cfg);

    if ($stored === 0) {
        fail(400, 'No acceptable reports in request body');
    }
    http_response_code(204);  // Reporting API treats any 2xx as successful delivery
    exit;
}

// ---------------------------------------------------------------------------------------------
// Web interface
// ---------------------------------------------------------------------------------------------

function lookup(array $cfg, string $q): array
{
    $q = trim($q);
    $ips = [];
    $host = null;
    $ip = normalise_ip($q);
    if ($ip !== null) {
        $ips = [$ip];
    } elseif (is_hostname($q)) {
        $host = strtolower(rtrim($q, '.'));
        $ips  = resolve_host($host);
    } else {
        return ['error' => 'Enter a valid IPv4 or IPv6 address or a hostname.'];
    }

    $where = [];
    $args  = [];
    if ($ips) {
        $where[] = 'source_ip IN (' . implode(',', array_fill(0, count($ips), '?')) . ')';
        $args = $ips;
    }
    if ($host !== null) {
        $where[] = 'source_host = ?';
        $args[] = $host;
    }
    $limit = max(1, (int)$cfg['max_results']);
    $stmt = db($cfg)->prepare('SELECT * FROM reports WHERE ' . implode(' OR ', $where)
        . ' ORDER BY received_at DESC, id DESC LIMIT ' . ($limit + 1));
    $stmt->execute($args);
    $rows = $stmt->fetchAll();
    $truncated = count($rows) > $limit;
    if ($truncated) {
        array_pop($rows);
    }
    return ['ips' => $ips, 'host' => $host, 'rows' => $rows, 'truncated' => $truncated];
}

function handle_get(array $cfg): void
{
    purge_expired($cfg);
    $q = isset($_GET['source']) ? (string)$_GET['source'] : '';
    $result = $q !== '' ? lookup($cfg, $q) : null;

    if (($_GET['format'] ?? '') === 'json') {
        header('Content-Type: application/json; charset=utf-8');
        if ($result === null || isset($result['error'])) {
            http_response_code(400);
            echo json_encode(['error' => $result['error'] ?? 'source parameter required']);
            exit;
        }
        foreach ($result['rows'] as &$row) {
            $row['issues'] = json_decode($row['issues'] ?? '[]', true);
            $row['raw']    = json_decode($row['raw'], true);
            $row['received_at'] = gmdate('Y-m-d\TH:i:s\Z', (int)$row['received_at']);
        }
        unset($row);
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    header('Content-Type: text/html; charset=utf-8');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
    header('X-Content-Type-Options: nosniff');
    $endpoint = self_url();
    $me = client_ip($cfg);
    ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DVB-I Signature Reports</title>
<style>
  :root { --fg:#1d2330; --muted:#5d6677; --bg:#f6f7f9; --card:#fff; --line:#dde1e7; --accent:#2457c5; --warn:#a15c00; --warnbg:#fff4e0; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e6e9ef; --muted:#9aa3b2; --bg:#14171c; --card:#1c2027; --line:#323844; --accent:#7aa2ff; --warn:#ffb54d; --warnbg:#3a2c14; }
  }
  * { box-sizing:border-box; }
  body { margin:0; font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color:var(--fg); background:var(--bg); }
  main { max-width:1200px; margin:0 auto; padding:24px 16px 48px; }
  h1 { font-size:1.4rem; margin:0 0 4px; }
  p.sub { color:var(--muted); margin:0 0 20px; }
  form { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:20px; }
  input[type=text] { flex:1 1 280px; padding:9px 12px; font:inherit; color:inherit; background:var(--card); border:1px solid var(--line); border-radius:6px; }
  button { padding:9px 18px; font:inherit; color:#fff; background:var(--accent); border:0; border-radius:6px; cursor:pointer; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px 16px; margin-bottom:16px; overflow-x:auto; }
  .muted { color:var(--muted); }
  code, pre { font:13px/1.45 ui-monospace, Consolas, monospace; }
  pre { margin:6px 0 0; white-space:pre-wrap; word-break:break-all; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:600; white-space:nowrap; }
  td.url { word-break:break-all; min-width:220px; }
  .issue { display:inline-block; margin:2px 0; padding:1px 6px; border-radius:4px; color:var(--warn); background:var(--warnbg); font-size:12.5px; }
  .ok { color:var(--muted); font-size:12.5px; }
  details summary { cursor:pointer; color:var(--accent); font-size:13px; }
  .error { color:var(--warn); }
</style>
</head>
<body>
<main>
  <h1>DVB-I signature validation reports</h1>
  <p class="sub">Reports per DVB A177r8 clause 7.6.2.5 are kept for <?= h($cfg['retention_days']) ?> days.</p>

  <form method="get" action="">
    <input type="text" name="source" value="<?= h($q) ?>" placeholder="Source IP address or hostname" autofocus aria-label="Source IP address or hostname">
    <button type="submit">Show reports</button>
  </form>

<?php if ($result === null): ?>
  <div class="card">
    <p style="margin-top:0">Point DVB-I clients here by sending this header from the DVB-I endpoint:</p>
    <pre>Reporting-Endpoints: <?= h(ENDPOINT_NAME) ?>="<?= h($endpoint) ?>"</pre>
    <p class="muted" style="margin-bottom:0">Your address as seen by this server: <code><?= h($me) ?></code></p>
  </div>
<?php elseif (isset($result['error'])): ?>
  <div class="card error"><?= h($result['error']) ?></div>
<?php else: ?>
  <div class="card">
    <strong><?= count($result['rows']) ?></strong> report<?= count($result['rows']) === 1 ? '' : 's' ?> for <code><?= h($q) ?></code>
    <?php if ($result['host'] !== null): ?>
      <span class="muted">— resolves to <?= $result['ips'] ? h(implode(', ', $result['ips'])) : 'no addresses' ?>; also matched on reverse DNS name</span>
    <?php endif; ?>
    <?php if ($result['truncated']): ?><div class="error">Only the most recent <?= h($cfg['max_results']) ?> reports are shown.</div><?php endif; ?>
    <?php if ($result['rows']): ?>
      · <a href="?source=<?= h(rawurlencode($q)) ?>&amp;format=json">JSON</a>
    <?php endif; ?>
  </div>

  <?php if ($result['rows']): ?>
  <div class="card">
  <table>
    <thead><tr>
      <th>Received (UTC)</th><th>Source</th><th>Resource URL</th><th>Policy</th>
      <th>Signature present</th><th>Vendor action</th><th>Conformance</th>
    </tr></thead>
    <tbody>
    <?php foreach ($result['rows'] as $r):
        $issues = json_decode($r['issues'] ?? '[]', true) ?: [];
        $pretty = json_encode(json_decode($r['raw'], true), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    ?>
      <tr>
        <td><?= h(gmdate('Y-m-d H:i:s', (int)$r['received_at'])) ?>
          <?php if ($r['report_age'] !== null): ?><div class="muted">age <?= h(number_format((int)$r['report_age'] / 1000, 1)) ?> s</div><?php endif; ?></td>
        <td><code><?= h($r['source_ip']) ?></code><?php if ($r['source_host']): ?><div class="muted"><?= h($r['source_host']) ?></div><?php endif; ?></td>
        <td class="url"><?= h($r['report_url'] ?? '') ?>
          <details><summary>details</summary>
            <div class="muted">Report user-agent: <?= h($r['report_user_agent'] ?? '—') ?></div>
            <div class="muted">POST User-Agent: <?= h($r['http_user_agent'] ?: '—') ?></div>
            <div class="muted">Content-Type: <?= h($r['content_type'] ?: '—') ?></div>
            <pre><?= h($pretty) ?></pre>
          </details></td>
        <td><?= h($r['policy'] ?? '—') ?></td>
        <td><?= h($r['signature_present'] ?? '—') ?></td>
        <td><?= h($r['vendor_action'] ?? '—') ?></td>
        <td><?php if ($issues): foreach ($issues as $i): ?><div class="issue"><?= h($i) ?></div><?php endforeach; else: ?><span class="ok">conforms</span><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
  <?php endif; ?>
<?php endif; ?>
</main>
</body>
</html>
<?php
}

// ---------------------------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------------------------

try {
    switch ($_SERVER['REQUEST_METHOD'] ?? 'GET') {
        case 'OPTIONS':
            send_cors($CONFIG);
            http_response_code(204);
            exit;
        case 'POST':
            handle_post($CONFIG);
            break;
        case 'GET':
        case 'HEAD':
            handle_get($CONFIG);
            break;
        default:
            header('Allow: GET, HEAD, POST, OPTIONS');
            fail(405, 'Method not allowed');
    }
} catch (Throwable $e) {
    error_log('dvbi-signature-reports: ' . $e);
    fail(500, 'Internal error');
}
