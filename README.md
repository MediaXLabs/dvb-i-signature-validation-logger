# DVB-I Signature Validation Report Collector

A single-file PHP endpoint that receives DVB-I signature validation reports and provides a
web interface to browse them by source IP address or hostname.

DVB-I clients send these reports when they check the signature on a DVB-I service list or
other signed resource, as defined in **DVB BlueBook A177r8 (ETSI TS 103 770 v1.3.1),
clause 7.6.2.5**. Reports are delivered using the
[W3C Reporting API](https://www.w3.org/TR/reporting-1/) with:

| Item              | Value                           |
|-------------------|---------------------------------|
| Endpoint name     | `dvbi-signature-validation`     |
| Report type       | `signature-verification-issue`  |
| Content-Type      | `application/reports+json`      |

## Features

- Accepts Reporting API deliveries (a JSON array of reports). For convenience it also accepts a
  single JSON object, or `application/json`.
- Handles the CORS pre-flight (`OPTIONS`) request that browser-based DVB-I clients send.
- Checks each report against clause 7.6.2.5 and records any departures, for example a missing
  `url`, a missing `body.policy`, or `signature-present` with a value other than `"false"`.
  These notes appear in the **Conformance** column.
- Records the sender's address and, optionally, its reverse-DNS hostname, so you can look up
  reports by either.
- Looks up by hostname too: the hostname is resolved to its IPv4/IPv6 addresses, and reports
  whose stored reverse-DNS name matches are included.
- Gives JSON output for scripting (`?source=...&format=json`).
- Deletes reports automatically once they are older than the retention period (default 183 days).
- Stores everything in SQLite, so no database server is needed.
- Includes a light/dark theme web UI.

## Requirements

- PHP 7.4 or later
- The `pdo_sqlite` extension
- A web server that runs PHP (Apache, nginx + PHP-FPM, IIS, or `php -S` for testing)
- Write access for the web server user to the `data/` directory (created automatically)

## Installation

1. Copy `index.php` to a directory served by your web server, e.g. `/var/www/html/dvbi-reports/`.
2. Make sure the web server user can create and write `data/` in that directory, or set
   `db_path` to a location outside the web root (recommended).
3. Configure your DVB-I endpoint (the server delivering the service list) to send this
   response header:

   ```
   Reporting-Endpoints: dvbi-signature-validation="https://example.com/dvbi-reports/index.php"
   ```

   With no `source` parameter, the collector's home page shows this header with the correct URL.

### Quick local test

```sh
php -S localhost:8080
```

Then open <http://localhost:8080/> in a browser.

## Configuration

Defaults are set in the `$CONFIG` array at the top of `index.php`. Rather than editing that
file, copy `config.example.php` to `config.php` (git ignores it) and keep only the keys you
want to change:

```php
<?php
return [
    'retention_days'  => 90,
    'db_path'         => '/var/lib/dvbi-reports/reports.sqlite',
    'trusted_proxies' => ['10.0.0.1'],
];
```

| Key                    | Default                  | Description |
|------------------------|--------------------------|-------------|
| `retention_days`       | `183`                    | Days to keep reports (about 6 months). |
| `db_path`              | `data/reports.sqlite`    | SQLite database file. |
| `max_body_bytes`       | `262144` (256 KiB)       | Largest POST body accepted. |
| `max_reports_per_post` | `100`                    | Most reports accepted in one POST. |
| `strict_type`          | `false`                  | `true` drops reports whose `type` isn't `signature-verification-issue`; `false` stores them with a conformance note. |
| `reverse_dns`          | `true`                   | Look up the sender's hostname when a report arrives. |
| `trusted_proxies`      | `[]`                     | Reverse proxy addresses; the client address is then read from `X-Forwarded-For`. |
| `cors_allow_origin`    | `*`                      | `Access-Control-Allow-Origin` value. |
| `max_results`          | `1000`                   | Most reports shown in one lookup. |

## HTTP interface

| Method    | Purpose |
|-----------|---------|
| `POST`    | Submit reports. Returns `204 No Content` on success; `400` for invalid JSON or no acceptable reports; `413` if the body or report count is too large. |
| `OPTIONS` | CORS pre-flight. Returns `204`. |
| `GET`     | Web UI. `?source=<ip-or-hostname>` lists reports; add `&format=json` for JSON. |

### Example report

```sh
curl -i -X POST https://example.com/dvbi-reports/index.php \
  -H 'Content-Type: application/reports+json' \
  -d '[{
        "type": "signature-verification-issue",
        "age": 1200,
        "url": "https://example.com/servicelist.xml",
        "user-agent": "ExampleTV/1.0",
        "body": {
          "policy": "strict",
          "signature-present": "false",
          "vendor-action": "rejected"
        }
      }]'
```

### Example lookup

```sh
curl 'https://example.com/dvbi-reports/index.php?source=203.0.113.7&format=json'
```

## Data stored

Each report is stored as one row containing: the time it was received, the source IP,
the reverse-DNS hostname, the POST `User-Agent` and `Content-Type`, the extracted report
fields (`type`, `url`, `user-agent`, `age`, `body.policy`, `body.signature-present`,
`body.vendor-action`), any conformance notes, and the raw report JSON exactly as received.

## Security notes

- **The web interface has no authentication.** Anyone who can reach it can look up reports for
  any address. If that is a concern, restrict `GET` access with your web server (HTTP auth, IP
  allow-list), and leave `POST` and `OPTIONS` open so clients can still deliver reports.
- On Apache, `data/` is protected by an automatically created `.htaccess` file. **On nginx
  or IIS you must block access to `data/` yourself**, or move `db_path` outside the web root.
  For nginx:

  ```nginx
  location ~ /data/ { deny all; }
  ```

- Only set `trusted_proxies` when the script really is behind those proxies. Otherwise clients
  can fake their source address with `X-Forwarded-For`.
- Serve the collector over HTTPS. The Reporting API only delivers reports to secure endpoints.

## Repository layout

| Path                      | Contents |
|---------------------------|----------|
| `index.php`               | The whole collector: ingestion, storage and web UI. |
| `config.example.php`      | Template for a local `config.php`. |
| `.github/workflows/`      | CI: PHP syntax check on PHP 7.4–8.4. |
| `.github/ISSUE_TEMPLATE/` | Bug report and feature request templates. |

## Contributing

Issues and pull requests are welcome. Please run `php -l index.php` before submitting, and if
you can, test by POSTing a sample report to a local `php -S` instance.

## License

Copyright (c) 2026, Paul Higgs. Released under the BSD 3-Clause License. See [LICENSE](LICENSE).

## Credits

Developed with the assistance of **Claude** (Opus 5.5), an AI model by
[Anthropic](https://www.anthropic.com), using [Claude Code](https://claude.com/claude-code).
