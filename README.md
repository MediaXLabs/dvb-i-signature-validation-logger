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

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **PHP 7.4 or later** | PHP 8.x is recommended. CI checks syntax on 7.4 to 8.4. |
| **`pdo_sqlite` extension** | Used to store reports. No database server is needed. |
| **`json` extension** | Built into PHP 8; enabled by default in most PHP 7.4 builds. |
| **A web server that runs PHP** | Apache with `mod_php` or PHP-FPM, nginx with PHP-FPM, or IIS with PHP via FastCGI. |
| **HTTPS** (recommended) | The W3C Reporting API only delivers reports to secure (`https://`) endpoints, so browser-based DVB-I clients need the collector to have a valid TLS certificate. The collector itself also accepts plain HTTP, which is useful for testing or for clients that don't use the Reporting API, but reports and lookups then travel unencrypted. To enforce HTTPS, set `https_only` to `true` (see [Configuration](#configuration)) or redirect HTTP in the web server configuration. |
| **A writable data directory** | The web server's user must be able to create and write the SQLite database **and its directory**. SQLite creates `-wal` and `-shm` files next to the database. |
| **Outbound DNS** (optional) | Used for the reverse lookup of senders (`reverse_dns`) and for hostname searches in the web UI. |
| **POST and OPTIONS allowed** | The server must pass `POST` (report delivery) and `OPTIONS` (CORS pre-flight) requests through to PHP, as well as `GET`. |

To check that PHP has the extensions it needs:

```sh
php -v
php -m | grep -i -E 'pdo_sqlite|json'
```

If `pdo_sqlite` is missing, install it:

| Platform | Command / action |
|----------|------------------|
| Debian / Ubuntu | `sudo apt install php-sqlite3`, then restart the web server or PHP-FPM |
| RHEL / Fedora / Rocky | `sudo dnf install php-pdo`, then restart the web server or PHP-FPM |
| Alpine | `apk add php83-pdo_sqlite` (match your PHP version) |
| Windows | In `php.ini`, uncomment `extension=pdo_sqlite` (and `extension=sqlite3`), then restart IIS or the PHP service |

Remember that the command-line PHP and the web server's PHP may use different `php.ini` files.
To check the web server's PHP, look at `phpinfo()` output.

## Installation

The steps below install the collector at `https://example.com/dvbi-reports/`. Adjust the paths
and hostname to suit your server.

### 1. Copy the files

```sh
sudo mkdir -p /var/www/html/dvbi-reports
sudo cp index.php /var/www/html/dvbi-reports/
```

Only `index.php` is required. If you want to change any settings, also copy
`config.example.php` to `config.php` in the same directory and edit it
(see [Configuration](#configuration)).

### 2. Create the data directory

The recommended setup keeps the database **outside the web root**:

```sh
sudo mkdir -p /var/lib/dvbi-reports
sudo chown www-data:www-data /var/lib/dvbi-reports   # nginx/RHEL: use nginx or apache
sudo chmod 770 /var/lib/dvbi-reports
```

and in `/var/www/html/dvbi-reports/config.php`:

```php
<?php
return ['db_path' => '/var/lib/dvbi-reports/reports.sqlite'];
```

To use the default instead (`data/` next to `index.php`), make the install directory writable by
the web server user, or create `data/` yourself and give that user ownership of it. **You must
then make sure `data/` cannot be downloaded**, as described for each web server below.

If SELinux is enforcing (RHEL family), also allow the web server to write to the data directory:

```sh
sudo semanage fcontext -a -t httpd_sys_rw_content_t '/var/lib/dvbi-reports(/.*)?'
sudo restorecon -R /var/lib/dvbi-reports
```

### 3. Configure the web server

#### Apache

With `mod_php` or PHP-FPM already set up, no extra configuration is usually needed:
`index.php` is served as the directory index.

If you keep the database in `data/` under the web root, the collector writes a `.htaccess` file
that denies access to it. This only takes effect if `.htaccess` files are allowed for that
directory (`AllowOverride All`, or at least `AllowOverride AuthConfig Limit`). If they aren't,
block the directory explicitly:

```apache
<Directory "/var/www/html/dvbi-reports/data">
    Require all denied
</Directory>
```

#### nginx + PHP-FPM

```nginx
location /dvbi-reports/ {
    index index.php;
}

# Only needed if the database is kept in data/ under the web root
location ^~ /dvbi-reports/data/ {
    deny all;
}

location ~ ^/dvbi-reports/.+\.php$ {
    include snippets/fastcgi-php.conf;          # Debian/Ubuntu; elsewhere include fastcgi_params
    fastcgi_pass unix:/run/php/php8.3-fpm.sock; # match your PHP-FPM socket
}
```

nginx ignores `.htaccess`, so the `data/` block above is essential if you use the default
`db_path`. Reload nginx afterwards (`sudo nginx -t && sudo systemctl reload nginx`).

#### IIS (Windows)

1. Install PHP for IIS (FastCGI). Make sure the PHP handler mapping accepts **all verbs**, or at
   least `GET, HEAD, POST, OPTIONS`. Some installations allow only `GET,HEAD,POST`, which makes
   CORS pre-flight requests fail.
2. Add `index.php` to the site's **Default Document** list.
3. Give the application pool identity (e.g. `IIS AppPool\DefaultAppPool`) **Modify** permission
   on the data directory.
4. If the database is in `data/` under the site, hide that directory with a `web.config` next to
   `index.php`:

   ```xml
   <configuration>
     <system.webServer>
       <security>
         <requestFiltering>
           <hiddenSegments>
             <add segment="data" />
           </hiddenSegments>
         </requestFiltering>
       </security>
     </system.webServer>
   </configuration>
   ```

#### Behind a reverse proxy or load balancer

Set `trusted_proxies` in `config.php` to the proxy addresses so reports are recorded against the
real client address from `X-Forwarded-For`, and make sure the proxy passes `POST` and `OPTIONS`
requests through.

### 4. Check the installation

1. Open `https://example.com/dvbi-reports/` in a browser. You should see the lookup form and the
   `Reporting-Endpoints` header to use. An "Internal error" page usually means PHP can't create
   or write the database; check the web server's PHP error log.
2. Send a test report:

   ```sh
   curl -i -X POST https://example.com/dvbi-reports/ \
     -H 'Content-Type: application/reports+json' \
     -d '[{"type":"signature-verification-issue","age":0,"url":"https://example.com/test.xml","user-agent":"curl-test","body":{"policy":"test"}}]'
   ```

   The response should be `HTTP/1.1 204 No Content`.
3. Look up your own address (shown on the home page) in the web UI. The test report should
   be listed.
4. Check that the database can't be downloaded. For example,
   `curl -I https://example.com/dvbi-reports/data/reports.sqlite` should return `403` or `404`.

### 5. Point DVB-I clients at the collector

Configure the DVB-I endpoint (the server that delivers the service list) to send this
response header:

```
Reporting-Endpoints: dvbi-signature-validation="https://example.com/dvbi-reports/"
```

The collector's home page shows this header with the correct URL for your installation.

### Quick local test

To try the collector without a web server, run PHP's built-in server from the project directory:

```sh
php -S localhost:8080
```

Then open <http://localhost:8080/> in a browser. This is for testing only: it is not suitable for
production, and DVB-I clients won't send reports to a non-HTTPS address other than `localhost`.

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
| `https_only`           | `false`                  | `true` accepts HTTPS connections only, for both report delivery (`POST`) and viewing (`GET`). Plain HTTP `GET`/`HEAD` requests are redirected (`301`) to HTTPS; other HTTP requests get `403`. HTTPS responses then carry a `Strict-Transport-Security` header. Behind a TLS-terminating proxy, list it in `trusted_proxies` so its `X-Forwarded-Proto` header is trusted. |

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
  Set `https_only` to `true` to refuse plain HTTP connections.

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
