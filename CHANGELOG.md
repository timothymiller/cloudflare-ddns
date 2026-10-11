# Changelog

All notable changes to this project are documented here, newest first.
Docker images are published as `timothyjmiller/cloudflare-ddns:<version>`
(for example `2.2.0`, `2.2`, `2`; there is no `v` prefix).

## Unreleased

### Behavior changes

- **Graceful shutdown on SIGTERM as well as SIGINT.** `docker stop`,
  Kubernetes pod termination and systemd now trigger the same shutdown path
  as Ctrl+C: `DELETE_ON_STOP` cleanup runs and the exit heartbeat is sent.
  Waits between updates are interruptible, so shutdown is immediate.
- **Failed Cloudflare writes are reported as failures.** A failed create,
  update or delete now sends a fail heartbeat and a notification instead of
  being logged and treated as success.
- **Invalid settings are startup errors.** An invalid
  `MANAGED_RECORDS_COMMENT_REGEX`, `MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX`,
  `PROXIED` expression, `WAF_LISTS` entry, `TTL`, `DETECTION_TIMEOUT` or
  `UPDATE_TIMEOUT` now stops the process with an error instead of silently
  falling back to a default (or silently dropping the entry).
- **`UPDATE_CRON` minimum interval is 30s.** Lower `@every` values are
  clamped to 30s with a warning.
- **Legacy `--repeat` interval.** In legacy `config.json` mode the polling
  interval is the TTL, but never less than 300s when the TTL is 1 (auto);
  any `ttl` below 30 now polls every 300s instead of every second.
- **Exit code.** One-shot runs (`UPDATE_CRON=@once`, or legacy mode without
  `--repeat`) exit with code 1 if the update failed.
- **Uptime Kuma URL.** A query string on `UPTIMEKUMA` (such as the
  `?status=up&msg=OK&ping=` that Uptime Kuma shows) is stripped
  automatically, so both the bare push URL and the copied URL work.
- **API token validation.** Surrounding quotes on the token are stripped
  with a warning; a token containing whitespace or other invalid characters
  is a clear startup error (the token itself is never printed). In legacy
  mode an empty or placeholder token is a startup error.
- **WAF lists are created if missing.** A list named in `WAF_LISTS` that does
  not exist is created, using `WAF_LIST_DESCRIPTION` as its description
  (requires the Account Filter Lists Edit permission).
- **Telegram messages are sent as plain text** (no Markdown parse mode), so
  domain names with `_` or `*` no longer break delivery.
- **Logging.** Heartbeat and notification failures are logged with the HTTP
  status; secrets in notification URLs are redacted in logs.

### Documentation and deployment

- README restructured: quick start with exact token permissions, how-it-works
  section, configuration by topic, one canonical environment variable
  reference, deployment, security notes and troubleshooting.
- Legacy `config.json` mode documented separately in
  [`docs/legacy-config.md`](docs/legacy-config.md), including a migration
  table to environment variables.
- Corrected documentation: the IPv4 default provider is `cloudflare.trace`
  (#294); Pushover URL is `pushover://shoutrrr:api-token@user-key`;
  scheduling supports `@every`/`@once` only (not cron expressions).
- `docker/docker-compose.yml` is now environment-variable mode; the legacy
  file is `docker/docker-compose.legacy.yml`. Obsolete `version:` and
  `PUID`/`PGID` removed.
- systemd unit: absolute `ExecStart`, optional
  `EnvironmentFile=/etc/cloudflare-ddns/env` for environment-variable mode,
  and sandboxing (`DynamicUser`, `ProtectSystem=strict`, ...).
- Helm chart 0.2.0 (appVersion 2.2.0): notification and heartbeat URLs moved
  into the Secret, `existingSecret` can carry them, new `deleteOnFailure`,
  `rejectCloudflareIps`, `wafListDescription`, `wafListItemComment` and
  `managedWafListItemsCommentRegex` values, restricted security context and
  `Recreate` strategy.
- `k8s/cloudflare-ddns.yml` rewritten for environment-variable mode (legacy
  manifest kept as `k8s/cloudflare-ddns.legacy.yml`).
- Legacy `config.json` now supports `recordComment` (#289).
- Release notes consolidated into this changelog.

## 2.2.0 — Zulip notifications, safer failure handling & Helm chart

### ⚠️ Behavior change: `DELETE_ON_FAILURE` now defaults to `false` (#277)

Previously, when a provider definitively reported no address for an IP
family, managed DNS records for that family were **deleted** by default,
which could take services offline after a transient misdetection.

- `DELETE_ON_FAILURE` now defaults to **`false`**: on detection failure the
  update is skipped and existing records are preserved.
- Transient detection errors (network failures) always preserve existing
  records, regardless of this setting.
- WAF list updates are skipped when any configured IP family fails
  detection, so a partial failure cannot strip that family's IPs from the
  list.

If you relied on the old behavior, set `DELETE_ON_FAILURE=true` explicitly.

### New features

- **Zulip notifications (#271).** Native
  `zulip://bot-mail:bot-key@host/?stream=stream-name&topic=topic-name`
  support. The `@` in the bot email may be literal or `%40`; `topic` is
  optional and defaults to `Cloudflare DDNS`.
- **Configurable JSON field for generic webhooks (#271).** Generic webhooks
  send `{"message": "..."}`; append `?messagekey=<field>` to rename the
  field (e.g. `?messagekey=text` for Slack-style payloads).
- **Stable local IPv6 provider (#273).** `local.iface.stable:<name>` selects
  the preferred stable IPv6 address of a Linux interface, excluding
  temporary (privacy-extension) and deprecated addresses.
- **Helm chart (#278).** `charts/cloudflare-ddns`, published as an OCI
  artifact to GHCR.

### Dependencies

- reqwest 0.13.4, rustls 0.23.42, tokio 1.52.4, rand 0.10.2,
  serde_json 1.0.150, actions/checkout 7

## 2.1.2 — Notification & domain casing fixes

### Bug fixes

- **Mixed-case domains match existing DNS records (#255).** Domains such as
  `ExaMple.com` caused duplicate-create attempts failing with Cloudflare
  error `81058`. Record lookup is now case-insensitive.
- **Pushover notifications work again (#258).** The canonical shoutrrr form
  `pushover://shoutrrr:TOKEN@USER` no longer leaks the `shoutrrr:` prefix
  into the API token. Optional shoutrrr query parameters (`?devices=`,
  `?priority=`) are tolerated (ignored).
- **Gotify notifications produce a valid request URL (#262).** The token may
  be the last path segment or a `?token=` query parameter; `?disabletls=yes`
  switches to HTTP, and `gotify+http://` / `gotify+https://` are accepted.

### Already addressed (closing #257)

Multi-endpoint trace fallback, strict address-family validation, API request
timeouts and duplicate record cleanup were already part of the Rust port
shipped in 2.0.8.

## 2.1.1

### Features

- `DELETE_ON_FAILURE` environment variable controls whether DNS records are
  removed when IP detection reports no address (#263, thanks @DMaxter).
  It defaulted to `true` in this release; the default changed to `false` in
  2.2.0.
- Proportional jitter (up to 20% of the update interval) before each
  scheduled update, to spread requests across clients (#253, thanks
  @jhutchings1).

### Fixes

- Build fix for `rand` 0.10 (`random_range` moved to the `RngExt` trait).
- Regression tests for `delete_on_failure`.

### Dependencies

- rustls 0.23.37 → 0.23.40, rustls-webpki 0.103.10 → 0.103.13,
  tokio 1.50.0 → 1.52.1, reqwest 0.13.2 → 0.13.3, rand 0.9.2 → 0.10.1

Older releases: see the
[GitHub releases page](https://github.com/timothymiller/cloudflare-ddns/releases).
