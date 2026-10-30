<p align="center"><a href="https://timknowsbest.com/free-dynamic-dns" target="_blank" rel="noopener noreferrer"><img width="1024" src="feature-graphic.jpg" alt="Cloudflare DDNS"/></a></p>

# 🌍 Cloudflare DDNS

Access your home network remotely via a custom domain name without a static IP!

A dynamic DNS client for Cloudflare, written in Rust: a ~1.1 MB static Docker image (built from `scratch`) that uses ~3.5 MB of RAM. Configure it with environment variables and it keeps your A/AAAA records — and optionally Cloudflare WAF IP lists — pointed at your current public IP.

[![Docker Pulls](https://img.shields.io/docker/pulls/timothyjmiller/cloudflare-ddns?style=flat&logo=docker&label=pulls)](https://hub.docker.com/r/timothyjmiller/cloudflare-ddns) [![Docker Image Size](https://img.shields.io/docker/image-size/timothyjmiller/cloudflare-ddns/latest?style=flat&logo=docker&label=image%20size)](https://hub.docker.com/r/timothyjmiller/cloudflare-ddns)

## ✨ Features

- **IPv4 and IPv6** with independent detection providers: Cloudflare trace (default), Cloudflare DNS-over-HTTPS, ipify, local routing table or interface, custom URL, or static IPs
- **Multi-homed hosts**: bind detection to a network interface (`ipify@eth1`) and give groups of domains their own providers
- **Many domains across many zones**, including wildcards (`*.example.com`); zones are found automatically
- **Outage-safe**: a failed IP lookup never deletes or overwrites your records, and Cloudflare's own anycast IPs are rejected
- **WAF IP lists** kept in sync with your addresses
- **Per-domain proxying** with expressions like `!is(vpn.example.com)`
- **Notifications** via shoutrrr-style URLs (Discord, Slack, Telegram, Gotify, Pushover, Zulip, generic webhooks)
- **Heartbeats** to Healthchecks.io and Uptime Kuma
- **Simple scheduling** (`@every 5m`, `@once`) with jitter, dry-run mode, and graceful shutdown with optional record cleanup
- **Record comments and comment regexes** to share a zone safely with other tools
- **Runs anywhere**: Docker (amd64, arm64, arm/v7, arm/v6, ppc64le) on Docker Hub and GHCR, Kubernetes/Helm, systemd, or a static binary from [releases](https://github.com/timothymiller/cloudflare-ddns/releases)

## Contents

- [Quick start](#-quick-start)
- [How it works](#-how-it-works)
- [Configuration](#-configuration)
- [Environment variable reference](#-environment-variable-reference)
- [Deployment](#-deployment)
- [Security notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Legacy config.json mode](#-legacy-configjson-mode)

## 🚀 Quick start

### 1. Create an API token

In the Cloudflare dashboard go to [**My Profile › API Tokens › Create Token**](https://dash.cloudflare.com/profile/api-tokens), choose **Create Custom Token**, and grant:

| Permission | Needed for |
|------------|------------|
| **Zone › DNS › Edit** | Creating, updating and deleting records |
| **Zone › Zone › Read** | Finding the zone each domain belongs to |
| **Account › Account Filter Lists › Edit** | Only if you use [`WAF_LISTS`](#waf-lists) |

Under **Zone Resources**, include only the zones you want to update.

### 2. Run it

```bash
docker run -d \
  --name cloudflare-ddns \
  --restart unless-stopped \
  --network host \
  -e CLOUDFLARE_API_TOKEN=your-api-token \
  -e DOMAINS=example.com,www.example.com \
  timothyjmiller/cloudflare-ddns:2.3.1
```

The container detects your public IPv4 and IPv6 addresses and updates the records every 5 minutes. Check `docker logs cloudflare-ddns` to see what it did.

`--network host` is only needed for IPv6 ([why](#ipv6-is-not-detected-in-docker)). For IPv4 only, drop it and add `-e IP6_PROVIDER=none`.

### 3. Or use Docker Compose

IPv4 only (no host networking needed):

```yaml
services:
  cloudflare-ddns:
    image: timothyjmiller/cloudflare-ddns:2.3.1
    container_name: cloudflare-ddns
    security_opt:
      - no-new-privileges:true
    environment:
      - CLOUDFLARE_API_TOKEN=your-api-token
      - DOMAINS=example.com,www.example.com
      - PROXIED=true
      - IP6_PROVIDER=none
      - HEALTHCHECKS=https://hc-ping.com/your-uuid
    restart: unless-stopped
```

For IPv4 + IPv6, add `network_mode: host` and remove `IP6_PROVIDER=none`. A ready-made file is in [`docker/docker-compose.yml`](docker/docker-compose.yml).

## 🔄 How it works

Every update cycle:

1. **Detect** the public IPv4 and IPv6 addresses with the configured providers (`cloudflare.trace` by default for both).
2. **Reject Cloudflare IPs.** Some lookups can return a Cloudflare anycast address instead of yours. Detected addresses inside [Cloudflare's published ranges](https://www.cloudflare.com/ips/) are discarded with a warning. The ranges are fetched on the first cycle and cached for 24 hours; if a refresh fails, the cached copy is kept. If they have never been fetched successfully, the cycle is skipped rather than risk writing a Cloudflare IP. Disable with `REJECT_CLOUDFLARE_IPS=false`.
3. **Update** each domain: find its zone, then create, update or delete its managed A/AAAA records so they match the detected addresses (duplicates are removed). WAF lists are then synced with all detected addresses.
4. **Report**: send a heartbeat (success or fail), and a notification if anything changed or failed.

By default the first update runs at startup, then every 5 minutes. After the first run, each scheduled update is delayed by a random 0–20% of the interval so that many installations don't hit the Cloudflare API at the same moment.

On `SIGTERM` (`docker stop`, Kubernetes, systemd) or `SIGINT` (Ctrl+C) the process stops right away, deletes its records if `DELETE_ON_STOP=true`, and sends a final heartbeat.

### Failure safety

A failed IP lookup never breaks your DNS. Two cases are distinguished:

- **Transient failure** — a network provider (`cloudflare.trace`, `cloudflare.doh`, `ipify`, `url:`) errored, every detected address was a Cloudflare IP, or the Cloudflare ranges were unavailable. The real IP is unknown, so that family's update is skipped and existing records are **always preserved**, whatever `DELETE_ON_FAILURE` says. If any family fails, WAF list updates are skipped entirely so that family's IPs aren't stripped from the list.
- **Definitive absence** — a deterministic provider (`none`, `literal:`, `local`, `local.iface:`, `local.iface.stable:`) reports that there is no address of that family. With the default `DELETE_ON_FAILURE=false` the update is skipped and records are preserved; with `DELETE_ON_FAILURE=true` the managed records of that family are deleted. (So `IP6_PROVIDER=none` together with `DELETE_ON_FAILURE=true` removes the AAAA records of everything in `DOMAINS`.)

Both cases send a fail heartbeat. A failed Cloudflare API write (create, update or delete) also counts as a failure: you get a fail heartbeat and a notification.

With `UPDATE_CRON=@once`, the process exits with code `1` if the update failed, so cron jobs and systemd can detect it.

## 🧰 Configuration

All settings are environment variables. Setting `CLOUDFLARE_API_TOKEN` (or `CLOUDFLARE_API_TOKEN_FILE`, `DOMAINS`, `IP4_DOMAINS`, `IP6_DOMAINS`) selects environment-variable mode; otherwise the program falls back to [legacy `config.json` mode](#-legacy-configjson-mode).

Invalid settings stop the program at startup with an error message instead of being silently ignored.

### Authentication

| Variable | Description |
|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | API token ([permissions](#1-create-an-api-token)) |
| `CLOUDFLARE_API_TOKEN_FILE` | Path to a file containing the token, e.g. a Docker or Kubernetes secret. Surrounding whitespace is trimmed |

Paste the token exactly as Cloudflare shows it. Surrounding quotes are stripped with a warning; a token containing spaces or other invalid characters is rejected at startup (the token itself is never logged). The placeholder `YOUR-CLOUDFLARE-API-TOKEN` from the examples is rejected too.

### Domains

| Variable | Description |
|----------|-------------|
| `DOMAINS` | Comma-separated domains to update with both IPv4 (A) and IPv6 (AAAA) |
| `IP4_DOMAINS` | Comma-separated domains to update with IPv4 only |
| `IP6_DOMAINS` | Comma-separated domains to update with IPv6 only |

Use fully-qualified names (`example.com`, `home.example.com`, `*.example.com`). The zone is looked up from the name, so domains from several zones can be mixed. At least one of `DOMAINS`, `IP4_DOMAINS`, `IP6_DOMAINS` or `WAF_LISTS` must be set.

### IP detection providers

| Variable | Default | Description |
|----------|---------|-------------|
| `IP4_PROVIDER` | `cloudflare.trace` | How to detect the IPv4 address |
| `IP6_PROVIDER` | `cloudflare.trace` | How to detect the IPv6 address |
| `REJECT_CLOUDFLARE_IPS` | `true` | Discard detected addresses inside Cloudflare's IP ranges |

| Provider | Description |
|----------|-------------|
| `cloudflare.trace` | Cloudflare's `/cdn-cgi/trace` (`cloudflare.com`, falling back to `api.cloudflare.com`), forced over the right address family |
| `cloudflare.trace:<url>` | Same, but using your own trace URL |
| `cloudflare.doh` | DNS-over-HTTPS `whoami.cloudflare` TXT query |
| `ipify` | `api4.ipify.org` / `api6.ipify.org` |
| `local` | Source address the OS would use to reach the internet (no request is sent). Must be a public address, so not useful behind NAT |
| `local.iface:<name>` | Public addresses on a network interface, e.g. `local.iface:eth0` |
| `local.iface.stable:<name>` | Linux, IPv6: the preferred stable address on an interface, skipping temporary (privacy) and deprecated addresses |
| `url:<url>` | Any `http(s)` URL that returns an IP address as plain text |
| `literal:<ips>` | Fixed addresses, separated by commas or spaces, e.g. `literal:203.0.113.10` |
| `none` | Don't manage this address family |

Add `@<interface>` to `cloudflare.trace`, `cloudflare.doh`, `ipify` or `url:` to send the detection request through a specific network interface, e.g. `IP4_PROVIDER=cloudflare.trace@ens5`.

Detected addresses must be global unicast: private, CGNAT (`100.64.0.0/10`), loopback and link-local addresses are ignored. An empty `IP4_PROVIDER` / `IP6_PROVIDER` counts as unset (the default applies), so use `none` to disable a family.

### Multiple interfaces and detection groups

On multi-homed hosts (cloud instances with several network interfaces, dual-WAN routers), numbered variables define extra detection groups, each with its own domains and providers:

```ini
DOMAINS=a.example.com                    # default group
DOMAINS_2=b.example.com                  # group 2
IP4_PROVIDER_2=cloudflare.trace@ens5     # IPv4 detected through ens5
IP6_PROVIDER_2=local.iface:ens5          # IPv6 read from ens5
```

Groups start at `_2`, and a family without its own provider uses the default group's. See [docs/multi-interface.md](docs/multi-interface.md) for the full rules and platform notes.

### Scheduling

| Variable | Default | Description |
|----------|---------|-------------|
| `UPDATE_CRON` | `@every 5m` | `@every <duration>` or `@once` |
| `UPDATE_ON_START` | `true` | Run an update immediately at startup |
| `DELETE_ON_STOP` | `false` | Delete managed records (and clear managed WAF list items) on shutdown |
| `DELETE_ON_FAILURE` | `false` | Delete managed records when a deterministic provider reports no address ([details](#failure-safety)) |

`UPDATE_CRON` is **not** a cron expression. Supported values:

- `@every <n>s`, `@every <n>m`, `@every <n>h` — e.g. `@every 30s`, `@every 10m`, `@every 1h`. A bare number is seconds (`@every 300`). Combined units (`1h30m`) are not supported. The minimum is 30 seconds; lower values are raised to 30s with a warning.
- `@once` — update once and exit. Requires `UPDATE_ON_START=true` and `DELETE_ON_STOP=false`.
- `@disabled` and `@nevermore` are deprecated aliases of `@once`.

### DNS records

| Variable | Default | Description |
|----------|---------|-------------|
| `TTL` | `1` | Record TTL in seconds. `1` = automatic, and values below 30 also mean automatic. Cloudflare accepts up to 86400 |
| `PROXIED` | `false` | Which domains are proxied through Cloudflare (expression below) |
| `RECORD_COMMENT` | — | Comment set on records this tool creates or updates |
| `MANAGED_RECORDS_COMMENT_REGEX` | — | Only records whose comment matches this regex are managed (updated or deleted). Empty = every A/AAAA record with a configured name |

`PROXIED` expressions:

| Expression | Meaning |
|------------|---------|
| `true` / `false` | Proxy all / no domains |
| `is(example.com)` | Proxy exactly `example.com` |
| `is(a.example.com, b.example.com)` | Proxy either name |
| `sub(example.com)` | Proxy `example.com` and all its subdomains |
| `!is(vpn.example.com)` | Proxy everything except `vpn.example.com` |
| `is(a.com) \|\| sub(b.com)` | Combine with `!`, `&&`, `\|\|` and parentheses |

To share a zone with other tools, give this tool's records a fixed comment and only manage records carrying it, e.g. `RECORD_COMMENT=managed by cloudflare-ddns` and `MANAGED_RECORDS_COMMENT_REGEX=^managed by cloudflare-ddns$`. Records without a matching comment are then never touched. A warning is logged if the comment doesn't match the regex.

### WAF lists

| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_LISTS` | — | Comma-separated IP lists as `account-id/list-name` |
| `WAF_LIST_DESCRIPTION` | — | Description used when a list has to be created |
| `WAF_LIST_ITEM_COMMENT` | — | Comment set on list items this tool adds |
| `MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX` | — | Only items whose comment matches are managed. Empty = all items in the list |

Each list ends up containing every detected address (IPv4 and IPv6). List names may only contain lowercase letters, digits and `_`. A list that doesn't exist yet is created. Requires the **Account › Account Filter Lists › Edit** permission. The account ID is in the dashboard URL (`dash.cloudflare.com/<account-id>`).

### Notifications

| Variable | Description |
|----------|-------------|
| `SHOUTRRR` | One or more notification URLs, **one per line** |

A notification is sent when a record or WAF list changes, or when an update fails.

| Service | URL format |
|---------|------------|
| Discord | `discord://token@webhook-id` |
| Slack | `slack://token-a/token-b/token-c` |
| Telegram | `telegram://bot-token@telegram?chats=chat-id` — only the first chat ID is used; messages are sent as plain text |
| Gotify | `gotify://host[:port]/app-token` or `gotify://host[:port]/path?token=app-token`. HTTPS by default; use `gotify+http://…` or add `?disabletls=yes` for plain HTTP |
| Pushover | `pushover://shoutrrr:api-token@user-key` (shoutrrr's format); `pushover://api-token@user-key` also works. Query parameters such as `?devices=` are ignored |
| Zulip | `zulip://bot-mail:bot-key@host/?stream=stream-name&topic=topic-name` — the `@` in the bot email may be literal or `%40`; `topic` defaults to `Cloudflare DDNS` |
| Generic webhook | `generic://host/path` (HTTPS), `generic+https://host/path`, `generic+http://host/path`, or a plain `https://…` / `http://…` URL |

Generic webhooks receive a JSON `POST` of `{"message": "..."}`; add `?messagekey=text` (or any field name) to rename the field.

To use several services, put each URL on its own line. In Docker Compose, use the map form of `environment` with a YAML block scalar:

```yaml
    environment:
      CLOUDFLARE_API_TOKEN: your-api-token
      DOMAINS: example.com
      SHOUTRRR: |
        discord://token@webhook-id
        telegram://bot-token@telegram?chats=123456789
```

A `.env` file or `docker run -e` holds a single line, so use those for one URL only.

### Heartbeats

| Variable | Description |
|----------|-------------|
| `HEALTHCHECKS` | Healthchecks.io ping URL, e.g. `https://hc-ping.com/<uuid>` |
| `UPTIMEKUMA` | Uptime Kuma push URL, e.g. `https://kuma.example.com/api/push/<token>` |

A heartbeat is sent at startup, after every update cycle (success or fail), and at shutdown. For Uptime Kuma, create a **Push** monitor and paste its URL; the `?status=up&msg=OK&ping=` part that Uptime Kuma shows is removed automatically.

### Timeouts and output

| Variable | Default | Description |
|----------|---------|-------------|
| `DETECTION_TIMEOUT` | `5s` | Timeout for each IP detection request |
| `UPDATE_TIMEOUT` | `30s` | Timeout for each Cloudflare API request |
| `EMOJI` | `true` | Use emoji in log output |
| `QUIET` | `false` | Only log warnings and errors |

### Value formats

- **Booleans**: `true`, `1` or `yes` (any case) mean true. **Anything else is false** — including `on` and typos.
- **Durations**: a number followed by `s`, `m` or `h` (`30s`, `5m`, `1h`). A bare number is seconds.
- **Lists**: comma-separated; whitespace around entries is trimmed and empty entries are ignored. `SHOUTRRR` is newline-separated.
- **Empty values**: a variable set to an empty string is treated as unset, so the default applies.

### CLI flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Log what would change without writing to Cloudflare |
| `--repeat` | Legacy mode only: keep running (environment-variable mode uses `UPDATE_CRON`). The Docker image always passes it |
| `--health` | Exit 0 if the running update loop has checked in on schedule, 1 otherwise. Used by the image's `HEALTHCHECK`; a failed update does not make it unhealthy, only a stalled loop |

## 📋 Environment variable reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | — | API token |
| `CLOUDFLARE_API_TOKEN_FILE` | — | File containing the API token |
| `DOMAINS` | — | Domains for A and AAAA records |
| `IP4_DOMAINS` | — | Domains for A records only |
| `IP6_DOMAINS` | — | Domains for AAAA records only |
| `IP4_PROVIDER` | `cloudflare.trace` | IPv4 detection provider |
| `IP6_PROVIDER` | `cloudflare.trace` | IPv6 detection provider |
| `DOMAINS_N`, `IP4_DOMAINS_N`, `IP6_DOMAINS_N`, `IP4_PROVIDER_N`, `IP6_PROVIDER_N` | — | Detection group N (N ≥ 2); see [multiple interfaces](#multiple-interfaces-and-detection-groups) |
| `REJECT_CLOUDFLARE_IPS` | `true` | Discard detected Cloudflare IPs |
| `UPDATE_CRON` | `@every 5m` | `@every <duration>` (min 30s) or `@once` |
| `UPDATE_ON_START` | `true` | Update immediately at startup |
| `DELETE_ON_STOP` | `false` | Delete managed records on shutdown |
| `DELETE_ON_FAILURE` | `false` | Delete managed records when a deterministic provider finds no address |
| `TTL` | `1` | Record TTL in seconds (`1` = auto) |
| `PROXIED` | `false` | Proxy expression |
| `RECORD_COMMENT` | — | Comment on managed records |
| `MANAGED_RECORDS_COMMENT_REGEX` | — | Regex selecting managed records by comment |
| `WAF_LISTS` | — | WAF IP lists, `account-id/list-name` |
| `WAF_LIST_DESCRIPTION` | — | Description for newly created lists |
| `WAF_LIST_ITEM_COMMENT` | — | Comment on managed list items |
| `MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX` | — | Regex selecting managed list items by comment |
| `SHOUTRRR` | — | Notification URLs, one per line |
| `HEALTHCHECKS` | — | Healthchecks.io ping URL |
| `UPTIMEKUMA` | — | Uptime Kuma push URL |
| `DETECTION_TIMEOUT` | `5s` | IP detection timeout |
| `UPDATE_TIMEOUT` | `30s` | Cloudflare API timeout |
| `EMOJI` | `true` | Emoji in output |
| `QUIET` | `false` | Only warnings and errors |
| `HEALTH_FILE` | `/tmp/cloudflare-ddns.health` | Liveness file written by the update loop and read by `--health` |

Legacy mode additionally reads `CONFIG_PATH` and `CF_DDNS_*` — see [docs/legacy-config.md](docs/legacy-config.md).

### Deprecated aliases

| Variable | Status |
|----------|--------|
| `CF_API_TOKEN` | Alias of `CLOUDFLARE_API_TOKEN` (warning logged) |
| `CF_API_TOKEN_FILE` | Alias of `CLOUDFLARE_API_TOKEN_FILE` (warning logged) |
| `IP4_POLICY` | Alias of `IP4_PROVIDER` (warning logged) |
| `IP6_POLICY` | Alias of `IP6_PROVIDER` (warning logged) |
| `CF_ACCOUNT_ID` | Ignored, may log a warning. The account ID goes in `WAF_LISTS` |
| `PUID`, `PGID` | Ignored (warning logged). Use Docker's `user:` / `--user` instead |

## 🚢 Deployment

### Docker Compose

- [`docker/docker-compose.yml`](docker/docker-compose.yml) — environment-variable mode
- [`docker/docker-compose.legacy.yml`](docker/docker-compose.legacy.yml) — legacy `config.json` mode

To keep the token out of the compose file, use a secret:

```yaml
services:
  cloudflare-ddns:
    image: timothyjmiller/cloudflare-ddns:2.3.1
    container_name: cloudflare-ddns
    security_opt:
      - no-new-privileges:true
    network_mode: host
    environment:
      - CLOUDFLARE_API_TOKEN_FILE=/run/secrets/cloudflare_api_token
      - DOMAINS=example.com,www.example.com
    secrets:
      - cloudflare_api_token
    restart: unless-stopped

secrets:
  cloudflare_api_token:
    file: ./cloudflare_api_token.txt
```

### Kubernetes with Helm (recommended)

The chart is published to GHCR as an OCI artifact.

```bash
helm install cloudflare-ddns oci://ghcr.io/timothymiller/cloudflare-ddns \
  --namespace ddns --create-namespace \
  -f values.yaml
```

```yaml
# values.yaml
cloudflare:
  apiToken: your-api-token        # or existingSecret: my-secret

domains: example.com,www.example.com
ip6Provider: cloudflare.trace     # "none" for IPv4 only (then hostNetwork: false is fine)
proxied: "true"

shoutrrr: |
  discord://token@webhook-id
healthchecks: https://hc-ping.com/your-uuid
```

Use a values file rather than `--set` for domain lists: `--set` treats commas as separators.

Upgrade with `helm upgrade cloudflare-ddns oci://ghcr.io/timothymiller/cloudflare-ddns -n ddns -f values.yaml`; remove with `helm uninstall cloudflare-ddns -n ddns`.

| Value | Default | Description |
|-------|---------|-------------|
| `cloudflare.apiToken` | `""` | API token, stored in a chart-managed Secret |
| `cloudflare.existingSecret` | `""` | Use your own Secret instead. It must hold the token (under `cloudflare.existingSecretKey`, default `CLOUDFLARE_API_TOKEN`) and may hold `SHOUTRRR`, `HEALTHCHECKS`, `UPTIMEKUMA` |
| `domains`, `ip4Domains`, `ip6Domains` | `""` | Domains (comma-separated) |
| `wafLists`, `wafListDescription`, `wafListItemComment`, `managedWafListItemsCommentRegex` | `""` | WAF list settings |
| `ip4Provider`, `ip6Provider` | `cloudflare.trace` | Detection providers |
| `rejectCloudflareIps` | `true` | `REJECT_CLOUDFLARE_IPS` |
| `updateCron`, `updateOnStart`, `deleteOnStop`, `deleteOnFailure` | `@every 5m`, `true`, `false`, `false` | Scheduling |
| `ttl`, `proxied`, `recordComment`, `managedRecordsCommentRegex` | `1`, `"false"`, `""`, `""` | Record settings |
| `shoutrrr`, `healthchecks`, `uptimeKuma` | `""` | Stored in the chart's Secret. Not allowed together with `existingSecret` — add them to that Secret instead |
| `hostNetwork` | `true` | Needed for IPv6 detection; set `false` for IPv4 only |
| `podSecurityContext`, `securityContext` | non-root (65534), read-only root FS, all capabilities dropped, `RuntimeDefault` seccomp | Override if needed |
| `extraEnv` | `[]` | Any other environment variables |

The Deployment uses the `Recreate` strategy so two pods never update the same records at once. See [`charts/cloudflare-ddns/values.yaml`](charts/cloudflare-ddns/values.yaml) for all values.

### Kubernetes manifest

[`k8s/cloudflare-ddns.yml`](k8s/cloudflare-ddns.yml) creates a `ddns` namespace, a Secret with the token, and a single-replica Deployment. Edit the token and `DOMAINS`, then:

```bash
kubectl apply -f k8s/cloudflare-ddns.yml
kubectl -n ddns logs deploy/cloudflare-ddns
```

The legacy `config.json` variant is [`k8s/cloudflare-ddns.legacy.yml`](k8s/cloudflare-ddns.legacy.yml).

### systemd

The units in [`systemd/`](systemd) run one update every 15 minutes from a timer, as a sandboxed dynamic user.

```bash
cargo build --release
sudo install -m 755 target/release/cloudflare-ddns /usr/local/bin/cloudflare-ddns

sudo install -d -m 700 /etc/cloudflare-ddns
sudo tee /etc/cloudflare-ddns/env >/dev/null <<'EOF'
CLOUDFLARE_API_TOKEN=your-api-token
DOMAINS=example.com,www.example.com
EOF
sudo chmod 600 /etc/cloudflare-ddns/env

sudo cp systemd/cloudflare-ddns.service systemd/cloudflare-ddns.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflare-ddns.timer
journalctl -u cloudflare-ddns.service
```

The service sets `UPDATE_CRON=@once`; don't set `UPDATE_CRON` or `DELETE_ON_STOP` in the env file. Change the interval in `cloudflare-ddns.timer`. For legacy `config.json` with systemd, see [docs/legacy-config.md](docs/legacy-config.md#systemd).

### Build from source

```bash
cargo build --release          # binary: target/release/cloudflare-ddns
./scripts/docker-build.sh      # Docker image, linux/amd64
./scripts/docker-build-all.sh  # linux/amd64, linux/arm64, linux/arm/v7, linux/arm/v6, linux/ppc64le
```

## 🔒 Security notes

- **Pin the image tag.** Images are tagged with the full version (`2.3.1`), minor (`2.3`), major (`2`) and `latest` — there is no `v` prefix. Use `2.3.1` (or at least `2.3`) in production and upgrade deliberately after reading the [changelog](CHANGELOG.md).
- **Scope the token** to the permissions and zones [listed above](#1-create-an-api-token). Never use the Global API Key.
- **Keep the token out of compose files and shell history**: use `CLOUDFLARE_API_TOKEN_FILE` with a Docker or Kubernetes secret, or a mode-`600` env file for systemd. Notification and heartbeat URLs contain credentials too.
- **Host networking** (`--network host`) gives the container the host's full network stack. Use it only for IPv6 or `local`/`local.iface` detection; IPv4-only setups don't need it.
- **The image runs as a non-root user** (UID/GID 65534). Mounted files (`config.json`, the token file) must be readable by that user, or pass `--user` with the file owner's UID. `security_opt: no-new-privileges:true` is recommended. The Helm chart and `k8s/` manifest also use a read-only root filesystem and no capabilities.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## 🩺 Troubleshooting

### "Permission denied" reading config.json or the token file

The image runs as UID 65534, which can't read a file with mode `600` owned by another user. Run `chmod 644` on the file, or start the container with `--user <uid>:<gid>` of the file's owner (Compose: `user: "1000:1000"`).

### IPv6 is not detected in Docker

Docker's default bridge network has no IPv6 connectivity, so `cloudflare.trace` can't reach Cloudflare over IPv6, and interface providers only see the container's own interfaces. Run with `--network host` (Compose: `network_mode: host`; Helm: `hostNetwork: true`). If you don't need IPv6, set `IP6_PROVIDER=none`.

### Wrong or rejected IP with Cloudflare WARP / Zero Trust

When the host runs WARP, traffic to Cloudflare leaves through WARP, so the trace endpoint sees a Cloudflare egress address. Those are rejected (`Rejected …: matches Cloudflare IP range`) and the update is skipped. Exclude `cloudflare.com` and `api.cloudflare.com` from the WARP tunnel (split tunnel), or use a provider that doesn't go through WARP — e.g. `IP4_PROVIDER=ipify`, `url:<your-endpoint>`, or `local.iface:<name>`.

### "WAF list … not found"

Missing lists are created automatically, so this usually means the token lacks **Account › Account Filter Lists › Edit** for that account, or the account ID in `WAF_LISTS` is wrong. Also check that the list name uses only lowercase letters, digits and `_`.

### Uptime Kuma shows the monitor as down

Use the URL of a **Push** monitor (`https://<host>/api/push/<token>`); pasting it with `?status=up&msg=OK&ping=` is fine. Set the monitor's heartbeat interval longer than `UPDATE_CRON` plus the 20% jitter (e.g. 7 minutes for the default 5).

### "Invalid format for Authorization header"

Cloudflare didn't recognise the value as an API token. Either it is the wrong credential (the Global API Key, a token ID, or a revoked token), or it reached Cloudflare with extra characters such as quotes or whitespace. Use the token value shown once when the token is created. In Compose's list syntax (`- CLOUDFLARE_API_TOKEN="abc"`) the quotes become part of the value; write `- CLOUDFLARE_API_TOKEN=abc`. Surrounding quotes are stripped with a warning and tokens containing whitespace are rejected at startup, so check the first log lines. With `CLOUDFLARE_API_TOKEN_FILE`, the file must contain only the token (a trailing newline is fine).

### "Could not find zone for domain"

The token can't see the zone: add **Zone › Zone › Read** and include the zone under **Zone Resources**.

## 📁 Legacy config.json mode

The original `config.json` format still works. It is used only when none of `CLOUDFLARE_API_TOKEN`, `CF_API_TOKEN`, `CLOUDFLARE_API_TOKEN_FILE`, `CF_API_TOKEN_FILE`, `DOMAINS`, `IP4_DOMAINS`, `IP6_DOMAINS` is set. See **[docs/legacy-config.md](docs/legacy-config.md)** for the format, which environment variables still apply, and a migration table. Example file: [`config-example.json`](config-example.json).

## 🔗 Helpful links

- [Cloudflare API tokens](https://dash.cloudflare.com/profile/api-tokens) ([how to create one](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/))
- [Find your zone and account IDs](https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/)
- [Cloudflare IP ranges](https://www.cloudflare.com/ips/)

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md).

## 📜 License

This project is licensed under the GNU General Public License, version 3 (GPLv3).

## 👨‍💻 Author

Timothy Miller

[View my GitHub profile 💡](https://github.com/timothymiller)

[View my personal website 💻](https://itstmillertime.com)
