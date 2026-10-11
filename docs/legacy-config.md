# Legacy `config.json` mode

cloudflare-ddns still reads the `config.json` format used by the original
Python version, so existing deployments keep working. **New deployments
should use environment variables** (see the [README](../README.md)); legacy
mode lacks WAF lists, `PROXIED` expressions, configurable scheduling, timeouts
and output settings, and `DELETE_ON_STOP`.

- [When legacy mode is used](#when-legacy-mode-is-used)
- [Quick start](#quick-start)
- [File location](#file-location)
- [Keys](#keys)
- [Environment variables in legacy mode](#environment-variables-in-legacy-mode)
- [Variable substitution](#variable-substitution)
- [`purgeUnknownRecords`](#purgeunknownrecords)
- [Running continuously (`--repeat`)](#running-continuously---repeat)
- [Deployment](#deployment)
- [Examples](#examples)
- [Migrating to environment variables](#migrating-to-environment-variables)

## When legacy mode is used

The mode is chosen at startup. If **any** of these environment variables is
set to a non-empty value, cloudflare-ddns runs in environment-variable mode
and `config.json` is ignored:

`CLOUDFLARE_API_TOKEN`, `CF_API_TOKEN`, `CLOUDFLARE_API_TOKEN_FILE`,
`CF_API_TOKEN_FILE`, `DOMAINS`, `IP4_DOMAINS`, `IP6_DOMAINS`

Otherwise it loads `config.json`. The first log lines say which mode is
active: `Using config.json configuration` or
`Using environment variable configuration`.

## Quick start

```bash
cp config-example.json config.json
# edit config.json
cloudflare-ddns            # one update, then exit
cloudflare-ddns --repeat   # keep running
```

The API token needs **Zone › DNS › Edit** and **Zone › Zone › Read** on each
zone listed in the file. A missing token (when no `api_key` is given), or the
`api_token_here` placeholder from the example, is a startup error.

## File location

The file is read from `$CONFIG_PATH/config.json`. `CONFIG_PATH` defaults to
the current working directory (`/` inside the Docker image, so mount the file
at `/config.json`).

```bash
CONFIG_PATH=/etc/cloudflare-ddns cloudflare-ddns
```

## Keys

### Top level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cloudflare` | array | required | Zone entries (see below) |
| `a` | bool | `true` | Update IPv4 (A) records |
| `aaaa` | bool | `true` | Update IPv6 (AAAA) records |
| `purgeUnknownRecords` | bool | `false` | Delete duplicate records and, on definitive IP absence, records of that type (see [below](#purgeunknownrecords)) |
| `ttl` | int | `300` | Record TTL in seconds. Values below 30 become `1` (auto). Also the `--repeat` interval |
| `ip4_provider` | string | `"cloudflare.trace"` | IPv4 detection provider |
| `ip6_provider` | string | `"cloudflare.trace"` | IPv6 detection provider |
| `recordComment` | string | — | Comment set on every record this tool writes (`record_comment` is accepted as an alias) |

`ip4_provider` / `ip6_provider` accept the same values as `IP4_PROVIDER` /
`IP6_PROVIDER` in the README: `cloudflare.trace`, `cloudflare.trace:<url>`,
`cloudflare.doh`, `ipify`, `local`, `local.iface:<name>`,
`local.iface.stable:<name>`, `url:<url>`, `literal:<ips>`, `none`. Setting a
provider to `none` disables that family even if `a`/`aaaa` is `true`.

### Zone entries (`cloudflare[]`)

| Key | Type | Description |
|-----|------|-------------|
| `authentication.api_token` | string | API token (recommended) |
| `authentication.api_key` | object | Legacy Global API Key: `{ "api_key": "...", "account_email": "..." }`. Still accepted, not recommended |
| `zone_id` | string | Zone ID (Cloudflare dashboard › your domain › Overview › API section) |
| `subdomains` | array | Records to manage in this zone |
| `proxied` | bool | Default `proxied` for string subdomain entries (default `false`) |

Each zone entry carries its own credentials, so different zones can use
different tokens.

### Subdomains

Entries are either a string or an object:

```json
"subdomains": [
  "",
  "@",
  "www",
  { "name": "vpn", "proxied": false }
]
```

- `""` and `"@"` mean the zone apex. Do not include the zone name
  (`"www"`, not `"www.example.com"`).
- A string entry uses the zone's `proxied` value.
- The object form **requires both `name` and `proxied`**. An object missing
  either key makes the whole file fail to parse.

## Environment variables in legacy mode

| Variable | Applies in legacy mode |
|----------|------------------------|
| `CONFIG_PATH` | Yes — directory containing `config.json` |
| `CF_DDNS_*` | Yes — [substituted into the file](#variable-substitution) |
| `SHOUTRRR` | Yes — notifications |
| `HEALTHCHECKS` | Yes — heartbeat |
| `UPTIMEKUMA` | Yes — heartbeat |
| `REJECT_CLOUDFLARE_IPS` | Yes — default `true` |
| Everything else | **Ignored** — including `IP4_PROVIDER`, `IP6_PROVIDER`, `TTL`, `PROXIED`, `RECORD_COMMENT`, `UPDATE_CRON`, `UPDATE_ON_START`, `DELETE_ON_STOP`, `DELETE_ON_FAILURE`, `WAF_*`, `MANAGED_*`, `DETECTION_TIMEOUT` (fixed 5s), `UPDATE_TIMEOUT` (fixed 30s), `EMOJI` (off), `QUIET` (off) |

Remember that setting `CLOUDFLARE_API_TOKEN`, `DOMAINS`, `IP4_DOMAINS` or
`IP6_DOMAINS` does not "add" to legacy mode — it switches to
environment-variable mode.

## Variable substitution

Before parsing, every environment variable whose name starts with `CF_DDNS_`
is substituted into the file. Both `$VAR` and `${VAR}` forms work:

```json
"authentication": { "api_token": "${CF_DDNS_API_TOKEN}" }
```

```bash
CF_DDNS_API_TOKEN=... cloudflare-ddns
```

Only `CF_DDNS_`-prefixed variables are substituted; other references are
left as-is. Both `$VAR` and `${VAR}` work, and longer names are substituted
first, so `$CF_DDNS_TOKEN_2` is never clobbered by `$CF_DDNS_TOKEN`. A
reference to an unset `CF_DDNS_` variable is left in place and logs a warning;
the token check at startup then reports the malformed token.

## `purgeUnknownRecords`

When `true`:

1. **Duplicates.** If a configured name has several records of the same type,
   one is kept (preferably the one already holding the current IP) and the
   others are deleted.
2. **Definitive absence.** If a deterministic provider (`literal:`, `local`,
   `local.iface:`, `local.iface.stable:`) reports no address for a family,
   the records of that type (A or AAAA) for the **configured subdomains** are
   deleted. Other records in the zone are never touched.

Transient detection failures (`cloudflare.trace`, `cloudflare.doh`, `ipify`,
`url:` erroring) never delete anything; the cycle is skipped and records are
preserved.

## Running continuously (`--repeat`)

Without `--repeat` the program runs one update and exits (exit code 1 if the
update failed). With `--repeat` it updates every `ttl` seconds; when `ttl` is
auto (any value below 30), it polls every 300 seconds. The Docker image's
entrypoint already passes `--repeat`.

`--dry-run` logs what would change without writing to Cloudflare.

## Deployment

### Docker

```bash
docker run -d --name cloudflare-ddns --restart unless-stopped \
  --network host \
  -v /path/to/config.json:/config.json:ro \
  timothyjmiller/cloudflare-ddns:2.2.0
```

Compose: [`docker/docker-compose.legacy.yml`](../docker/docker-compose.legacy.yml).
Host networking is only required for IPv6 (`"aaaa": true`).

### Kubernetes

[`k8s/cloudflare-ddns.legacy.yml`](../k8s/cloudflare-ddns.legacy.yml) mounts
`config.json` from a Secret:

```bash
kubectl create namespace ddns
kubectl create secret generic config-cloudflare-ddns --from-file=config.json -n ddns
kubectl apply -f k8s/cloudflare-ddns.legacy.yml -n ddns
```

### systemd

The unit in [`systemd/`](../systemd) runs as a dynamic (unprivileged) user,
which cannot read a root-only `config.json`. Hand the file to the service as
a credential with a drop-in:

```bash
sudo install -d -m 700 /etc/cloudflare-ddns
sudo install -m 600 config.json /etc/cloudflare-ddns/config.json
sudo systemctl edit cloudflare-ddns.service
```

```ini
[Service]
LoadCredential=config.json:/etc/cloudflare-ddns/config.json
Environment=CONFIG_PATH=%d
```

Then `sudo systemctl enable --now cloudflare-ddns.timer`. `LoadCredential=`
needs systemd 247 or newer (`%d` needs 248).

## Examples

### Several subdomains

```json
{
  "cloudflare": [
    {
      "authentication": { "api_token": "${CF_DDNS_API_TOKEN}" },
      "zone_id": "your_zone_id",
      "subdomains": [
        { "name": "", "proxied": true },
        { "name": "www", "proxied": true },
        { "name": "vpn", "proxied": false }
      ]
    }
  ],
  "a": true,
  "aaaa": true,
  "purgeUnknownRecords": false,
  "ttl": 300
}
```

### Several zones, IPv4 only

```json
{
  "cloudflare": [
    {
      "authentication": { "api_token": "${CF_DDNS_API_TOKEN}" },
      "zone_id": "first_zone_id",
      "subdomains": ["@"]
    },
    {
      "authentication": { "api_token": "${CF_DDNS_API_TOKEN}" },
      "zone_id": "second_zone_id",
      "subdomains": ["@", "www"]
    }
  ],
  "ip6_provider": "none",
  "recordComment": "managed by cloudflare-ddns"
}
```

## Migrating to environment variables

Environment-variable mode finds zones from the domain names, so you list
fully-qualified names instead of zone IDs. The token must be able to read
the zones (**Zone › Zone › Read**) as well as edit DNS.

| Legacy key / flag | Environment variable |
|-------------------|----------------------|
| `authentication.api_token` | `CLOUDFLARE_API_TOKEN` (or `CLOUDFLARE_API_TOKEN_FILE`) |
| `authentication.api_key` | Not supported — create an API token |
| `zone_id` + `subdomains` | `DOMAINS` as FQDNs, e.g. `example.com,www.example.com` (`""`/`"@"` → `example.com`) |
| `proxied` (zone or subdomain) | `PROXIED` expression, e.g. `true`, `is(www.example.com)`, `!is(vpn.example.com)` |
| `a: false` | `IP4_PROVIDER=none` (or list the names in `IP6_DOMAINS` only) |
| `aaaa: false` | `IP6_PROVIDER=none` (or list the names in `IP4_DOMAINS` only) |
| `ip4_provider` / `ip6_provider` | `IP4_PROVIDER` / `IP6_PROVIDER` |
| `ttl` | `TTL` |
| `recordComment` | `RECORD_COMMENT` |
| `purgeUnknownRecords` | No direct equivalent. Duplicate records for a managed name are always cleaned up; deletion on definitive absence is `DELETE_ON_FAILURE=true` and only touches the configured names. Use `MANAGED_RECORDS_COMMENT_REGEX` to limit which records are managed |
| `--repeat` (interval = `ttl`) | `UPDATE_CRON=@every 5m` (default); one-shot is `UPDATE_CRON=@once` |
| `CF_DDNS_*` substitution | Not needed — set the variables directly |
| `CONFIG_PATH` | Not used |

Example — the "several subdomains" config above becomes:

```bash
CLOUDFLARE_API_TOKEN=...
DOMAINS=example.com,www.example.com,vpn.example.com
PROXIED=!is(vpn.example.com)
TTL=300
```

When switching, remove the `config.json` mount (it is ignored anyway) and
keep `SHOUTRRR`, `HEALTHCHECKS`, `UPTIMEKUMA` and `REJECT_CLOUDFLARE_IPS` as
they are.
