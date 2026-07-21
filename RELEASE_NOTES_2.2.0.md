# cloudflare-ddns v2.2.0 — Zulip Notifications, Safer Failure Handling & Helm Chart

This minor release adds new notification and deployment options, a safer
default when IP detection fails, and a stable IPv6 provider for Linux hosts.

## ⚠️ Behavior change: `DELETE_ON_FAILURE` now defaults to `false` (#277)

Previously, when a provider definitively reported no address for an IP
family, managed DNS records for that family were **deleted** by default —
which could take services offline after a transient misdetection.

- `DELETE_ON_FAILURE` now defaults to **`false`**: on detection failure the
  update is skipped and existing records are preserved.
- Transient detection errors (network failures) always preserve existing
  records, regardless of this setting.
- WAF list updates are now skipped when any configured IP family fails
  detection, preventing a partial failure from silently stripping that
  family's IPs from the list.

If you relied on the old behavior, set `DELETE_ON_FAILURE=true` explicitly.

## New features

- **Zulip notifications (#271).**
  Native `zulip://` shoutrrr URL support:

  ```text
  zulip://bot-mail:bot-key@host/?stream=stream-name&topic=topic-name
  ```

  Messages are sent to the Zulip API (`/api/v1/messages`) with Basic auth.
  The `@` in the bot email may be written literally or percent-encoded
  (`%40`); `topic` is optional and defaults to `Cloudflare DDNS`.

- **Configurable JSON field for generic webhooks (#271).**
  Generic webhooks send `{"message": "..."}` by default. Append
  `?messagekey=<field>` to rename the field — e.g.
  `generic://host/path?messagekey=text` for services expecting Slack-style
  payloads (including Zulip's slack-compatible endpoints).

- **Stable local IPv6 provider (#273).**
  New `local.iface.stable:<name>` provider selects the preferred stable
  IPv6 address from a Linux network interface, excluding temporary
  (privacy-extension) and deprecated addresses.

- **Helm chart (#278).**
  A Helm chart is now available under `charts/cloudflare-ddns`, published
  as an OCI artifact to GHCR via CI.

## Dependency updates

- reqwest 0.13.4, rustls 0.23.42, tokio 1.52.4, rand 0.10.2,
  serde_json 1.0.150, actions/checkout 7

## Upgrade

```bash
docker pull timothyjmiller/cloudflare-ddns:2.2.0
# or
docker pull timothyjmiller/cloudflare-ddns:latest
```

No configuration changes are required unless you depend on records being
deleted when IP detection fails — in that case set `DELETE_ON_FAILURE=true`.
