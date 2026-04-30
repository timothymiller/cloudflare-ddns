# cloudflare-ddns v2.1.2 — Notification & Domain Casing Fixes

This patch release fixes three bugs reported on GitHub.

## Bug fixes

- **Mixed-case domains now match existing DNS records (#255).**
  In env-var mode, configuring a domain with mixed casing (for example
  `ExaMple.com`) caused every update cycle to attempt a duplicate record
  create and fail with Cloudflare error `81058: An identical record already
  exists.` Cloudflare normalizes record names to lowercase server-side, so
  the lookup is now case-insensitive.

- **Pushover notifications work again (#258).**
  The shoutrrr-style URL `pushover://shoutrrr:TOKEN@USER` (the canonical form
  from `containrrr/shoutrrr`) was being parsed with the literal `shoutrrr:`
  username included in the API token, which Pushover rejected. The parser
  now strips the optional `<user>:` prefix from the token segment, restoring
  the v2.0.7 behavior. Optional shoutrrr query parameters (`?devices=...`,
  `?priority=...`) are tolerated.

- **Gotify notifications now produce a valid request URL (#262).**
  The Gotify URL parser blindly appended `/message` after any query string,
  producing malformed webhook URLs like
  `https://host:9090?token=XYZ/message`. The parser now follows shoutrrr's
  canonical layout — token as the final path segment or `?token=` query —
  and supports `?disabletls=yes` to switch the resulting webhook from HTTPS
  to HTTP for typical home-LAN setups, plus the `gotify+http://` /
  `gotify+https://` aliases.

## Already addressed (closing #257)

The robust public-IP discovery enhancements requested in #257 (multi-endpoint
trace fallback, strict address-family validation, API request timeouts,
duplicate record cleanup) were already folded into the Rust port shipped in
v2.0.8 — see `src/provider.rs` (`CF_TRACE_PRIMARY` / `CF_TRACE_FALLBACK`,
`validate_detected_ip`, `build_split_client`) and `src/cloudflare.rs`
(`set_ips` dedup behavior, per-request `timeout`).

## Upgrade

```bash
docker pull timothyjmiller/cloudflare-ddns:2.1.2
# or
docker pull timothyjmiller/cloudflare-ddns:latest
```

No configuration changes are required.
