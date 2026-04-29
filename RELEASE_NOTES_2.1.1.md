# cloudflare-ddns v2.1.1

Maintenance release. Bug fix for `rand` 0.10 API change, plus opt-in failure-safe deletion behavior contributed in the v2.1.0 → v2.1.1 window, dependency refresh, and proportional jitter for IP detection.

## Highlights

- **Fix:** Restore the build under `rand` 0.10 — `random_range` moved to the `RngExt` trait, and the unconditional jitter sleep in `--repeat` mode no longer fails to compile.
- **New:** `DELETE_ON_FAILURE` (env-var mode) controls whether DNS records are removed when an IP detection or update fails. Defaults to `true` to preserve existing behavior; set `DELETE_ON_FAILURE=false` to keep stale records on transient failures instead of yanking them.
- **Improvement:** Proportional jitter (up to 20% of the update interval) is added before each scheduled update to spread requests across clients and reduce synchronized spikes against the Cloudflare API.

## Changes since v2.1.0

### Features
- `DELETE_ON_FAILURE` env var to prevent DNS record deletion on failed updates (#263, thanks @DMaxter)
- Proportional jitter on update intervals to desynchronize API traffic (#253, thanks @jhutchings1)

### Fixes
- Compile fix for `rand` 0.10: import `RngExt` so `random_range` resolves
- `delete_on_failure` regression test coverage added

### Dependencies
- `rustls` 0.23.37 → 0.23.40
- `rustls-webpki` 0.103.10 → 0.103.13
- `tokio` 1.50.0 → 1.52.1
- `reqwest` 0.13.2 → 0.13.3
- `rand` 0.9.2 → 0.10.1

### Docs
- Document `DELETE_ON_FAILURE` in the README

## Upgrade notes

- **Default behavior unchanged.** `DELETE_ON_FAILURE` defaults to `true`, matching pre-2.1.1 behavior. Set it to `false` if you want stale records preserved during outages.
- No config file schema changes. Existing `config.json` deployments continue to work without edits.

## Docker

```sh
docker pull timothyjmiller/cloudflare-ddns:2.1.1
docker pull timothyjmiller/cloudflare-ddns:latest
```

Multi-arch: `linux/amd64`, `linux/arm64`, `linux/ppc64le`.

## Verification

- `cargo test` — 352 tests pass
- Release build succeeds, binary size ~1.7 MiB (pre-UPX)
- Smoke tested in both legacy `config.json` mode and env-var mode against the live Cloudflare API
