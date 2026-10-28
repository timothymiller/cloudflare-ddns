mod cf_ip_filter;
mod cloudflare;
mod config;
mod domain;
mod health;
mod notifier;
mod pp;
mod provider;
mod updater;

use crate::cloudflare::{Auth, CloudflareHandle};
use crate::config::{AppConfig, CronSchedule};
use crate::notifier::{CompositeNotifier, Heartbeat, Message};
use crate::pp::PP;
use rand::RngExt;
use reqwest::Client;
use std::collections::HashSet;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main(flavor = "current_thread")]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Parse CLI args
    let args: Vec<String> = std::env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let repeat = args.iter().any(|a| a == "--repeat");

    // Check for unknown args (legacy behavior)
    let known_args = ["--dry-run", "--repeat", "--health"];
    let unknown: Vec<&str> = args
        .iter()
        .skip(1)
        .filter(|a| !known_args.contains(&a.as_str()))
        .map(|a| a.as_str())
        .collect();

    if !unknown.is_empty() {
        eprintln!(
            "Unrecognized parameter(s): {}. Stopping now.",
            unknown.join(", ")
        );
        return;
    }

    // Container health probe: answers from the health file and exits without
    // loading config, so it stays cheap enough to run every few seconds.
    if args.iter().any(|a| a == "--health") {
        std::process::exit(health::run_check());
    }

    // Determine config mode and create initial PP for config loading
    let initial_pp = if config::is_env_config_mode() {
        // In env mode, read emoji/quiet from env before loading full config
        let emoji = std::env::var("EMOJI")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(true);
        let quiet = std::env::var("QUIET")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        PP::new(emoji, quiet)
    } else {
        // Legacy mode: no emoji, not quiet (preserves original output behavior)
        PP::new(false, false)
    };

    println!("cloudflare-ddns v{VERSION}");

    // Load config
    let app_config = match config::load_config(dry_run, repeat, &initial_pp) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            sleep(Duration::from_secs(10)).await;
            std::process::exit(1);
        }
    };

    // Create PP with final settings
    let ppfmt = PP::new(app_config.emoji, app_config.quiet);

    if dry_run {
        ppfmt.noticef(
            pp::EMOJI_WARNING,
            "[DRY RUN] No records will be created, updated, or deleted.",
        );
    }

    // Print config summary (env mode only)
    config::print_config_summary(&app_config, &ppfmt);

    // Setup notifiers and heartbeats
    let notifier = config::setup_notifiers(&ppfmt);
    let heartbeat = config::setup_heartbeats(&ppfmt);

    // Create Cloudflare handle (for env mode)
    let handle = if !app_config.legacy_mode {
        CloudflareHandle::new(
            app_config.auth.clone(),
            app_config.update_timeout,
            app_config.managed_comment_regex.clone(),
            app_config.managed_waf_comment_regex.clone(),
        )
    } else {
        // Create a dummy handle for legacy mode (won't be used)
        CloudflareHandle::new(
            Auth::Token(String::new()),
            Duration::from_secs(30),
            None,
            None,
        )
    };

    // Signal handler for graceful shutdown (SIGINT and SIGTERM)
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        println!("Stopping...");
        let _ = shutdown_tx.send(true);
    });
    let mut shutdown = Shutdown(shutdown_rx);

    // Start heartbeat
    heartbeat.start().await;

    let mut cf_cache = cf_ip_filter::CachedCloudflareFilter::new();
    let detection_client = Client::builder()
        .timeout(app_config.detection_timeout)
        .build()
        .unwrap_or_default();

    let ok = if app_config.legacy_mode {
        // --- Legacy mode (original cloudflare-ddns behavior) ---
        run_legacy_mode(
            &app_config,
            &handle,
            &notifier,
            &heartbeat,
            &ppfmt,
            &mut shutdown,
            &mut cf_cache,
            &detection_client,
        )
        .await
    } else {
        // --- Env var mode (cf-ddns behavior) ---
        run_env_mode(
            &app_config,
            &handle,
            &notifier,
            &heartbeat,
            &ppfmt,
            &mut shutdown,
            &mut cf_cache,
            &detection_client,
        )
        .await
    };

    // On shutdown: delete records if configured
    let exit_msg = if app_config.delete_on_stop && !app_config.legacy_mode {
        ppfmt.noticef(pp::EMOJI_STOP, "Deleting records on stop...");
        updater::final_delete(&app_config, &handle, &notifier, &ppfmt).await
    } else {
        Message::new_ok("Shutting down")
    };

    // Exit heartbeat
    heartbeat.exit(&exit_msg).await;

    // Single-shot runs (systemd oneshot, cron, --dry-run) report failure via exit code.
    if !ok {
        std::process::exit(1);
    }
}

/// Resolves when the process receives SIGINT or SIGTERM.
///
/// `docker stop`, `kubectl delete pod` and `systemctl stop` all send SIGTERM; as
/// PID 1 in a scratch image we must handle it ourselves or the kernel ignores it.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

/// Shutdown flag shared by the update loops.
struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    fn requested(&self) -> bool {
        *self.0.borrow()
    }

    /// Sleep for `d`, waking early if shutdown is requested.
    /// Returns `true` if the full duration elapsed and the loop should continue.
    async fn sleep(&mut self, d: Duration) -> bool {
        if self.requested() {
            return false;
        }
        let elapsed = tokio::select! {
            _ = sleep(d) => true,
            _ = self.0.wait_for(|stop| *stop) => false,
        };
        elapsed && !self.requested()
    }
}

/// Runs legacy mode. Returns `false` if a single-shot run failed.
async fn run_legacy_mode(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    heartbeat: &Heartbeat,
    ppfmt: &PP,
    shutdown: &mut Shutdown,
    cf_cache: &mut cf_ip_filter::CachedCloudflareFilter,
    detection_client: &Client,
) -> bool {
    let legacy = match &config.legacy_config {
        Some(l) => l,
        None => return false,
    };

    let mut noop_reported = HashSet::new();

    if config.repeat {
        let interval = config
            .update_cron
            .next_duration()
            .unwrap_or(Duration::from_secs(300));
        let secs = interval.as_secs();
        match (legacy.a, legacy.aaaa) {
            (true, true) => {
                println!("Updating IPv4 (A) & IPv6 (AAAA) records every {secs} seconds")
            }
            (true, false) => println!("Updating IPv4 (A) records every {secs} seconds"),
            (false, true) => println!("Updating IPv6 (AAAA) records every {secs} seconds"),
            (false, false) => println!("Both IPv4 and IPv6 are disabled"),
        }

        while !shutdown.requested() {
            health::mark_alive(Duration::ZERO, cycle_timeouts(config), ppfmt);
            updater::update_once(
                config,
                handle,
                notifier,
                heartbeat,
                cf_cache,
                ppfmt,
                &mut noop_reported,
                detection_client,
            )
            .await;

            health::mark_alive(interval, cycle_timeouts(config), ppfmt);
            if !shutdown.sleep(interval).await {
                break;
            }
        }
        true
    } else {
        updater::update_once(
            config,
            handle,
            notifier,
            heartbeat,
            cf_cache,
            ppfmt,
            &mut noop_reported,
            detection_client,
        )
        .await
    }
}

/// Runs env var mode. Returns `false` if a single-shot run failed.
async fn run_env_mode(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    heartbeat: &Heartbeat,
    ppfmt: &PP,
    shutdown: &mut Shutdown,
    cf_cache: &mut cf_ip_filter::CachedCloudflareFilter,
    detection_client: &Client,
) -> bool {
    let mut noop_reported = HashSet::new();

    match &config.update_cron {
        CronSchedule::Once => {
            if config.update_on_start {
                return updater::update_once(
                    config,
                    handle,
                    notifier,
                    heartbeat,
                    cf_cache,
                    ppfmt,
                    &mut noop_reported,
                    detection_client,
                )
                .await;
            }
            true
        }
        schedule => {
            let interval = schedule.next_duration().unwrap_or(Duration::from_secs(300));

            ppfmt.noticef(
                pp::EMOJI_LAUNCH,
                &format!(
                    "Started cloudflare-ddns, updating every {}",
                    describe_duration(interval)
                ),
            );

            // Update on start if configured
            if config.update_on_start {
                health::mark_alive(Duration::ZERO, cycle_timeouts(config), ppfmt);
                updater::update_once(
                    config,
                    handle,
                    notifier,
                    heartbeat,
                    cf_cache,
                    ppfmt,
                    &mut noop_reported,
                    detection_client,
                )
                .await;
            }

            // Main loop
            while !shutdown.requested() {
                ppfmt.infof(
                    pp::EMOJI_SLEEP,
                    &format!("Next update in {}", describe_duration(interval)),
                );

                // Proportional jitter spreads API calls across clients and reduces
                // synchronized traffic spikes at Cloudflare.
                let jitter = jitter_duration(interval.as_secs(), rand::rng().random());
                health::mark_alive(interval + jitter, cycle_timeouts(config), ppfmt);
                if !shutdown.sleep(interval + jitter).await {
                    break;
                }

                health::mark_alive(Duration::ZERO, cycle_timeouts(config), ppfmt);
                updater::update_once(
                    config,
                    handle,
                    notifier,
                    heartbeat,
                    cf_cache,
                    ppfmt,
                    &mut noop_reported,
                    detection_client,
                )
                .await;
            }
            true
        }
    }
}

/// Extra health-check slack from the configured timeouts, so raising them
/// never makes a slow but working cycle look hung.
fn cycle_timeouts(config: &AppConfig) -> Duration {
    config.detection_timeout + config.update_timeout
}

fn jitter_duration(interval_secs: u64, rand_val: u64) -> std::time::Duration {
    let max_jitter = interval_secs / 5;
    if max_jitter == 0 {
        return std::time::Duration::ZERO;
    }
    std::time::Duration::from_secs(rand_val % (max_jitter + 1))
}

fn describe_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins > 0 {
            format!("{hours}h{mins}m")
        } else {
            format!("{hours}h")
        }
    } else if secs >= 60 {
        let mins = secs / 60;
        let s = secs % 60;
        if s > 0 {
            format!("{mins}m{s}s")
        } else {
            format!("{mins}m")
        }
    } else {
        format!("{secs}s")
    }
}

// ============================================================
// Tests (backwards compatible with original test suite)
// ============================================================

#[cfg(test)]
pub(crate) fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
pub(crate) fn test_client() -> reqwest::Client {
    init_crypto();
    reqwest::Client::new()
}

#[cfg(test)]
mod tests {
    use crate::config::parse_legacy_config;
    use crate::provider::parse_trace_ip;

    #[test]
    fn test_parse_trace_ip() {
        let body = "fl=1f1\nh=1.1.1.1\nip=203.0.113.42\nts=1234567890\nvisit_scheme=https\n";
        assert_eq!(parse_trace_ip(body), Some("203.0.113.42".to_string()));
    }

    #[test]
    fn test_parse_trace_ip_missing() {
        let body = "fl=1f1\nh=1.1.1.1\nts=1234567890\n";
        assert_eq!(parse_trace_ip(body), None);
    }

    #[test]
    fn test_parse_config_minimal() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok123" },
                "zone_id": "zone1",
                "subdomains": ["@"]
            }]
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert!(config.a);
        assert!(config.aaaa);
        assert!(!config.purge_unknown_records);
        assert_eq!(config.ttl, 300);
    }

    #[test]
    fn test_parse_config_low_ttl() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok123" },
                "zone_id": "zone1",
                "subdomains": ["@"]
            }],
            "ttl": 10
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert_eq!(config.ttl, 1);
    }

    #[test]
    fn test_jitter_duration_standard() {
        // 5-minute interval: max jitter = 60s
        let d = super::jitter_duration(300, 30);
        assert_eq!(d, std::time::Duration::from_secs(30));
        let d = super::jitter_duration(300, 61);
        assert_eq!(d, std::time::Duration::from_secs(61 % 61)); // wraps within [0, 60]
    }

    #[test]
    fn test_jitter_duration_short_interval() {
        // interval < 5s: must return zero
        assert_eq!(super::jitter_duration(4, 99), std::time::Duration::ZERO);
        assert_eq!(super::jitter_duration(0, 99), std::time::Duration::ZERO);
    }

    #[test]
    fn test_jitter_duration_deterministic() {
        // rand_val=0 always returns zero duration
        assert_eq!(super::jitter_duration(300, 0), std::time::Duration::ZERO);
    }

    // --- describe_duration tests ---
    #[test]
    fn test_describe_duration_seconds_only() {
        use tokio::time::Duration;
        assert_eq!(super::describe_duration(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn test_describe_duration_exact_minutes() {
        use tokio::time::Duration;
        assert_eq!(super::describe_duration(Duration::from_secs(300)), "5m");
    }

    #[test]
    fn test_describe_duration_minutes_and_seconds() {
        use tokio::time::Duration;
        assert_eq!(super::describe_duration(Duration::from_secs(330)), "5m30s");
    }

    #[test]
    fn test_describe_duration_exact_hours() {
        use tokio::time::Duration;
        assert_eq!(super::describe_duration(Duration::from_secs(7200)), "2h");
    }

    #[test]
    fn test_describe_duration_hours_and_minutes() {
        use tokio::time::Duration;
        assert_eq!(super::describe_duration(Duration::from_secs(5400)), "1h30m");
    }


    // --- Shutdown ---

    fn shutdown_pair() -> (tokio::sync::watch::Sender<bool>, super::Shutdown) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (tx, super::Shutdown(rx))
    }

    #[tokio::test]
    async fn test_shutdown_sleep_completes_without_signal() {
        let (_tx, mut shutdown) = shutdown_pair();
        assert!(shutdown.sleep(std::time::Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn test_shutdown_sleep_wakes_early_on_signal() {
        let (tx, mut shutdown) = shutdown_pair();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            tx.send(true).unwrap();
        });
        let started = std::time::Instant::now();
        assert!(!shutdown.sleep(std::time::Duration::from_secs(3600)).await);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(shutdown.requested());
    }

    #[tokio::test]
    async fn test_shutdown_sleep_returns_immediately_if_already_requested() {
        let (tx, mut shutdown) = shutdown_pair();
        tx.send(true).unwrap();
        assert!(!shutdown.sleep(std::time::Duration::from_secs(3600)).await);
    }
}
