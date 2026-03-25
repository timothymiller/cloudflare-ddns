mod cf_ip_filter;
mod cloudflare;
mod config;
mod domain;
mod notifier;
mod pp;
mod provider;
mod updater;

use crate::cloudflare::{Auth, CloudflareHandle};
use crate::config::{AppConfig, CronSchedule};
use crate::notifier::{CompositeNotifier, Heartbeat, Message};
use crate::pp::PP;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use reqwest::Client;
use tokio::signal;
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
    let known_args = ["--dry-run", "--repeat"];
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

    // Signal handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        println!("Stopping...");
        r.store(false, Ordering::SeqCst);
    });

    // Start heartbeat
    heartbeat.start().await;

    let mut cf_cache = cf_ip_filter::CachedCloudflareFilter::new();
    let detection_client = Client::builder()
        .timeout(app_config.detection_timeout)
        .build()
        .unwrap_or_default();

    if app_config.legacy_mode {
        // --- Legacy mode (original cloudflare-ddns behavior) ---
        run_legacy_mode(&app_config, &handle, &notifier, &heartbeat, &ppfmt, running, &mut cf_cache, &detection_client).await;
    } else {
        // --- Env var mode (cf-ddns behavior) ---
        run_env_mode(&app_config, &handle, &notifier, &heartbeat, &ppfmt, running, &mut cf_cache, &detection_client).await;
    }

    // On shutdown: delete records if configured
    if app_config.delete_on_stop && !app_config.legacy_mode {
        ppfmt.noticef(pp::EMOJI_STOP, "Deleting records on stop...");
        updater::final_delete(&app_config, &handle, &notifier, &heartbeat, &ppfmt).await;
    }

    // Exit heartbeat
    heartbeat
        .exit(&Message::new_ok("Shutting down"))
        .await;
}

async fn run_legacy_mode(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    heartbeat: &Heartbeat,
    ppfmt: &PP,
    running: Arc<AtomicBool>,
    cf_cache: &mut cf_ip_filter::CachedCloudflareFilter,
    detection_client: &Client,
) {
    let legacy = match &config.legacy_config {
        Some(l) => l,
        None => return,
    };

    let mut noop_reported = HashSet::new();

    if config.repeat {
        match (legacy.a, legacy.aaaa) {
            (true, true) => println!(
                "Updating IPv4 (A) & IPv6 (AAAA) records every {} seconds",
                legacy.ttl
            ),
            (true, false) => {
                println!("Updating IPv4 (A) records every {} seconds", legacy.ttl)
            }
            (false, true) => {
                println!("Updating IPv6 (AAAA) records every {} seconds", legacy.ttl)
            }
            (false, false) => println!("Both IPv4 and IPv6 are disabled"),
        }

        while running.load(Ordering::SeqCst) {
            updater::update_once(config, handle, notifier, heartbeat, cf_cache, ppfmt, &mut noop_reported, detection_client).await;

            for _ in 0..legacy.ttl {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                sleep(Duration::from_secs(1)).await;
            }
        }
    } else {
        updater::update_once(config, handle, notifier, heartbeat, cf_cache, ppfmt, &mut noop_reported, detection_client).await;
    }
}

async fn run_env_mode(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    heartbeat: &Heartbeat,
    ppfmt: &PP,
    running: Arc<AtomicBool>,
    cf_cache: &mut cf_ip_filter::CachedCloudflareFilter,
    detection_client: &Client,
) {
    let mut noop_reported = HashSet::new();

    match &config.update_cron {
        CronSchedule::Once => {
            if config.update_on_start {
                updater::update_once(config, handle, notifier, heartbeat, cf_cache, ppfmt, &mut noop_reported, detection_client).await;
            }
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
                updater::update_once(config, handle, notifier, heartbeat, cf_cache, ppfmt, &mut noop_reported, detection_client).await;
            }

            // Main loop
            while running.load(Ordering::SeqCst) {
                // Sleep for interval, checking running flag each second
                let secs = interval.as_secs();
                let mins = secs / 60;
                let rem_secs = secs % 60;
                ppfmt.infof(
                    pp::EMOJI_SLEEP,
                    &format!("Next update in {}m {}s", mins, rem_secs),
                );

                for _ in 0..secs {
                    if !running.load(Ordering::SeqCst) {
                        return;
                    }
                    sleep(Duration::from_secs(1)).await;
                }

                if !running.load(Ordering::SeqCst) {
                    return;
                }

                updater::update_once(config, handle, notifier, heartbeat, cf_cache, ppfmt, &mut noop_reported, detection_client).await;
            }
        }
    }
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
    use crate::config::{
        LegacyAuthentication, LegacyCloudflareEntry, LegacyConfig, LegacySubdomainEntry,
        parse_legacy_config,
    };
    use crate::provider::parse_trace_ip;
    use reqwest::Client;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(zone_id: &str) -> LegacyConfig {
        LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "test-token".to_string(),
                    api_key: None,
                },
                zone_id: zone_id.to_string(),
                subdomains: vec![
                    LegacySubdomainEntry::Detailed {
                        name: "".to_string(),
                        proxied: false,
                    },
                    LegacySubdomainEntry::Detailed {
                        name: "vpn".to_string(),
                        proxied: true,
                    },
                ],
                proxied: false,
            }],
            a: true,
            aaaa: false,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: None,
            ip6_provider: None,
        }
    }

    // Helper to create a legacy client for testing
    struct TestDdnsClient {
        client: Client,
        cf_api_base: String,
        ipv4_urls: Vec<String>,
        dry_run: bool,
    }

    impl TestDdnsClient {
        fn new(base_url: &str) -> Self {
            Self {
                client: crate::test_client(),
                cf_api_base: base_url.to_string(),
                ipv4_urls: vec![format!("{base_url}/cdn-cgi/trace")],
                dry_run: false,
            }
        }

        fn dry_run(mut self) -> Self {
            self.dry_run = true;
            self
        }

        async fn cf_api<T: serde::de::DeserializeOwned>(
            &self,
            endpoint: &str,
            method_str: &str,
            token: &str,
            body: Option<&impl serde::Serialize>,
        ) -> Option<T> {
            let url = format!("{}/{endpoint}", self.cf_api_base);
            let mut req = match method_str {
                "GET" => self.client.get(&url),
                "POST" => self.client.post(&url),
                "PUT" => self.client.put(&url),
                "DELETE" => self.client.delete(&url),
                _ => return None,
            };
            req = req.header("Authorization", format!("Bearer {token}"));
            if let Some(b) = body {
                req = req.json(b);
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => resp.json::<T>().await.ok(),
                Ok(resp) => {
                    let text = resp.text().await.unwrap_or_default();
                    eprintln!("Error: {text}");
                    None
                }
                Err(e) => {
                    eprintln!("Exception: {e}");
                    None
                }
            }
        }

        async fn get_ip(&self) -> Option<String> {
            for url in &self.ipv4_urls {
                if let Ok(resp) = self.client.get(url).send().await {
                    if let Ok(body) = resp.text().await {
                        if let Some(ip) = parse_trace_ip(&body) {
                            return Some(ip);
                        }
                    }
                }
            }
            None
        }

        async fn commit_record(
            &self,
            ip: &str,
            record_type: &str,
            config: &[LegacyCloudflareEntry],
            ttl: i64,
            purge_unknown_records: bool,
            noop_reported: &mut std::collections::HashSet<String>,
        ) {
            for entry in config {
                #[derive(serde::Deserialize)]
                struct Resp<T> {
                    result: Option<T>,
                }
                #[derive(serde::Deserialize)]
                struct Zone {
                    name: String,
                }
                #[derive(serde::Deserialize)]
                struct Rec {
                    id: String,
                    name: String,
                    content: String,
                    proxied: bool,
                }

                let zone_resp: Option<Resp<Zone>> = self
                    .cf_api(
                        &format!("zones/{}", entry.zone_id),
                        "GET",
                        &entry.authentication.api_token,
                        None::<&()>.as_ref(),
                    )
                    .await;

                let base_domain = match zone_resp.and_then(|r| r.result) {
                    Some(z) => z.name,
                    None => continue,
                };

                for subdomain in &entry.subdomains {
                    let (name, proxied) = match subdomain {
                        LegacySubdomainEntry::Detailed { name, proxied } => {
                            (name.to_lowercase().trim().to_string(), *proxied)
                        }
                        LegacySubdomainEntry::Simple(name) => {
                            (name.to_lowercase().trim().to_string(), entry.proxied)
                        }
                    };

                    let fqdn = crate::domain::make_fqdn(&name, &base_domain);

                    #[derive(serde::Serialize)]
                    struct Payload {
                        #[serde(rename = "type")]
                        record_type: String,
                        name: String,
                        content: String,
                        proxied: bool,
                        ttl: i64,
                    }

                    let record = Payload {
                        record_type: record_type.to_string(),
                        name: fqdn.clone(),
                        content: ip.to_string(),
                        proxied,
                        ttl,
                    };

                    let dns_endpoint = format!(
                        "zones/{}/dns_records?per_page=100&type={record_type}",
                        entry.zone_id
                    );
                    let dns_records: Option<Resp<Vec<Rec>>> = self
                        .cf_api(
                            &dns_endpoint,
                            "GET",
                            &entry.authentication.api_token,
                            None::<&()>.as_ref(),
                        )
                        .await;

                    let mut identifier: Option<String> = None;
                    let mut modified = false;
                    let mut duplicate_ids: Vec<String> = Vec::new();

                    if let Some(resp) = dns_records {
                        if let Some(records) = resp.result {
                            for r in &records {
                                if r.name == fqdn {
                                    if let Some(ref existing_id) = identifier {
                                        if r.content == ip {
                                            duplicate_ids.push(existing_id.clone());
                                            identifier = Some(r.id.clone());
                                        } else {
                                            duplicate_ids.push(r.id.clone());
                                        }
                                    } else {
                                        identifier = Some(r.id.clone());
                                        if r.content != ip || r.proxied != proxied {
                                            modified = true;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let noop_key = format!("{fqdn}:{record_type}");
                    if let Some(ref id) = identifier {
                        if modified {
                            noop_reported.remove(&noop_key);
                            if self.dry_run {
                                println!("[DRY RUN] Would update record {fqdn} -> {ip}");
                            } else {
                                println!("Updating record {fqdn} -> {ip}");
                                let update_endpoint =
                                    format!("zones/{}/dns_records/{id}", entry.zone_id);
                                let _: Option<serde_json::Value> = self
                                    .cf_api(
                                        &update_endpoint,
                                        "PUT",
                                        &entry.authentication.api_token,
                                        Some(&record),
                                    )
                                    .await;
                            }
                        } else if noop_reported.insert(noop_key) {
                            if self.dry_run {
                                println!("[DRY RUN] Record {fqdn} is up to date");
                            } else {
                                println!("Record {fqdn} is up to date");
                            }
                        }
                    } else {
                        noop_reported.remove(&noop_key);
                        if self.dry_run {
                            println!("[DRY RUN] Would add new record {fqdn} -> {ip}");
                        } else {
                            println!("Adding new record {fqdn} -> {ip}");
                            let create_endpoint =
                                format!("zones/{}/dns_records", entry.zone_id);
                            let _: Option<serde_json::Value> = self
                                .cf_api(
                                    &create_endpoint,
                                    "POST",
                                    &entry.authentication.api_token,
                                    Some(&record),
                                )
                                .await;
                        }
                    }

                    if purge_unknown_records {
                        for dup_id in &duplicate_ids {
                            if self.dry_run {
                                println!("[DRY RUN] Would delete stale record {dup_id}");
                            } else {
                                println!("Deleting stale record {dup_id}");
                                let del_endpoint =
                                    format!("zones/{}/dns_records/{dup_id}", entry.zone_id);
                                let _: Option<serde_json::Value> = self
                                    .cf_api(
                                        &del_endpoint,
                                        "DELETE",
                                        &entry.authentication.api_token,
                                        None::<&()>.as_ref(),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }

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

    #[tokio::test]
    async fn test_ip_detection() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/cdn-cgi/trace"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("fl=1f1\nh=mock\nip=198.51.100.7\nts=0\n"),
            )
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri());
        let ip = ddns.get_ip().await;
        assert_eq!(ip, Some("198.51.100.7".to_string()));
    }

    #[tokio::test]
    async fn test_creates_new_record() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-abc-123";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "new-record-1" }
            })))
            .expect(2)
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri());
        let config = test_config(zone_id);
        ddns.commit_record("198.51.100.7", "A", &config.cloudflare, 300, false, &mut std::collections::HashSet::new())
            .await;
    }

    #[tokio::test]
    async fn test_updates_existing_record() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-update-1";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-1", "name": "example.com", "content": "10.0.0.1", "proxied": false },
                    { "id": "rec-2", "name": "vpn.example.com", "content": "10.0.0.1", "proxied": true }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("PUT"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "rec-1" }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("PUT"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-2")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "rec-2" }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri());
        let config = test_config(zone_id);
        ddns.commit_record("198.51.100.7", "A", &config.cloudflare, 300, false, &mut std::collections::HashSet::new())
            .await;
    }

    #[tokio::test]
    async fn test_skips_up_to_date_record() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-noop";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-1", "name": "example.com", "content": "198.51.100.7", "proxied": false },
                    { "id": "rec-2", "name": "vpn.example.com", "content": "198.51.100.7", "proxied": true }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri());
        let config = test_config(zone_id);
        ddns.commit_record("198.51.100.7", "A", &config.cloudflare, 300, false, &mut std::collections::HashSet::new())
            .await;
    }

    #[tokio::test]
    async fn test_dry_run_does_not_mutate() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-dry";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri()).dry_run();
        let config = test_config(zone_id);
        ddns.commit_record("198.51.100.7", "A", &config.cloudflare, 300, false, &mut std::collections::HashSet::new())
            .await;
    }

    #[tokio::test]
    async fn test_purge_duplicate_records() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-purge";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-keep", "name": "example.com", "content": "198.51.100.7", "proxied": false },
                    { "id": "rec-dup", "name": "example.com", "content": "198.51.100.7", "proxied": false }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-keep")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri());
        let config = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "test-token".to_string(),
                    api_key: None,
                },
                zone_id: zone_id.to_string(),
                subdomains: vec![LegacySubdomainEntry::Detailed {
                    name: "".to_string(),
                    proxied: false,
                }],
                proxied: false,
            }],
            a: true,
            aaaa: false,
            purge_unknown_records: true,
            ttl: 300,
            ip4_provider: None,
            ip6_provider: None,
        };
        ddns.commit_record("198.51.100.7", "A", &config.cloudflare, 300, true, &mut std::collections::HashSet::new())
            .await;
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

    #[tokio::test]
    async fn test_end_to_end_detect_and_update() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-e2e";

        Mock::given(method("GET"))
            .and(path("/cdn-cgi/trace"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("fl=1f1\nh=mock\nip=203.0.113.99\nts=0\n"),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-root", "name": "example.com", "content": "10.0.0.1", "proxied": false }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("PUT"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-root")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "rec-root" }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let ddns = TestDdnsClient::new(&mock_server.uri());
        let ip = ddns.get_ip().await;
        assert_eq!(ip, Some("203.0.113.99".to_string()));

        let config = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "test-token".to_string(),
                    api_key: None,
                },
                zone_id: zone_id.to_string(),
                subdomains: vec![LegacySubdomainEntry::Detailed {
                    name: "".to_string(),
                    proxied: false,
                }],
                proxied: false,
            }],
            a: true,
            aaaa: false,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: None,
            ip6_provider: None,
        };

        ddns.commit_record("203.0.113.99", "A", &config.cloudflare, 300, false, &mut std::collections::HashSet::new())
            .await;
    }
}
