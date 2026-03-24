use crate::cf_ip_filter::CachedCloudflareFilter;
use crate::cloudflare::{CloudflareHandle, SetResult};
use crate::config::{AppConfig, LegacyCloudflareEntry, LegacySubdomainEntry};
use crate::domain::make_fqdn;
use crate::notifier::{CompositeNotifier, Heartbeat, Message};
use crate::pp::{self, PP};
use crate::provider::IpType;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

/// Run a single update cycle.
pub async fn update_once(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    heartbeat: &Heartbeat,
    cf_cache: &mut CachedCloudflareFilter,
    ppfmt: &PP,
    noop_reported: &mut HashSet<String>,
    detection_client: &Client,
) -> bool {
    let mut all_ok = true;
    let mut messages = Vec::new();
    let mut notify = false; // NEW: track meaningful events

    if config.legacy_mode {
        let (ok, legacy_msgs, legacy_notify) =
            update_legacy(config, cf_cache, ppfmt, noop_reported, detection_client).await;
        all_ok = ok;
        messages = legacy_msgs;
        notify = legacy_notify;
    } else {
        // Detect IPs for each provider
        let mut detected_ips: HashMap<IpType, Vec<IpAddr>> = HashMap::new();

        for (ip_type, provider) in &config.providers {
            ppfmt.infof(
                pp::EMOJI_DETECT,
                &format!("Detecting {} via {}", ip_type.describe(), provider.name()),
            );
            let ips = provider
                .detect_ips(&detection_client, *ip_type, config.detection_timeout, ppfmt)
                .await;

            if ips.is_empty() {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!("No {} address detected", ip_type.describe()),
                );
                messages.push(Message::new_fail(&format!(
                    "Failed to detect {} address",
                    ip_type.describe()
                )));
            } else {
                let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                ppfmt.infof(
                    pp::EMOJI_DETECT,
                    &format!("Detected {}: {}", ip_type.describe(), ip_strs.join(", ")),
                );
                messages.push(Message::new_ok(&format!(
                    "Detected {}: {}",
                    ip_type.describe(),
                    ip_strs.join(", ")
                )));
                detected_ips.insert(*ip_type, ips);
            }
        }

        // Filter out Cloudflare IPs if enabled
        if config.reject_cloudflare_ips {
            if let Some(cf_filter) =
                cf_cache.get(&detection_client, config.detection_timeout, ppfmt).await
            {
                for (ip_type, ips) in detected_ips.iter_mut() {
                    let before_count = ips.len();
                    ips.retain(|ip| {
                        if cf_filter.contains(ip) {
                            ppfmt.warningf(
                                pp::EMOJI_WARNING,
                                &format!(
                                    "Rejected {ip}: matches Cloudflare IP range ({})",
                                    ip_type.describe()
                                ),
                            );
                            false
                        } else {
                            true
                        }
                    });
                    if ips.is_empty() && before_count > 0 {
                        ppfmt.warningf(
                            pp::EMOJI_WARNING,
                            &format!(
                                "All detected {} addresses were Cloudflare IPs; skipping updates for this type",
                                ip_type.describe()
                            ),
                        );
                        messages.push(Message::new_fail(&format!(
                            "All {} addresses rejected (Cloudflare IPs)",
                            ip_type.describe()
                        )));
                    }
                }
            } else if !detected_ips.is_empty() {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    "Could not fetch Cloudflare IP ranges; skipping update to avoid writing Cloudflare IPs",
                );
                detected_ips.clear();
            }
        }

        // Update DNS records (env var mode - domain-based)
        for (ip_type, domains) in &config.domains {
            let ips = detected_ips.get(ip_type).cloned().unwrap_or_default();
            let record_type = ip_type.record_type();

            for domain_str in domains {
                // Find zone ID for this domain
                let zone_id = match handle.zone_id_of_domain(domain_str, ppfmt).await {
                    Some(id) => id,
                    None => {
                        ppfmt.errorf(
                            pp::EMOJI_ERROR,
                            &format!("Could not find zone for domain {domain_str}"),
                        );
                        all_ok = false;
                        messages.push(Message::new_fail(&format!(
                            "Failed to find zone for {domain_str}"
                        )));
                        continue;
                    }
                };

                let proxied = config
                    .proxied_expression
                    .as_ref()
                    .map(|f| f(domain_str))
                    .unwrap_or(false);

                let result = handle
                    .set_ips(
                        &zone_id,
                        domain_str,
                        record_type,
                        &ips,
                        proxied,
                        config.ttl,
                        config.record_comment.as_deref(),
                        config.dry_run,
                        ppfmt,
                    )
                    .await;

                let noop_key = format!("{domain_str}:{record_type}");
                match result {
                    SetResult::Updated => {
                        noop_reported.remove(&noop_key);
                        notify = true;
                        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                        messages.push(Message::new_ok(&format!(
                            "Updated {domain_str} -> {}",
                            ip_strs.join(", ")
                        )));
                    }
                    SetResult::Failed => {
                        noop_reported.remove(&noop_key);
                        notify = true;
                        all_ok = false;
                        messages.push(Message::new_fail(&format!(
                            "Failed to update {domain_str}"
                        )));
                    }
                    SetResult::Noop => {
                        if noop_reported.insert(noop_key) {
                            ppfmt.infof(pp::EMOJI_SKIP, &format!("Record {domain_str} is up to date"));
                        }
                    }
                }
            }
        }

        // Update WAF lists
        for waf_list in &config.waf_lists {
            // Collect all detected IPs for WAF lists
            let all_ips: Vec<IpAddr> = detected_ips
                .values()
                .flatten()
                .copied()
                .collect();

            let result = handle
                .set_waf_list(
                    waf_list,
                    &all_ips,
                    config.waf_list_item_comment.as_deref(),
                    config.waf_list_description.as_deref(),
                    config.dry_run,
                    ppfmt,
                )
                .await;

            let noop_key = format!("waf:{}", waf_list.describe());
            match result {
                SetResult::Updated => {
                    noop_reported.remove(&noop_key);
                    notify = true;
                    messages.push(Message::new_ok(&format!(
                        "Updated WAF list {}",
                        waf_list.describe()
                    )));
                }
                SetResult::Failed => {
                    noop_reported.remove(&noop_key);
                    notify = true;
                    all_ok = false;
                    messages.push(Message::new_fail(&format!(
                        "Failed to update WAF list {}",
                        waf_list.describe()
                    )));
                }
                SetResult::Noop => {
                    if noop_reported.insert(noop_key) {
                        ppfmt.infof(pp::EMOJI_SKIP, &format!("WAF list {} is up to date", waf_list.describe()));
                    }
                }
            }
        }
    }

    // Always ping heartbeat so monitors know the updater is alive
    let heartbeat_msg = Message::merge(messages.clone());
    heartbeat.ping(&heartbeat_msg).await;

    // Send notifications ONLY when IP changed or failed
    if notify {
        let notifier_msg = Message::merge(messages);
        notifier.send(&notifier_msg).await;
    }

    all_ok
}

/// Run legacy mode update (using the original cloudflare-ddns logic with zone_id-based config).
///
/// IP detection uses the shared provider abstraction (`config.providers`), which builds
/// IP-family-bound clients (0.0.0.0 for IPv4, [::] for IPv6). This prevents the old
/// wrong-family warning on dual-stack hosts and honours `ip4_provider`/`ip6_provider`
/// overrides from config.json.
async fn update_legacy(
    config: &AppConfig,
    cf_cache: &mut CachedCloudflareFilter,
    ppfmt: &PP,
    noop_reported: &mut HashSet<String>,
    detection_client: &Client,
) -> (bool, Vec<Message>, bool) {
    let legacy = match &config.legacy_config {
        Some(l) => l,
        None => return (false, Vec::new(), false),
    };

    let ddns = LegacyDdnsClient {
        client: Client::builder()
            .timeout(config.update_timeout)
            .build()
            .unwrap_or_default(),
        cf_api_base: "https://api.cloudflare.com/client/v4".to_string(),
        dry_run: config.dry_run,
    };

    let mut ips = HashMap::new();

    for (ip_type, provider) in &config.providers {
        ppfmt.infof(
            pp::EMOJI_DETECT,
            &format!("Detecting {} via {}", ip_type.describe(), provider.name()),
        );
        let detected = provider
            .detect_ips(&detection_client, *ip_type, config.detection_timeout, ppfmt)
            .await;

        if detected.is_empty() {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("No {} address detected", ip_type.describe()),
            );
            if legacy.purge_unknown_records {
                ddns.delete_entries(ip_type.record_type(), &legacy.cloudflare)
                    .await;
            }
        } else {
            let key = match ip_type {
                IpType::V4 => "ipv4",
                IpType::V6 => "ipv6",
            };
            ppfmt.infof(
                pp::EMOJI_DETECT,
                &format!("Detected {}: {}", ip_type.describe(), detected[0]),
            );
            ips.insert(
                key.to_string(),
                LegacyIpInfo {
                    record_type: ip_type.record_type().to_string(),
                    ip: detected[0].to_string(),
                },
            );
        }
    }

    // Filter out Cloudflare IPs if enabled
    if config.reject_cloudflare_ips {
        let before_count = ips.len();
        if let Some(cf_filter) =
            cf_cache.get(&detection_client, config.detection_timeout, ppfmt).await
        {
            ips.retain(|key, ip_info| {
                if let Ok(addr) = ip_info.ip.parse::<std::net::IpAddr>() {
                    if cf_filter.contains(&addr) {
                        ppfmt.warningf(
                            pp::EMOJI_WARNING,
                            &format!(
                                "Rejected {}: matches Cloudflare IP range ({})",
                                ip_info.ip, key
                            ),
                        );
                        return false;
                    }
                }
                true
            });
            if ips.is_empty() && before_count > 0 {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    "All detected addresses were Cloudflare IPs; skipping updates",
                );
            }
        } else if !ips.is_empty() {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                "Could not fetch Cloudflare IP ranges; skipping update to avoid writing Cloudflare IPs",
            );
            ips.clear();
        }
    }

    let (msgs, should_notify) = ddns
        .update_ips(
            &ips,
            &legacy.cloudflare,
            legacy.ttl,
            legacy.purge_unknown_records,
            noop_reported,
        )
        .await;

    (true, msgs, should_notify)
}

/// Delete records on stop (for env var mode).
pub async fn final_delete(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    heartbeat: &Heartbeat,
    ppfmt: &PP,
) {
    let mut messages = Vec::new();

    // Delete DNS records
    for (ip_type, domains) in &config.domains {
        let record_type = ip_type.record_type();

        for domain_str in domains {
            if let Some(zone_id) = handle.zone_id_of_domain(domain_str, ppfmt).await {
                handle.final_delete(&zone_id, domain_str, record_type, ppfmt).await;
                messages.push(Message::new_ok(&format!("Deleted records for {domain_str}")));
            }
        }
    }

    // Clear WAF lists
    for waf_list in &config.waf_lists {
        handle.final_clear_waf_list(waf_list, ppfmt).await;
        messages.push(Message::new_ok(&format!(
            "Cleared WAF list {}",
            waf_list.describe()
        )));
    }

    // Send notifications
    let msg = Message::merge(messages);
    heartbeat.exit(&msg).await;
    notifier.send(&msg).await;
}

// ============================================================
// Legacy DDNS Client (preserved for backwards compatibility)
// ============================================================

pub struct LegacyIpInfo {
    pub record_type: String,
    pub ip: String,
}

struct LegacyDdnsClient {
    client: Client,
    cf_api_base: String,
    dry_run: bool,
}

impl LegacyDdnsClient {
    async fn cf_api<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        method: &str,
        entry: &LegacyCloudflareEntry,
        body: Option<&impl serde::Serialize>,
    ) -> Option<T> {
        let url = format!("{}/{endpoint}", self.cf_api_base);

        let mut req = match method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "PATCH" => self.client.patch(&url),
            "DELETE" => self.client.delete(&url),
            _ => return None,
        };

        if !entry.authentication.api_token.is_empty()
            && entry.authentication.api_token != "api_token_here"
        {
            req = req.header(
                "Authorization",
                format!("Bearer {}", entry.authentication.api_token),
            );
        } else if let Some(api_key) = &entry.authentication.api_key {
            req = req
                .header("X-Auth-Email", &api_key.account_email)
                .header("X-Auth-Key", &api_key.api_key);
        }

        if let Some(b) = body {
            req = req.json(b);
        }

        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json::<T>().await.ok()
                } else {
                    let url_str = resp.url().to_string();
                    let text = resp.text().await.unwrap_or_default();
                    eprintln!("Error sending '{method}' request to '{url_str}': {text}");
                    None
                }
            }
            Err(e) => {
                eprintln!("Exception sending '{method}' request to '{endpoint}': {e}");
                None
            }
        }
    }

    async fn delete_entries(&self, record_type: &str, entries: &[LegacyCloudflareEntry]) {
        for entry in entries {
            let endpoint = format!(
                "zones/{}/dns_records?per_page=100&type={record_type}",
                entry.zone_id
            );
            let answer: Option<LegacyCfResponse<Vec<LegacyDnsRecord>>> =
                self.cf_api(&endpoint, "GET", entry, None::<&()>.as_ref())
                    .await;

            if let Some(resp) = answer {
                if let Some(records) = resp.result {
                    for record in records {
                        if self.dry_run {
                            println!("[DRY RUN] Would delete stale record {}", record.id);
                            continue;
                        }
                        let del_endpoint = format!(
                            "zones/{}/dns_records/{}",
                            entry.zone_id, record.id
                        );
                        let _: Option<serde_json::Value> = self
                            .cf_api(&del_endpoint, "DELETE", entry, None::<&()>.as_ref())
                            .await;
                        println!("Deleted stale record {}", record.id);
                    }
                }
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    async fn update_ips(
        &self,
        ips: &HashMap<String, LegacyIpInfo>,
        config: &[LegacyCloudflareEntry],
        ttl: i64,
        purge_unknown_records: bool,
        noop_reported: &mut HashSet<String>,
    ) -> (Vec<Message>, bool) {
        let mut messages = Vec::new();
        let mut notify = false;
        for ip in ips.values() {
            let (msgs, changed) = self
                .commit_record(ip, config, ttl, purge_unknown_records, noop_reported)
                .await;
            messages.extend(msgs);
            if changed {
                notify = true;
            }
        }
        (messages, notify)
    }

    async fn commit_record(
        &self,
        ip: &LegacyIpInfo,
        config: &[LegacyCloudflareEntry],
        ttl: i64,
        purge_unknown_records: bool,
        noop_reported: &mut HashSet<String>,
    ) -> (Vec<Message>, bool) {
        let mut messages = Vec::new();
        let mut changed = false;
        for entry in config {
            let zone_resp: Option<LegacyCfResponse<LegacyZoneResult>> = self
                .cf_api(
                    &format!("zones/{}", entry.zone_id),
                    "GET",
                    entry,
                    None::<&()>.as_ref(),
                )
                .await;

            let base_domain = match zone_resp.and_then(|r| r.result) {
                Some(z) => z.name,
                None => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
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

                let fqdn = make_fqdn(&name, &base_domain);

                let record = LegacyDnsRecordPayload {
                    record_type: ip.record_type.clone(),
                    name: fqdn.clone(),
                    content: ip.ip.clone(),
                    proxied,
                    ttl,
                };

                let dns_endpoint = format!(
                    "zones/{}/dns_records?per_page=100&type={}",
                    entry.zone_id, ip.record_type
                );
                let dns_records: Option<LegacyCfResponse<Vec<LegacyDnsRecord>>> =
                    self.cf_api(&dns_endpoint, "GET", entry, None::<&()>.as_ref())
                        .await;

                let mut identifier: Option<String> = None;
                let mut modified = false;
                let mut duplicate_ids: Vec<String> = Vec::new();

                if let Some(resp) = dns_records {
                    if let Some(records) = resp.result {
                        for r in &records {
                            if r.name == fqdn {
                                if let Some(ref existing_id) = identifier {
                                    if r.content == ip.ip {
                                        duplicate_ids.push(existing_id.clone());
                                        identifier = Some(r.id.clone());
                                    } else {
                                        duplicate_ids.push(r.id.clone());
                                    }
                                } else {
                                    identifier = Some(r.id.clone());
                                    if r.content != record.content
                                        || r.proxied != record.proxied
                                    {
                                        modified = true;
                                    }
                                }
                            }
                        }
                    }
                }

                let noop_key = format!("{fqdn}:{}", ip.record_type);
                if let Some(ref id) = identifier {
                    if modified {
                        noop_reported.remove(&noop_key);
                        changed = true;
                        if self.dry_run {
                            println!("[DRY RUN] Would update record {fqdn} -> {}", ip.ip);
                        } else {
                            println!("Updating record {fqdn} -> {}", ip.ip);
                            let update_endpoint =
                                format!("zones/{}/dns_records/{id}", entry.zone_id);
                            let _: Option<serde_json::Value> = self
                                .cf_api(&update_endpoint, "PUT", entry, Some(&record))
                                .await;
                        }
                        messages.push(Message::new_ok(&format!(
                            "Updated {fqdn} -> {}",
                            ip.ip
                        )));
                    } else if noop_reported.insert(noop_key) {
                        if self.dry_run {
                            println!("[DRY RUN] Record {fqdn} is up to date");
                        } else {
                            println!("Record {fqdn} is up to date");
                        }
                    }
                } else {
                    noop_reported.remove(&noop_key);
                    changed = true;
                    if self.dry_run {
                        println!("[DRY RUN] Would add new record {fqdn} -> {}", ip.ip);
                    } else {
                        println!("Adding new record {fqdn} -> {}", ip.ip);
                        let create_endpoint = format!("zones/{}/dns_records", entry.zone_id);
                        let _: Option<serde_json::Value> = self
                            .cf_api(&create_endpoint, "POST", entry, Some(&record))
                            .await;
                    }
                    messages.push(Message::new_ok(&format!(
                        "Created {fqdn} -> {}",
                        ip.ip
                    )));
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
                                .cf_api(&del_endpoint, "DELETE", entry, None::<&()>.as_ref())
                                .await;
                        }
                    }
                }
            }
        }
        (messages, changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::{Auth, CloudflareHandle, TTL, WAFList};
    use crate::config::{AppConfig, CronSchedule};
    use crate::notifier::{CompositeNotifier, Heartbeat};
    use crate::pp::PP;
    use crate::provider::{IpType, ProviderType};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::Duration;
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -------------------------------------------------------
    // Helpers
    // -------------------------------------------------------

    fn pp() -> PP {
        // quiet=true suppresses output during tests
        PP::new(false, true)
    }

    fn empty_notifier() -> CompositeNotifier {
        CompositeNotifier::new(vec![])
    }

    fn empty_heartbeat() -> Heartbeat {
        Heartbeat::new(vec![])
    }

    /// Build a minimal AppConfig for env-var (non-legacy) mode with a single V4 domain.
    fn make_config(
        providers: HashMap<IpType, ProviderType>,
        domains: HashMap<IpType, Vec<String>>,
        waf_lists: Vec<WAFList>,
        dry_run: bool,
    ) -> AppConfig {
        AppConfig {
            auth: Auth::Token("test-token".to_string()),
            providers,
            domains,
            waf_lists,
            update_cron: CronSchedule::Once,
            update_on_start: true,
            delete_on_stop: false,
            ttl: TTL::AUTO,
            proxied_expression: None,
            record_comment: None,
            managed_comment_regex: None,
            waf_list_description: None,
            waf_list_item_comment: None,
            managed_waf_comment_regex: None,
            detection_timeout: Duration::from_secs(5),
            update_timeout: Duration::from_secs(5),
            reject_cloudflare_ips: false,
            dry_run,
            emoji: false,
            quiet: true,
            legacy_mode: false,
            legacy_config: None,
            repeat: false,
        }
    }

    fn handle(base_url: &str) -> CloudflareHandle {
        CloudflareHandle::with_base_url(base_url, Auth::Token("test-token".to_string()))
    }

    /// JSON for a Cloudflare zones list response returning a single zone.
    fn zones_response(zone_id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "result": [{ "id": zone_id, "name": name }]
        })
    }

    /// JSON for an empty zones list response (zone not found).
    fn zones_empty_response() -> serde_json::Value {
        serde_json::json!({ "result": [] })
    }

    /// JSON for an empty DNS records list.
    fn dns_records_empty() -> serde_json::Value {
        serde_json::json!({ "result": [] })
    }

    /// JSON for a DNS records list containing one record.
    fn dns_records_one(id: &str, name: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "result": [{
                "id": id,
                "name": name,
                "content": content,
                "proxied": false,
                "ttl": 1,
                "comment": null
            }]
        })
    }

    /// JSON for a successful DNS record create/update response.
    fn dns_record_created(id: &str, name: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "result": {
                "id": id,
                "name": name,
                "content": content,
                "proxied": false,
                "ttl": 1,
                "comment": null
            }
        })
    }

    /// JSON for a WAF lists response returning a single list.
    fn waf_lists_response(list_id: &str, list_name: &str) -> serde_json::Value {
        serde_json::json!({
            "result": [{ "id": list_id, "name": list_name }]
        })
    }

    /// JSON for WAF list items response.
    fn waf_items_response(items: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "result": items })
    }

    // -------------------------------------------------------
    // update_once tests
    // -------------------------------------------------------

    /// update_once with a Literal IP provider creates a new DNS record when none exists.
    #[tokio::test]
    async fn test_update_once_creates_new_record() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";

        // Zone lookup: GET zones?name=home.example.com
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List existing records: GET zones/{zone_id}/dns_records?...
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Create record: POST zones/{zone_id}/dns_records
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-1", domain, ip)),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }

    /// update_once returns true (all_ok) when IP is already correct (Noop),
    /// and populates noop_reported so subsequent calls suppress the message.
    #[tokio::test]
    async fn test_update_once_noop_when_record_up_to_date() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List existing records - record already exists with correct IP
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_records_one("rec-1", domain, ip)),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let mut noop_reported = HashSet::new();

        // First call: noop_reported is empty, so "up to date" is reported and key is inserted
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut noop_reported, &Client::new()).await;
        assert!(ok);
        assert!(noop_reported.contains("home.example.com:A"), "noop_reported should contain the domain key after first noop");

        // Second call: noop_reported already has the key, so the message is suppressed
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut noop_reported, &Client::new()).await;
        assert!(ok);
        assert_eq!(noop_reported.len(), 1, "noop_reported should still have exactly one entry");
    }

    /// noop_reported is cleared when a record is updated, so "up to date" prints again
    /// on the next noop cycle.
    #[tokio::test]
    async fn test_update_once_noop_reported_cleared_on_change() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let old_ip = "198.51.100.42";
        let new_ip = "198.51.100.99";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List existing records - record has old IP, will be updated
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_records_one("rec-1", domain, old_ip)),
            )
            .mount(&server)
            .await;

        // Create record (new IP doesn't match existing, so it creates + deletes stale)
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-2", domain, new_ip)),
            )
            .mount(&server)
            .await;

        // Delete stale record
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"result": {}})))
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![new_ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        // Pre-populate noop_reported as if a previous cycle reported it
        let mut noop_reported = HashSet::new();
        noop_reported.insert("home.example.com:A".to_string());

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut noop_reported, &Client::new()).await;
        assert!(ok);
        assert!(!noop_reported.contains("home.example.com:A"), "noop_reported should be cleared after an update");
    }

    /// update_once returns true even when IP detection yields empty (no providers configured),
    /// but marks the result as degraded via messages (all_ok = false only on zone/record errors).
    /// Here we use ProviderType::None so no IPs are detected - all_ok stays true since there
    /// is no domain update attempted (empty ips -> set_ips with empty slice -> Noop).
    #[tokio::test]
    async fn test_update_once_empty_ip_detection_with_none_provider() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";

        // Zone lookup - still called even with empty IPs
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List records (set_ips called with empty ips, will list to delete managed records)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Provider that returns no IPs
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        // all_ok = true because no zone-level errors occurred (empty ips just noop or warn)
        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        // Providers with None are not inserted in loop, so no IP detection warning is emitted,
        // no detected_ips entry is created, and set_ips is called with empty slice -> Noop.
        assert!(ok);
    }

    /// When the Literal provider is used but the zone is not found, update_once returns false.
    #[tokio::test]
    async fn test_update_once_returns_false_when_zone_not_found() {
        let server = MockServer::start().await;
        let domain = "missing.example.com";
        let ip = "198.51.100.1";

        // Zone lookup for full domain fails
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_empty_response()),
            )
            .mount(&server)
            .await;

        // Zone lookup for parent domain also fails
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_empty_response()),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(!ok, "Expected false when zone is not found");
    }

    /// update_once in dry_run mode does NOT POST to create records.
    #[tokio::test]
    async fn test_update_once_dry_run_does_not_create_record() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List existing records - none exist
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST must NOT be called in dry_run - if it is, wiremock will panic at drop
        // (no Mock registered for POST, and strict mode is default for unexpected requests)

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], true /* dry_run */);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        // dry_run returns Updated from set_ips (it signals intent), all_ok should be true
        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }

    /// update_once with WAF lists: IPs are detected and WAF list is updated.
    #[tokio::test]
    async fn test_update_once_with_waf_list() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";
        let ip = "198.51.100.42";

        // GET accounts/{account_id}/rules/lists - returns our list
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET list items - empty (need to add the IP)
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_items_response(serde_json::json!([]))),
            )
            .mount(&server)
            .await;

        // POST to add items
        Mock::given(method("POST"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {}
            })))
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        // No DNS domains - only WAF list
        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }

    /// update_once with WAF list in dry_run mode: items are NOT POSTed.
    #[tokio::test]
    async fn test_update_once_waf_list_dry_run() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";
        let ip = "198.51.100.42";

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_items_response(serde_json::json!([]))),
            )
            .mount(&server)
            .await;

        // No POST mock registered - dry_run must not POST

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], true /* dry_run */);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }

    /// update_once with WAF list when WAF list is not found returns false (Failed).
    #[tokio::test]
    async fn test_update_once_waf_list_not_found_returns_false() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let ip = "198.51.100.42";

        // GET accounts/{account_id}/rules/lists - returns empty (list not found)
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": [] })),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip.parse::<IpAddr>().unwrap()],
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(!ok, "Expected false when WAF list is not found");
    }

    /// update_once with two domains (V4 and V6) - both updated independently.
    #[tokio::test]
    async fn test_update_once_v4_and_v6_domains() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain_v4 = "v4.example.com";
        let domain_v6 = "v6.example.com";
        let ip_v4 = "198.51.100.42";
        let ip_v6 = "2001:db8::1";

        // Zone lookups
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain_v4))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain_v6))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List records for both domains (no existing records)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Create record for V4
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-v4", domain_v4, ip_v4)),
            )
            .mount(&server)
            .await;

        // Create record for V6
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-v6", domain_v6, ip_v6)),
            )
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse::<IpAddr>().unwrap()],
            },
        );
        providers.insert(
            IpType::V6,
            ProviderType::Literal {
                ips: vec![ip_v6.parse::<IpAddr>().unwrap()],
            },
        );

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain_v4.to_string()]);
        domains.insert(IpType::V6, vec![domain_v6.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }

    /// update_once with no providers and no domains is a degenerate but valid case - returns true.
    #[tokio::test]
    async fn test_update_once_no_providers_no_domains() {
        let server = MockServer::start().await;
        // No HTTP mocks needed - nothing should be called

        let config = make_config(HashMap::new(), HashMap::new(), vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }

    // -------------------------------------------------------
    // final_delete tests
    // -------------------------------------------------------

    /// final_delete removes existing DNS records for a domain.
    #[tokio::test]
    async fn test_final_delete_removes_dns_records() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let record_id = "rec-to-delete";
        let ip = "198.51.100.1";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List records - one record exists
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_records_one(record_id, domain, ip)),
            )
            .mount(&server)
            .await;

        // DELETE the record
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/{record_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(HashMap::new(), domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        // Should complete without panic
        final_delete(&config, &cf, &notifier, &heartbeat, &ppfmt).await;
    }

    /// final_delete does nothing when no records exist for the domain.
    #[tokio::test]
    async fn test_final_delete_noop_when_no_records() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List records - empty
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // No DELETE mock - ensures DELETE is not called

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(HashMap::new(), domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &heartbeat, &ppfmt).await;
    }

    /// final_delete skips DNS deletion when zone is not found.
    #[tokio::test]
    async fn test_final_delete_skips_when_zone_not_found() {
        let server = MockServer::start().await;
        let domain = "missing.example.com";

        // Zone lookup - not found at either level
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_empty_response()),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_empty_response()),
            )
            .mount(&server)
            .await;

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(HashMap::new(), domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        // Should complete without error - zone not found means skip
        final_delete(&config, &cf, &notifier, &heartbeat, &ppfmt).await;
    }

    /// final_delete clears WAF list items.
    #[tokio::test]
    async fn test_final_delete_clears_waf_list() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";
        let item_id = "item-abc";
        let ip = "198.51.100.42";

        // GET lists
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET items - one item exists
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([
                    { "id": item_id, "ip": ip, "comment": null }
                ]))),
            )
            .mount(&server)
            .await;

        // DELETE items
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(HashMap::new(), HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &heartbeat, &ppfmt).await;
    }

    /// final_delete with no WAF items does not call DELETE.
    #[tokio::test]
    async fn test_final_delete_waf_list_no_items() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let list_name = "my_list";
        let list_id = "list-id-1";

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET items - empty
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_items_response(serde_json::json!([]))),
            )
            .mount(&server)
            .await;

        // No DELETE mock - ensures DELETE is not called for empty list

        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(HashMap::new(), HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &heartbeat, &ppfmt).await;
    }

    /// final_delete with both DNS domains and WAF lists - both are cleaned up.
    #[tokio::test]
    async fn test_final_delete_dns_and_waf() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let record_id = "rec-del";
        let ip = "198.51.100.5";
        let account_id = "acc-999";
        let list_name = "ddns_ips";
        let list_id = "list-xyz";
        let item_id = "item-xyz";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List DNS records
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_records_one(record_id, domain, ip)),
            )
            .mount(&server)
            .await;

        // DELETE DNS record
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/{record_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // WAF: GET lists
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // WAF: GET items
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([
                    { "id": item_id, "ip": ip, "comment": null }
                ]))),
            )
            .mount(&server)
            .await;

        // WAF: DELETE items
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: list_name.to_string(),
        };

        let config = make_config(HashMap::new(), domains, vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &heartbeat, &ppfmt).await;
    }

    // -------------------------------------------------------
    // Literal provider IP detection filtering
    // -------------------------------------------------------

    /// Literal provider only injects IPs of the matching type into the update cycle.
    /// V6 Literal IPs are ignored when the domain is V4-only.
    #[tokio::test]
    async fn test_update_once_literal_v4_not_used_for_v6_domain() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain_v6 = "v6only.example.com";
        // Only a V4 literal provider is configured but domain is V6
        let ip_v4 = "198.51.100.1";

        // Zone lookup for V6 domain
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain_v6))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List AAAA records - no existing records; set_ips called with empty ips -> Noop
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // V4 literal provider but V6 domain - the V4 provider will not be in detected_ips for V6
        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse::<IpAddr>().unwrap()],
            },
        );
        // No V6 provider -> detected_ips won't have V6 -> set_ips called with empty slice
        let mut domains = HashMap::new();
        domains.insert(IpType::V6, vec![domain_v6.to_string()]);

        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        // set_ips with empty ips and no existing records = Noop; all_ok = true
        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(&config, &cf, &notifier, &heartbeat, &mut cf_cache, &ppfmt, &mut HashSet::new(), &Client::new()).await;
        assert!(ok);
    }
    // -------------------------------------------------------
    // LegacyDdnsClient tests (internal/private struct)
    // -------------------------------------------------------

    #[tokio::test]
    async fn test_legacy_cf_api_get_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/zone1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let entry = crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: "zone1".to_string(),
            subdomains: vec![],
            proxied: false,
        };
        let result: Option<LegacyCfResponse<LegacyZoneResult>> = ddns
            .cf_api("zones/zone1", "GET", &entry, None::<&()>.as_ref())
            .await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().result.unwrap().name, "example.com");
    }

    #[tokio::test]
    async fn test_legacy_cf_api_post_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "new-rec" }
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let entry = crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: "zone1".to_string(),
            subdomains: vec![],
            proxied: false,
        };
        let body = serde_json::json!({"name": "test"});
        let result: Option<serde_json::Value> = ddns
            .cf_api("zones/zone1/dns_records", "POST", &entry, Some(&body))
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_legacy_cf_api_error_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let entry = crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: "zone1".to_string(),
            subdomains: vec![],
            proxied: false,
        };
        let result: Option<serde_json::Value> = ddns
            .cf_api("zones/zone1", "GET", &entry, None::<&()>.as_ref())
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_legacy_cf_api_unknown_method() {
        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: "http://localhost".to_string(),
            dry_run: false,
        };
        let entry = crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: "zone1".to_string(),
            subdomains: vec![],
            proxied: false,
        };
        let result: Option<serde_json::Value> = ddns
            .cf_api("zones/zone1", "OPTIONS", &entry, None::<&()>.as_ref())
            .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_legacy_cf_api_with_api_key_auth() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let entry = crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: String::new(),
                api_key: Some(crate::config::LegacyApiKey {
                    api_key: "key123".to_string(),
                    account_email: "user@example.com".to_string(),
                }),
            },
            zone_id: "zone1".to_string(),
            subdomains: vec![],
            proxied: false,
        };
        let result: Option<serde_json::Value> = ddns
            .cf_api("zones/zone1", "GET", &entry, None::<&()>.as_ref())
            .await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_legacy_commit_record_creates_new() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg1";

        // GET zone
        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        // GET dns_records - empty
        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        // POST create
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "new-rec" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let ip = LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "198.51.100.1".to_string(),
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
            proxied: false,
        }];
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new()).await;
    }

    #[tokio::test]
    async fn test_legacy_commit_record_updates_existing() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg2";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{
                    "id": "rec-1",
                    "name": "example.com",
                    "content": "10.0.0.1",
                    "proxied": false
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "rec-1" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let ip = LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "198.51.100.1".to_string(),
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
            proxied: false,
        }];
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new()).await;
    }

    #[tokio::test]
    async fn test_legacy_commit_record_dry_run() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg3";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: true,
        };
        let ip = LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "198.51.100.1".to_string(),
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
            proxied: false,
        }];
        // Should not POST
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new()).await;
    }

    #[tokio::test]
    async fn test_legacy_commit_record_with_detailed_subdomain() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg4";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "new-rec" }
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let ip = LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "198.51.100.1".to_string(),
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Detailed {
                name: "vpn".to_string(),
                proxied: true,
            }],
            proxied: false,
        }];
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new()).await;
    }

    #[tokio::test]
    async fn test_legacy_commit_record_purge_duplicates() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg5";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-1", "name": "example.com", "content": "198.51.100.1", "proxied": false },
                    { "id": "rec-dup", "name": "example.com", "content": "198.51.100.1", "proxied": false }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let ip = LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "198.51.100.1".to_string(),
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
            proxied: false,
        }];
        ddns.commit_record(&ip, &config, 300, true, &mut HashSet::new()).await;
    }

    #[tokio::test]
    async fn test_legacy_update_ips_calls_commit_for_each_ip() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg6";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "name": "example.com" }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": "new-rec" }
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let mut ips = HashMap::new();
        ips.insert("ipv4".to_string(), LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "198.51.100.1".to_string(),
        });
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
            proxied: false,
        }];
        ddns.update_ips(&ips, &config, 300, false, &mut HashSet::new()).await;
    }

    #[tokio::test]
    async fn test_legacy_delete_entries() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg7";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-1", "name": "example.com", "content": "10.0.0.1", "proxied": false }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![],
            proxied: false,
        }];
        ddns.delete_entries("A", &config).await;
    }

    #[tokio::test]
    async fn test_legacy_delete_entries_dry_run() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg8";

        Mock::given(method("GET"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "rec-1", "name": "example.com", "content": "10.0.0.1", "proxied": false }
                ]
            })))
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: Client::new(),
            cf_api_base: server.uri(),
            dry_run: true,
        };
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![],
            proxied: false,
        }];
        // dry_run: should not DELETE
        ddns.delete_entries("A", &config).await;
    }

}

// Legacy types for backwards compatibility
#[derive(Debug, serde::Deserialize)]
struct LegacyCfResponse<T> {
    result: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct LegacyZoneResult {
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct LegacyDnsRecord {
    id: String,
    name: String,
    content: String,
    proxied: bool,
}

#[derive(Debug, serde::Serialize)]
struct LegacyDnsRecordPayload {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    proxied: bool,
    ttl: i64,
}
