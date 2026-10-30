use crate::cf_ip_filter::CachedCloudflareFilter;
use crate::cloudflare::{CloudflareHandle, SetResult};
use crate::config::{AppConfig, LegacyCloudflareEntry, LegacySubdomainEntry};
use crate::domain::make_fqdn;
use crate::health;
use crate::notifier::{CompositeNotifier, Heartbeat, Message};
use crate::pp::{self, PP};
use crate::provider::{DetectionOutcome, IpType};
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
        // Each detection group (the default one plus any DOMAINS_2, ... groups)
        // detects its own addresses and updates its own domains. Identical
        // provider/family pairs are detected once per cycle.
        let mut detection_cache: HashMap<(String, IpType), DetectionOutcome> = HashMap::new();
        // WAF lists get the union of all groups' addresses, and are left alone
        // if any group's detection failed transiently.
        let mut waf_ips: Vec<IpAddr> = Vec::new();
        let mut any_detection_failed = false;

        for group in config.groups() {
            let tag = group.tag();
            // Types in `detection_failed` had a transient detection error: the real
            // IP is unknown, so their DNS records and WAF list entries are preserved
            // this cycle regardless of delete_on_failure (issue #277).
            let mut detected_ips: HashMap<IpType, Vec<IpAddr>> = HashMap::new();
            let mut detection_failed: HashSet<IpType> = HashSet::new();

            for (ip_type, provider) in group.providers {
                let cache_key = (provider.cache_key(), *ip_type);
                let outcome = match detection_cache.get(&cache_key) {
                    Some(cached) => cached.clone(),
                    None => {
                        ppfmt.infof(
                            pp::EMOJI_DETECT,
                            &format!(
                                "Detecting {}{tag} via {}",
                                ip_type.describe(),
                                provider.label()
                            ),
                        );
                        let outcome = provider
                            .detect(detection_client, *ip_type, config.detection_timeout, ppfmt)
                            .await;
                        detection_cache.insert(cache_key, outcome.clone());
                        outcome
                    }
                };
                match outcome {
                    DetectionOutcome::Ips(ips) => {
                        let ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                        ppfmt.infof(
                            pp::EMOJI_DETECT,
                            &format!(
                                "Detected {}{tag}: {}",
                                ip_type.describe(),
                                ip_strs.join(", ")
                            ),
                        );
                        messages.push(Message::new_ok(&format!(
                            "Detected {}{tag}: {}",
                            ip_type.describe(),
                            ip_strs.join(", ")
                        )));
                        detected_ips.insert(*ip_type, ips);
                    }
                    DetectionOutcome::NoIp => {
                        ppfmt.warningf(
                            pp::EMOJI_WARNING,
                            &format!("No {} address detected{tag}", ip_type.describe()),
                        );
                        messages.push(Message::new_fail(&format!(
                            "Failed to detect {} address{tag}",
                            ip_type.describe()
                        )));
                    }
                    DetectionOutcome::Failed => {
                        ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!(
                            "{} detection failed{tag}; skipping {} updates this cycle (existing records preserved)",
                            ip_type.describe(),
                            ip_type.describe()
                        ),
                    );
                        messages.push(Message::new_fail(&format!(
                            "Failed to detect {} address{tag}",
                            ip_type.describe()
                        )));
                        detection_failed.insert(*ip_type);
                    }
                }
            }

            // Filter out Cloudflare IPs if enabled
            if config.reject_cloudflare_ips {
                if let Some(cf_filter) = cf_cache
                    .get(detection_client, config.detection_timeout, ppfmt)
                    .await
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
                            // The real IP is unknown, not absent - preserve records.
                            detection_failed.insert(*ip_type);
                        }
                    }
                } else if !detected_ips.is_empty() {
                    ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    "Could not fetch Cloudflare IP ranges; skipping update to avoid writing Cloudflare IPs",
                );
                    detection_failed.extend(detected_ips.keys().copied());
                    detected_ips.clear();
                }
            }

            // Update DNS records (env var mode - domain-based)
            for (ip_type, domains) in group.domains {
                let ips = detected_ips.get(ip_type).cloned().unwrap_or_default();

                if ips.is_empty() {
                    // Transient detection failure: the real IP is unknown, so never
                    // touch existing records - not even with delete_on_failure set.
                    if detection_failed.contains(ip_type) {
                        ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!(
                            "Skipping {} update for {}: IP detection failed (existing records preserved)",
                            ip_type.describe(),
                            domains.join(", ")
                        ),
                    );
                        continue;
                    }
                    // Definitive "no address of this family": deletion is the
                    // documented DELETE_ON_FAILURE=true behavior; otherwise skip.
                    if !config.delete_on_failure {
                        ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!(
                            "Skipping {} update for {}: no {} address detected (existing records preserved)",
                            ip_type.describe(),
                            domains.join(", "),
                            ip_type.describe()
                        ),
                    );
                        continue;
                    }
                }

                let record_type = ip_type.record_type();

                for domain_str in domains {
                    health::mark_progress(config.detection_timeout + config.update_timeout);
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
                            if ips.is_empty() {
                                messages.push(Message::new_ok(&format!(
                                    "Deleted DNS records for {domain_str} (no {} address detected)",
                                    ip_type.describe()
                                )));
                            } else {
                                let ip_strs: Vec<String> =
                                    ips.iter().map(|ip| ip.to_string()).collect();
                                messages.push(Message::new_ok(&format!(
                                    "Updated {domain_str} -> {}",
                                    ip_strs.join(", ")
                                )));
                            }
                        }
                        SetResult::Failed => {
                            noop_reported.remove(&noop_key);
                            notify = true;
                            all_ok = false;
                            messages
                                .push(Message::new_fail(&format!("Failed to update {domain_str}")));
                        }
                        SetResult::Noop => {
                            if noop_reported.insert(noop_key) {
                                ppfmt.infof(
                                    pp::EMOJI_SKIP,
                                    &format!("Record {domain_str} is up to date"),
                                );
                            }
                        }
                    }
                }
            }

            waf_ips.extend(detected_ips.values().flatten().copied());
            any_detection_failed |= !detection_failed.is_empty();
        }

        // Update WAF lists.
        // A WAF list holds IPs from every configured family, so a transient
        // detection failure for any family would silently strip that family's
        // IPs from the list. Preserve the list until detection recovers.
        for waf_list in &config.waf_lists {
            health::mark_progress(config.detection_timeout + config.update_timeout);
            if any_detection_failed {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!(
                        "Skipping WAF list {} update: IP detection failed (existing items preserved)",
                        waf_list.describe()
                    ),
                );
                continue;
            }

            let mut all_ips = waf_ips.clone();
            all_ips.sort();
            all_ips.dedup();

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

            let noop_key = format!("waf:{}/{}", waf_list.account_id, waf_list.list_name);
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
                        ppfmt.infof(
                            pp::EMOJI_SKIP,
                            &format!("WAF list {} is up to date", waf_list.describe()),
                        );
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
    let mut ok = true;

    for (ip_type, provider) in &config.providers {
        ppfmt.infof(
            pp::EMOJI_DETECT,
            &format!("Detecting {} via {}", ip_type.describe(), provider.label()),
        );
        match provider
            .detect(detection_client, *ip_type, config.detection_timeout, ppfmt)
            .await
        {
            DetectionOutcome::Ips(detected) => {
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
            DetectionOutcome::NoIp => {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!("No {} address detected", ip_type.describe()),
                );
                if legacy.purge_unknown_records {
                    ok &= ddns
                        .delete_entries(ip_type.record_type(), &legacy.cloudflare)
                        .await;
                }
            }
            // Transient failure: the real IP is unknown, so never purge
            // records - a network blip must not take DNS down (issue #277).
            DetectionOutcome::Failed => {
                ok = false;
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!(
                        "{} detection failed; skipping {} updates this cycle (existing records preserved)",
                        ip_type.describe(),
                        ip_type.describe()
                    ),
                );
            }
        }
    }

    // Filter out Cloudflare IPs if enabled
    if config.reject_cloudflare_ips {
        let before_count = ips.len();
        if let Some(cf_filter) = cf_cache
            .get(detection_client, config.detection_timeout, ppfmt)
            .await
        {
            ips.retain(|key, ip_info| {
                if let Ok(addr) = ip_info.ip.parse::<IpAddr>() {
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

    let (msgs, should_notify, update_ok) = ddns
        .update_ips(
            &ips,
            &legacy.cloudflare,
            legacy.ttl,
            legacy.purge_unknown_records,
            noop_reported,
            config.record_comment.as_deref(),
        )
        .await;

    (ok && update_ok, msgs, should_notify)
}

/// Delete records on stop (for env var mode). Sends a notification and returns
/// the summary message so the caller can use it for the exit heartbeat.
pub async fn final_delete(
    config: &AppConfig,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
    ppfmt: &PP,
) -> Message {
    let mut messages = Vec::new();

    // Delete DNS records
    let groups = config.groups();
    for (ip_type, domains) in groups.iter().flat_map(|g| g.domains.iter()) {
        let record_type = ip_type.record_type();

        for domain_str in domains {
            let deleted = match handle.zone_id_of_domain(domain_str, ppfmt).await {
                Some(zone_id) => {
                    handle
                        .final_delete(&zone_id, domain_str, record_type, ppfmt)
                        .await
                }
                None => false,
            };
            messages.push(if deleted {
                Message::new_ok(&format!("Deleted {record_type} records for {domain_str}"))
            } else {
                Message::new_fail(&format!(
                    "Failed to delete {record_type} records for {domain_str}"
                ))
            });
        }
    }

    // Clear WAF lists
    for waf_list in &config.waf_lists {
        messages.push(if handle.final_clear_waf_list(waf_list, ppfmt).await {
            Message::new_ok(&format!("Cleared WAF list {}", waf_list.describe()))
        } else {
            Message::new_fail(&format!("Failed to clear WAF list {}", waf_list.describe()))
        });
    }

    let msg = Message::merge(messages);
    notifier.send(&msg).await;
    msg
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
                    match resp.json::<T>().await {
                        Ok(v) => Some(v),
                        Err(e) => {
                            eprintln!(
                                "Unexpected response to '{method}' request to '{endpoint}': {e}"
                            );
                            None
                        }
                    }
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

    /// Records of one type and name. `None` if the API call failed, so an error
    /// is never mistaken for "no record" (which would create duplicates).
    async fn list_records_by_name(
        &self,
        entry: &LegacyCloudflareEntry,
        record_type: &str,
        fqdn: &str,
    ) -> Option<Vec<LegacyDnsRecord>> {
        // Filter server-side (unfiltered listings are capped at one page) and
        // match case-insensitively: Cloudflare stores names lowercased.
        let endpoint = format!(
            "zones/{}/dns_records?per_page=100&type={record_type}&name={}",
            entry.zone_id,
            url::form_urlencoded::byte_serialize(fqdn.to_ascii_lowercase().as_bytes())
                .collect::<String>()
        );
        let resp: LegacyCfResponse<Vec<LegacyDnsRecord>> = self
            .cf_api(&endpoint, "GET", entry, None::<&()>.as_ref())
            .await?;
        Some(
            resp.result
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.name.eq_ignore_ascii_case(fqdn))
                .collect(),
        )
    }

    async fn zone_name(&self, entry: &LegacyCloudflareEntry) -> Option<String> {
        let resp: LegacyCfResponse<LegacyZoneResult> = self
            .cf_api(
                &format!("zones/{}", entry.zone_id),
                "GET",
                entry,
                None::<&()>.as_ref(),
            )
            .await?;
        resp.result.map(|z| z.name)
    }

    async fn delete_record(&self, entry: &LegacyCloudflareEntry, id: &str) -> bool {
        let endpoint = format!("zones/{}/dns_records/{id}", entry.zone_id);
        let resp: Option<serde_json::Value> = self
            .cf_api(&endpoint, "DELETE", entry, None::<&()>.as_ref())
            .await;
        resp.is_some()
    }

    /// Configured `(fqdn, proxied)` pairs for an entry in a zone named `base_domain`.
    fn subdomains(entry: &LegacyCloudflareEntry, base_domain: &str) -> Vec<(String, bool)> {
        entry
            .subdomains
            .iter()
            .map(|subdomain| {
                let (name, proxied) = match subdomain {
                    LegacySubdomainEntry::Detailed { name, proxied } => (name, *proxied),
                    LegacySubdomainEntry::Simple(name) => (name, entry.proxied),
                };
                (make_fqdn(name.to_lowercase().trim(), base_domain), proxied)
            })
            .collect()
    }

    /// Deletes this record type for the configured subdomains (used when a
    /// deterministic provider reports no address of the family). Only names
    /// listed in config.json are touched, never other records in the zone.
    /// Returns `false` if any lookup or deletion failed.
    async fn delete_entries(&self, record_type: &str, entries: &[LegacyCloudflareEntry]) -> bool {
        let mut ok = true;
        for entry in entries {
            let Some(base_domain) = self.zone_name(entry).await else {
                ok = false;
                continue;
            };
            for (fqdn, _) in Self::subdomains(entry, &base_domain) {
                // A few requests per name, each bounded by UPDATE_TIMEOUT:
                // well inside the health budget without adding the timeouts.
                health::mark_progress(Duration::ZERO);
                let Some(records) = self.list_records_by_name(entry, record_type, &fqdn).await
                else {
                    ok = false;
                    continue;
                };
                for record in records {
                    if self.dry_run {
                        println!("[DRY RUN] Would delete stale record {fqdn} ({})", record.id);
                        continue;
                    }
                    if self.delete_record(entry, &record.id).await {
                        println!("Deleted stale record {fqdn} ({})", record.id);
                    } else {
                        ok = false;
                    }
                }
            }
        }
        ok
    }

    /// Returns `(messages, changed, ok)`.
    async fn update_ips(
        &self,
        ips: &HashMap<String, LegacyIpInfo>,
        config: &[LegacyCloudflareEntry],
        ttl: i64,
        purge_unknown_records: bool,
        noop_reported: &mut HashSet<String>,
        comment: Option<&str>,
    ) -> (Vec<Message>, bool, bool) {
        let mut messages = Vec::new();
        let mut notify = false;
        let mut ok = true;
        for ip in ips.values() {
            let (msgs, changed, ip_ok) = self
                .commit_record(
                    ip,
                    config,
                    ttl,
                    purge_unknown_records,
                    noop_reported,
                    comment,
                )
                .await;
            messages.extend(msgs);
            notify |= changed;
            ok &= ip_ok;
        }
        (messages, notify, ok)
    }

    /// Returns `(messages, changed, ok)`.
    async fn commit_record(
        &self,
        ip: &LegacyIpInfo,
        config: &[LegacyCloudflareEntry],
        ttl: i64,
        purge_unknown_records: bool,
        noop_reported: &mut HashSet<String>,
        comment: Option<&str>,
    ) -> (Vec<Message>, bool, bool) {
        let mut messages = Vec::new();
        let mut changed = false;
        let mut ok = true;
        for entry in config {
            let Some(base_domain) = self.zone_name(entry).await else {
                messages.push(Message::new_fail(&format!(
                    "Could not look up zone {}",
                    entry.zone_id
                )));
                ok = false;
                continue;
            };

            for (fqdn, proxied) in Self::subdomains(entry, &base_domain) {
                health::mark_progress(Duration::ZERO);
                let record = LegacyDnsRecordPayload {
                    record_type: ip.record_type.clone(),
                    name: fqdn.clone(),
                    content: ip.ip.clone(),
                    proxied,
                    ttl,
                    comment: comment.map(|s| s.to_string()),
                };

                let Some(records) = self
                    .list_records_by_name(entry, &ip.record_type, &fqdn)
                    .await
                else {
                    messages.push(Message::new_fail(&format!(
                        "Could not list records for {fqdn}"
                    )));
                    ok = false;
                    continue;
                };

                // Keep the record already holding this IP if there is one;
                // otherwise update the first. The rest are duplicates.
                let keep = records
                    .iter()
                    .find(|r| r.content == ip.ip)
                    .or_else(|| records.first());
                let duplicate_ids: Vec<&str> = records
                    .iter()
                    .filter(|r| Some(r.id.as_str()) != keep.map(|k| k.id.as_str()))
                    .map(|r| r.id.as_str())
                    .collect();

                let noop_key = format!("{fqdn}:{}", ip.record_type);
                match keep {
                    Some(existing)
                        if existing.content == record.content
                            && existing.proxied == record.proxied
                            && existing.comment == record.comment =>
                    {
                        if noop_reported.insert(noop_key) {
                            if self.dry_run {
                                println!("[DRY RUN] Record {fqdn} is up to date");
                            } else {
                                println!("Record {fqdn} is up to date");
                            }
                        }
                    }
                    Some(existing) => {
                        noop_reported.remove(&noop_key);
                        changed = true;
                        if self.dry_run {
                            println!("[DRY RUN] Would update record {fqdn} -> {}", ip.ip);
                            messages.push(Message::new_ok(&format!("Updated {fqdn} -> {}", ip.ip)));
                        } else {
                            println!("Updating record {fqdn} -> {}", ip.ip);
                            let endpoint =
                                format!("zones/{}/dns_records/{}", entry.zone_id, existing.id);
                            let resp: Option<serde_json::Value> =
                                self.cf_api(&endpoint, "PUT", entry, Some(&record)).await;
                            if resp.is_some() {
                                messages
                                    .push(Message::new_ok(&format!("Updated {fqdn} -> {}", ip.ip)));
                            } else {
                                messages.push(Message::new_fail(&format!(
                                    "Failed to update {fqdn} -> {}",
                                    ip.ip
                                )));
                                ok = false;
                            }
                        }
                    }
                    None => {
                        noop_reported.remove(&noop_key);
                        changed = true;
                        if self.dry_run {
                            println!("[DRY RUN] Would add new record {fqdn} -> {}", ip.ip);
                            messages.push(Message::new_ok(&format!("Created {fqdn} -> {}", ip.ip)));
                        } else {
                            println!("Adding new record {fqdn} -> {}", ip.ip);
                            let endpoint = format!("zones/{}/dns_records", entry.zone_id);
                            let resp: Option<serde_json::Value> =
                                self.cf_api(&endpoint, "POST", entry, Some(&record)).await;
                            if resp.is_some() {
                                messages
                                    .push(Message::new_ok(&format!("Created {fqdn} -> {}", ip.ip)));
                            } else {
                                messages.push(Message::new_fail(&format!(
                                    "Failed to create {fqdn} -> {}",
                                    ip.ip
                                )));
                                ok = false;
                            }
                        }
                    }
                }

                if purge_unknown_records {
                    for dup_id in duplicate_ids {
                        if self.dry_run {
                            println!("[DRY RUN] Would delete stale record {dup_id}");
                        } else {
                            println!("Deleting stale record {dup_id}");
                            ok &= self.delete_record(entry, dup_id).await;
                        }
                    }
                }
            }
        }
        (messages, changed, ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::{Auth, CloudflareHandle, WAFList, TTL};
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
        let mut config = make_config_preserving(providers, domains, waf_lists, dry_run);
        config.delete_on_failure = true;
        config
    }

    /// Like make_config but with delete_on_failure disabled (the default since issue #277):
    /// detection failures skip updates instead of deleting records.
    fn make_config_preserving(
        providers: HashMap<IpType, ProviderType>,
        domains: HashMap<IpType, Vec<String>>,
        waf_lists: Vec<WAFList>,
        dry_run: bool,
    ) -> AppConfig {
        AppConfig {
            auth: Auth::Token("test-token".to_string()),
            providers,
            domains,
            extra_groups: Vec::new(),
            waf_lists,
            update_cron: CronSchedule::Once,
            update_on_start: true,
            delete_on_stop: false,
            delete_on_failure: false,
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
                ResponseTemplate::new(200).set_body_json(dns_record_created("rec-1", domain, ip)),
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
                ResponseTemplate::new(200).set_body_json(dns_records_one("rec-1", domain, ip)),
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut noop_reported,
            &crate::test_client(),
        )
        .await;
        assert!(ok);
        assert!(
            noop_reported.contains("home.example.com:A"),
            "noop_reported should contain the domain key after first noop"
        );

        // Second call: noop_reported already has the key, so the message is suppressed
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut noop_reported,
            &crate::test_client(),
        )
        .await;
        assert!(ok);
        assert_eq!(
            noop_reported.len(),
            1,
            "noop_reported should still have exactly one entry"
        );
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
                ResponseTemplate::new(200).set_body_json(dns_records_one("rec-1", domain, old_ip)),
            )
            .mount(&server)
            .await;

        // The existing managed record is reused and updated in place
        Mock::given(method("PUT"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-1")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(dns_record_created("rec-1", domain, new_ip)),
            )
            .expect(1)
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut noop_reported,
            &crate::test_client(),
        )
        .await;
        assert!(ok);
        assert!(
            !noop_reported.contains("home.example.com:A"),
            "noop_reported should be cleared after an update"
        );
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        // Providers with None are not inserted in loop, so no IP detection warning is emitted,
        // no detected_ips entry is created, and set_ips is called with empty slice -> Noop.
        assert!(ok);
    }

    /// Issue #277: a transient detection failure (provider errored, real IP
    /// unknown) must skip the DNS update entirely — no zone lookup, no record
    /// deletion — even with delete_on_failure enabled.
    #[tokio::test]
    async fn test_update_once_detection_failure_skips_dns_update() {
        let server = MockServer::start().await;
        let domain = "home.example.com";

        // IP detection endpoint errors -> DetectionOutcome::Failed.
        Mock::given(method("GET"))
            .and(path("/detect-ip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        // Zone lookup must NOT happen when detection fails and updates are skipped.
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response("zone-abc", "example.com")),
            )
            .expect(0)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::CustomURL {
                url: format!("{}/detect-ip", server.uri()),
            },
        );
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        // delete_on_failure is true here: transient failures must still preserve records.
        let config = make_config(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "skip on detection failure should not be an error");
    }

    /// A definitive "no address of this family" (e.g., provider `none`) with
    /// delete_on_failure enabled deletes the managed records (documented behavior).
    #[tokio::test]
    async fn test_update_once_no_ip_deletes_records_with_delete_on_failure() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let record_id = "rec-stale";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_one(
                record_id,
                domain,
                "198.51.100.42",
            )))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/{record_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(providers, domains, vec![], false); // delete_on_failure: true
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// A definitive "no address of this family" with delete_on_failure disabled
    /// skips the update and preserves existing records.
    #[tokio::test]
    async fn test_update_once_no_ip_skips_when_delete_on_failure_disabled() {
        let server = MockServer::start().await;
        let domain = "home.example.com";

        // Zone lookup must NOT happen when the update is skipped.
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response("zone-abc", "example.com")),
            )
            .expect(0)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config_preserving(providers, domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "skip on missing IP should not be an error");
    }

    /// Issue #277: a transient detection failure must not touch WAF lists —
    /// otherwise a network blip clears the list.
    #[tokio::test]
    async fn test_update_once_detection_failure_skips_waf_update() {
        let server = MockServer::start().await;
        let account_id = "acc-123";

        // IP detection endpoint errors -> DetectionOutcome::Failed.
        Mock::given(method("GET"))
            .and(path("/detect-ip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        // WAF list lookup must NOT happen.
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response("list-id-1", "my_list")),
            )
            .expect(0)
            .mount(&server)
            .await;

        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::CustomURL {
                url: format!("{}/detect-ip", server.uri()),
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: "my_list".to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(
            ok,
            "skipping WAF update on detection failure should not be an error"
        );
    }

    /// Issue #277: if only one address family fails detection transiently, the
    /// WAF update is still skipped — a partial update would strip the failed
    /// family's IPs from the shared list.
    #[tokio::test]
    async fn test_update_once_partial_detection_failure_skips_waf_update() {
        let server = MockServer::start().await;
        let account_id = "acc-123";
        let ip_v4 = "198.51.100.42";

        // V6 detection endpoint errors -> DetectionOutcome::Failed.
        Mock::given(method("GET"))
            .and(path("/detect-ip"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account_id}/rules/lists")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(waf_lists_response("list-id-1", "my_list")),
            )
            .expect(0)
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
            ProviderType::CustomURL {
                url: format!("{}/detect-ip", server.uri()),
            },
        );
        let waf_list = WAFList {
            account_id: account_id.to_string(),
            list_name: "my_list".to_string(),
        };

        let config = make_config(providers, HashMap::new(), vec![waf_list], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
            .respond_with(ResponseTemplate::new(200).set_body_json(zones_empty_response()))
            .mount(&server)
            .await;

        // Zone lookup for parent domain also fails
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(zones_empty_response()))
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// update_once with WAF lists: IPs are detected and the WAF list is updated.
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
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET list items - empty (need to add the IP)
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([]))),
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([]))),
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

        let config = make_config(
            providers,
            HashMap::new(),
            vec![waf_list],
            true, /* dry_run */
        );
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
                ResponseTemplate::new(200).set_body_json(dns_records_one(record_id, domain, ip)),
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
        let ppfmt = pp();

        // Should complete without panic
        final_delete(&config, &cf, &notifier, &ppfmt).await;
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
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
    }

    /// final_delete skips DNS deletion when the zone is not found.
    #[tokio::test]
    async fn test_final_delete_skips_when_zone_not_found() {
        let server = MockServer::start().await;
        let domain = "missing.example.com";

        // Zone lookup - not found at either level
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(ResponseTemplate::new(200).set_body_json(zones_empty_response()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(zones_empty_response()))
            .mount(&server)
            .await;

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec![domain.to_string()]);

        let config = make_config(HashMap::new(), domains, vec![], false);
        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let ppfmt = pp();

        // Should complete without error - zone not found means skip
        final_delete(&config, &cf, &notifier, &ppfmt).await;
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
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET items - one item exists
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(waf_items_response(
                serde_json::json!([
                    { "id": item_id, "ip": ip, "comment": null }
                ]),
            )))
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
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
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
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // GET items - empty
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(waf_items_response(serde_json::json!([]))),
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
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
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
                ResponseTemplate::new(200).set_body_json(dns_records_one(record_id, domain, ip)),
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
                ResponseTemplate::new(200).set_body_json(waf_lists_response(list_id, list_name)),
            )
            .mount(&server)
            .await;

        // WAF: GET items
        Mock::given(method("GET"))
            .and(path(format!(
                "/accounts/{account_id}/rules/lists/{list_id}/items"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(waf_items_response(
                serde_json::json!([
                    { "id": item_id, "ip": ip, "comment": null }
                ]),
            )))
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
        let ppfmt = pp();

        final_delete(&config, &cf, &notifier, &ppfmt).await;
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
        // Only a V4 literal provider is configured, but domain is V6
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
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
            client: crate::test_client(),
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
            client: crate::test_client(),
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
            client: crate::test_client(),
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
            client: crate::test_client(),
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
            client: crate::test_client(),
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
            client: crate::test_client(),
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
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new(), None)
            .await;
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
            client: crate::test_client(),
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
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new(), None)
            .await;
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
            client: crate::test_client(),
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
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new(), None)
            .await;
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
            client: crate::test_client(),
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
        ddns.commit_record(&ip, &config, 300, false, &mut HashSet::new(), None)
            .await;
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

        // The first record holding the IP is kept; the duplicate is purged.
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-dup")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: crate::test_client(),
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
        ddns.commit_record(&ip, &config, 300, true, &mut HashSet::new(), None)
            .await;
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
            client: crate::test_client(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let mut ips = HashMap::new();
        ips.insert(
            "ipv4".to_string(),
            LegacyIpInfo {
                record_type: "A".to_string(),
                ip: "198.51.100.1".to_string(),
            },
        );
        let config = vec![crate::config::LegacyCloudflareEntry {
            authentication: crate::config::LegacyAuthentication {
                api_token: "test-token".to_string(),
                api_key: None,
            },
            zone_id: zone_id.to_string(),
            subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
            proxied: false,
        }];
        ddns.update_ips(&ips, &config, 300, false, &mut HashSet::new(), None)
            .await;
    }

    #[tokio::test]
    async fn test_legacy_delete_entries() {
        // Only configured names are purged; other records in the zone survive.
        let server = MockServer::start().await;
        let zone_id = "zone-leg7";

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
                    { "id": "rec-1", "name": "example.com", "content": "10.0.0.1", "proxied": false },
                    { "id": "rec-other", "name": "mail.example.com", "content": "10.0.0.9", "proxied": false }
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
        Mock::given(method("DELETE"))
            .and(path(format!("/zones/{zone_id}/dns_records/rec-other")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(0)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: crate::test_client(),
            cf_api_base: server.uri(),
            dry_run: false,
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
        assert!(ddns.delete_entries("A", &config).await);
    }

    #[tokio::test]
    async fn test_legacy_commit_record_write_failure_is_reported() {
        let server = MockServer::start().await;
        let zone_id = "zone-leg-fail";
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
                    { "id": "rec-1", "name": "Example.com", "content": "10.0.0.1", "proxied": false }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let ddns = LegacyDdnsClient {
            client: crate::test_client(),
            cf_api_base: server.uri(),
            dry_run: false,
        };
        let ip = LegacyIpInfo {
            record_type: "A".to_string(),
            ip: "10.0.0.2".to_string(),
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
        let (msgs, _, ok) = ddns
            .commit_record(&ip, &config, 300, false, &mut HashSet::new(), None)
            .await;
        assert!(!ok);
        assert!(msgs.iter().any(|m| !m.ok));
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
            client: crate::test_client(),
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

    // -------------------------------------------------------
    // delete_on_failure tests
    // -------------------------------------------------------

    /// When IPv4 detection fails but IPv6 succeeds, and delete_on_failure=false, skip V4 domains but update V6
    #[tokio::test]
    async fn test_skip_v4_domains_when_v4_detection_fails() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let ip_v6 = "2001:db8::1";

        // Zone lookup for V6 domain
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "v6.example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // LIST existing records for V6
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST for V6 should be called (V6 succeeds)
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_record_created(
                "rec-1",
                "v6.example.com",
                "2001:db8::1",
            )))
            .expect(1)
            .mount(&server)
            .await;

        // Providers: V4 fails (None), V6 succeeds
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        providers.insert(
            IpType::V6,
            ProviderType::Literal {
                ips: vec![ip_v6.parse().unwrap()],
            },
        );

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with partial detection");
    }

    /// When IPv6 detection fails but IPv4 succeeds, and delete_on_failure=false, skip V6 domains but update V4
    #[tokio::test]
    async fn test_skip_v6_domains_when_v6_detection_fails() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let ip_v4 = "198.51.100.42";

        // Zone lookup for V4 domain
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "v4.example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // LIST existing records for V4
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST for V4 should be called (V4 succeeds)
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_record_created(
                "rec-1",
                "v4.example.com",
                "198.51.100.42",
            )))
            .expect(1)
            .mount(&server)
            .await;

        // Providers: V4 succeeds, V6 fails (None)
        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse().unwrap()],
            },
        );
        providers.insert(IpType::V6, ProviderType::None);

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with partial detection");
    }

    /// When both IPv4 and IPv6 detection fail, and delete_on_failure=false, skip all domains
    #[tokio::test]
    async fn test_skip_all_domains_when_both_detect_fail() {
        let server = MockServer::start().await;

        // No POST/DELETE should be called at all

        // Providers: both fail (None)
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::None);
        providers.insert(IpType::V6, ProviderType::None);

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed (no updates, no failures)");
    }

    /// When both IPv4 and IPv6 detection succeed, and delete_on_failure=false, update all domains
    #[tokio::test]
    async fn test_update_all_domains_when_both_detect() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let ip_v4 = "198.51.100.42";
        let ip_v6 = "2001:db8::1";

        // Zone lookups for both domains
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // LIST existing records (empty for both)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // POST for both should be called
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_record_created(
                "rec-new",
                "example.com",
                "198.51.100.42",
            )))
            .expect(2) // Two POSTs: one for V4, one for V6
            .mount(&server)
            .await;

        // Providers: both succeed
        let mut providers = HashMap::new();
        providers.insert(
            IpType::V4,
            ProviderType::Literal {
                ips: vec![ip_v4.parse().unwrap()],
            },
        );
        providers.insert(
            IpType::V6,
            ProviderType::Literal {
                ips: vec![ip_v6.parse().unwrap()],
            },
        );

        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        domains.insert(IpType::V6, vec!["v6.example.com".to_string()]);

        let mut config = make_config(providers, domains, vec![], false);
        config.delete_on_failure = false;

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with both detections");
    }

    /// update_once passes record_comment to the API when creating a new record.
    #[tokio::test]
    async fn test_update_once_with_record_comment() {
        let server = MockServer::start().await;
        let zone_id = "zone-abc";
        let domain = "home.example.com";
        let ip = "198.51.100.42";
        let comment = "managed by cf-ddns";

        // Zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", domain))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response(zone_id, "example.com")),
            )
            .mount(&server)
            .await;

        // List existing records (empty)
        Mock::given(method("GET"))
            .and(path_regex(format!("/zones/{zone_id}/dns_records")))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;

        // Create record: POST should receive the comment in the body
        Mock::given(method("POST"))
            .and(path(format!("/zones/{zone_id}/dns_records")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(dns_record_created("rec-1", domain, ip)),
            )
            .expect(1)
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

        let mut config = make_config(providers, domains, vec![], false);
        config.record_comment = Some(comment.to_string());

        let cf = handle(&server.uri());
        let notifier = empty_notifier();
        let heartbeat = empty_heartbeat();
        let ppfmt = pp();

        let mut cf_cache = CachedCloudflareFilter::new();
        let ok = update_once(
            &config,
            &cf,
            &notifier,
            &heartbeat,
            &mut cf_cache,
            &ppfmt,
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok, "Should succeed with record_comment set");
    }

    // ---- Detection groups (issue #248) ----

    /// Two groups with different providers write their own address to their
    /// own domain; the WAF list receives both.
    #[tokio::test]
    async fn test_detection_groups_update_independently() {
        use wiremock::matchers::body_partial_json;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(zones_response("z1", "example.com")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_empty()))
            .mount(&server)
            .await;
        for (name, ip) in [
            ("a.example.com", "198.51.100.1"),
            ("b.example.com", "203.0.113.2"),
        ] {
            Mock::given(method("POST"))
                .and(path("/zones/z1/dns_records"))
                .and(body_partial_json(
                    serde_json::json!({ "name": name, "content": ip }),
                ))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(dns_record_created("r", name, ip)),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let literal = |ip: &str| ProviderType::Literal {
            ips: vec![ip.parse().unwrap()],
        };
        let mut config = make_config(
            HashMap::from([(IpType::V4, literal("198.51.100.1"))]),
            HashMap::from([(IpType::V4, vec!["a.example.com".to_string()])]),
            vec![],
            false,
        );
        config.extra_groups = vec![crate::config::DetectionGroup {
            label: "2".to_string(),
            providers: HashMap::from([(IpType::V4, literal("203.0.113.2"))]),
            domains: HashMap::from([(IpType::V4, vec!["b.example.com".to_string()])]),
        }];

        let ok = update_once(
            &config,
            &handle(&server.uri()),
            &empty_notifier(),
            &empty_heartbeat(),
            &mut CachedCloudflareFilter::new(),
            &pp(),
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
        assert!(ok);
    }

    /// Groups sharing a provider detect once per cycle.
    #[tokio::test]
    async fn test_detection_groups_share_identical_detection() {
        let ip_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("198.51.100.7"))
            .expect(1)
            .mount(&ip_server)
            .await;
        let provider = ProviderType::CustomURL {
            url: ip_server.uri(),
        };
        // No domains: only detection runs.
        let mut config = make_config(
            HashMap::from([(IpType::V4, provider.clone())]),
            HashMap::new(),
            vec![],
            false,
        );
        config.reject_cloudflare_ips = false;
        config.extra_groups = vec![crate::config::DetectionGroup {
            label: "2".to_string(),
            providers: HashMap::from([(IpType::V4, provider)]),
            domains: HashMap::new(),
        }];
        update_once(
            &config,
            &handle("http://127.0.0.1:9"),
            &empty_notifier(),
            &empty_heartbeat(),
            &mut CachedCloudflareFilter::new(),
            &pp(),
            &mut HashSet::new(),
            &crate::test_client(),
        )
        .await;
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
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct LegacyDnsRecordPayload {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    proxied: bool,
    ttl: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}
