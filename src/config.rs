use crate::cloudflare::{Auth, TTL, WAFList};
use crate::domain;
use crate::notifier::{
    CompositeNotifier, Heartbeat, HeartbeatMonitor, HealthchecksMonitor, NotifierDyn,
    ShoutrrrNotifier, UptimeKumaMonitor,
};
use crate::pp::{self, PP};
use crate::provider::{IpType, ProviderType};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================
// Legacy JSON Config (backwards compatible with cloudflare-ddns)
// ============================================================

#[derive(Debug, Deserialize, Clone)]
pub struct LegacyConfig {
    pub cloudflare: Vec<LegacyCloudflareEntry>,
    #[serde(default = "default_true")]
    pub a: bool,
    #[serde(default = "default_true")]
    pub aaaa: bool,
    #[serde(rename = "purgeUnknownRecords", default)]
    pub purge_unknown_records: bool,
    #[serde(default = "default_ttl")]
    pub ttl: i64,
    #[serde(default)]
    pub ip4_provider: Option<String>,
    #[serde(default)]
    pub ip6_provider: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_ttl() -> i64 {
    300
}

#[derive(Debug, Deserialize, Clone)]
pub struct LegacyCloudflareEntry {
    pub authentication: LegacyAuthentication,
    pub zone_id: String,
    pub subdomains: Vec<LegacySubdomainEntry>,
    #[serde(default)]
    pub proxied: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum LegacySubdomainEntry {
    Detailed { name: String, proxied: bool },
    Simple(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct LegacyAuthentication {
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub api_key: Option<LegacyApiKey>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LegacyApiKey {
    pub api_key: String,
    pub account_email: String,
}

// ============================================================
// Unified Config (supports both legacy JSON and env var modes)
// ============================================================

/// The complete application configuration
pub struct AppConfig {
    pub auth: Auth,
    pub providers: HashMap<IpType, ProviderType>,
    pub domains: HashMap<IpType, Vec<String>>, // FQDN domains by IP type
    pub waf_lists: Vec<WAFList>,
    pub update_cron: CronSchedule,
    pub update_on_start: bool,
    pub delete_on_stop: bool,
    pub ttl: TTL,
    pub proxied_expression: Option<Box<dyn Fn(&str) -> bool + Send + Sync>>,
    pub record_comment: Option<String>,
    pub managed_comment_regex: Option<regex::Regex>,
    pub waf_list_description: Option<String>,
    pub waf_list_item_comment: Option<String>,
    pub managed_waf_comment_regex: Option<regex::Regex>,
    pub detection_timeout: Duration,
    pub update_timeout: Duration,
    pub reject_cloudflare_ips: bool,
    pub dry_run: bool,
    pub emoji: bool,
    pub quiet: bool,
    // Legacy mode fields
    pub legacy_mode: bool,
    pub legacy_config: Option<LegacyConfig>,
    pub repeat: bool,
}

/// Cron schedule
#[derive(Debug, Clone)]
pub enum CronSchedule {
    Every(Duration),
    Once,
}

impl CronSchedule {
    pub fn describe(&self) -> String {
        match self {
            CronSchedule::Every(d) => format!("@every {}s", d.as_secs()),
            CronSchedule::Once => "@once".to_string(),
        }
    }

    pub fn next_duration(&self) -> Option<Duration> {
        match self {
            CronSchedule::Every(d) => Some(*d),
            CronSchedule::Once => None,
        }
    }
}

fn parse_duration_string(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(minutes) = s.strip_suffix('m') {
        minutes.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60))
    } else if let Some(hours) = s.strip_suffix('h') {
        hours.parse::<u64>().ok().map(|h| Duration::from_secs(h * 3600))
    } else if let Some(secs) = s.strip_suffix('s') {
        secs.parse::<u64>().ok().map(Duration::from_secs)
    } else {
        // Try as seconds
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

// ============================================================
// Environment Variable Configuration (cf-ddns mode)
// ============================================================

fn getenv(key: &str) -> Option<String> {
    env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn getenv_bool(key: &str, default: bool) -> bool {
    match getenv(key) {
        Some(v) => matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"),
        None => default,
    }
}

fn getenv_duration(key: &str, default: Duration) -> Duration {
    match getenv(key) {
        Some(v) => parse_duration_string(&v).unwrap_or(default),
        None => default,
    }
}

fn getenv_list(key: &str, sep: char) -> Vec<String> {
    match getenv(key) {
        Some(v) => v
            .split(sep)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => Vec::new(),
    }
}

fn read_auth_from_env(ppfmt: &PP) -> Option<Auth> {
    // Try CLOUDFLARE_API_TOKEN first, then CF_API_TOKEN (deprecated)
    if let Some(token) = getenv("CLOUDFLARE_API_TOKEN").or_else(|| {
        let val = getenv("CF_API_TOKEN");
        if val.is_some() {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                "CF_API_TOKEN is deprecated; use CLOUDFLARE_API_TOKEN instead",
            );
        }
        val
    }) {
        if token == "YOUR-CLOUDFLARE-API-TOKEN" {
            ppfmt.errorf(pp::EMOJI_ERROR, "Please set CLOUDFLARE_API_TOKEN to your actual API token");
            return None;
        }
        return Some(Auth::Token(token));
    }

    // Try reading from file
    if let Some(path) = getenv("CLOUDFLARE_API_TOKEN_FILE").or_else(|| {
        let val = getenv("CF_API_TOKEN_FILE");
        if val.is_some() {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                "CF_API_TOKEN_FILE is deprecated; use CLOUDFLARE_API_TOKEN_FILE instead",
            );
        }
        val
    }) {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let token = content.trim().to_string();
                if !token.is_empty() {
                    return Some(Auth::Token(token));
                }
            }
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("Failed to read API token file '{path}': {e}"));
            }
        }
    }

    // Deprecated: CF_ACCOUNT_ID
    if getenv("CF_ACCOUNT_ID").is_some() {
        ppfmt.warningf(
            pp::EMOJI_WARNING,
            "CF_ACCOUNT_ID is deprecated and ignored since v1.14.0",
        );
    }

    None
}

fn read_providers_from_env(ppfmt: &PP) -> Result<HashMap<IpType, ProviderType>, String> {
    let mut providers = HashMap::new();

    let ip4_str = getenv("IP4_PROVIDER").or_else(|| {
        let val = getenv("IP4_POLICY");
        if val.is_some() {
            ppfmt.warningf(pp::EMOJI_WARNING, "IP4_POLICY is deprecated; use IP4_PROVIDER instead");
        }
        val
    });
    let ip6_str = getenv("IP6_PROVIDER").or_else(|| {
        let val = getenv("IP6_POLICY");
        if val.is_some() {
            ppfmt.warningf(pp::EMOJI_WARNING, "IP6_POLICY is deprecated; use IP6_PROVIDER instead");
        }
        val
    });

    let ip4_provider = match ip4_str {
        Some(s) => ProviderType::parse(&s)
            .map_err(|e| format!("Invalid IP4_PROVIDER: {e}"))?,
        None => ProviderType::CloudflareTrace { url: None },
    };

    let ip6_provider = match ip6_str {
        Some(s) => ProviderType::parse(&s)
            .map_err(|e| format!("Invalid IP6_PROVIDER: {e}"))?,
        None => ProviderType::CloudflareTrace { url: None },
    };

    if !matches!(ip4_provider, ProviderType::None) {
        providers.insert(IpType::V4, ip4_provider);
    }
    if !matches!(ip6_provider, ProviderType::None) {
        providers.insert(IpType::V6, ip6_provider);
    }

    Ok(providers)
}

fn read_domains_from_env(_ppfmt: &PP) -> HashMap<IpType, Vec<String>> {
    let mut domains: HashMap<IpType, Vec<String>> = HashMap::new();

    let both = getenv_list("DOMAINS", ',');
    let ip4_only = getenv_list("IP4_DOMAINS", ',');
    let ip6_only = getenv_list("IP6_DOMAINS", ',');

    let mut v4_domains: Vec<String> = both.clone();
    v4_domains.extend(ip4_only);
    if !v4_domains.is_empty() {
        domains.insert(IpType::V4, v4_domains);
    }

    let mut v6_domains: Vec<String> = both;
    v6_domains.extend(ip6_only);
    if !v6_domains.is_empty() {
        domains.insert(IpType::V6, v6_domains);
    }

    domains
}

fn read_waf_lists_from_env(ppfmt: &PP) -> Vec<WAFList> {
    let list_strs = getenv_list("WAF_LISTS", ',');
    let mut lists = Vec::new();
    for s in list_strs {
        match WAFList::parse(&s) {
            Ok(list) => lists.push(list),
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("Invalid WAF_LISTS entry: {e}"));
            }
        }
    }
    lists
}

fn read_cron_from_env(ppfmt: &PP) -> Result<CronSchedule, String> {
    match getenv("UPDATE_CRON") {
        Some(s) => {
            let s = s.trim();
            if s == "@once" {
                Ok(CronSchedule::Once)
            } else if s == "@disabled" || s == "@nevermore" {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!("UPDATE_CRON={s} is deprecated; use @once instead"),
                );
                Ok(CronSchedule::Once)
            } else if let Some(rest) = s.strip_prefix("@every ") {
                match parse_duration_string(rest) {
                    Some(d) => Ok(CronSchedule::Every(d)),
                    None => Err(format!("Invalid duration in UPDATE_CRON: {s}")),
                }
            } else {
                Err(format!(
                    "Unsupported UPDATE_CRON format: {s}. Use @every <duration>, @once, or omit for default (5m)."
                ))
            }
        }
        None => Ok(CronSchedule::Every(Duration::from_secs(300))),
    }
}

fn read_regex(key: &str, ppfmt: &PP) -> Option<regex::Regex> {
    match getenv(key) {
        Some(s) if !s.is_empty() => match regex::Regex::new(&s) {
            Ok(r) => Some(r),
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("Invalid regex in {key}: {e}"));
                None
            }
        },
        _ => None,
    }
}

// ============================================================
// JSON Config File with Env Var Substitution (legacy mode)
// ============================================================

fn substitute_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    for (key, value) in env::vars() {
        if key.starts_with("CF_DDNS_") {
            result = result.replace(&format!("${key}"), value.as_str());
            result = result.replace(&format!("${{{key}}}"), value.as_str());
        }
    }
    result
}

pub fn load_legacy_config() -> Result<LegacyConfig, String> {
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| ".".to_string());
    let path = PathBuf::from(&config_path).join("config.json");

    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("Error reading config.json: {e}"))?;

    let content = substitute_env_vars(&content);

    let mut config: LegacyConfig =
        serde_json::from_str(&content).map_err(|e| format!("Error parsing config.json: {e}"))?;

    if config.ttl < 30 {
        println!("TTL is too low - defaulting to 1 (auto)");
        config.ttl = 1;
    }

    Ok(config)
}

#[cfg(test)]
pub fn parse_legacy_config(content: &str) -> Result<LegacyConfig, String> {
    let mut config: LegacyConfig =
        serde_json::from_str(content).map_err(|e| format!("Error parsing config: {e}"))?;

    if config.ttl < 30 {
        config.ttl = 1;
    }

    Ok(config)
}

/// Convert a legacy config into a unified AppConfig
fn legacy_to_app_config(legacy: LegacyConfig, dry_run: bool, repeat: bool) -> Result<AppConfig, String> {
    // Extract auth from first entry
    let auth = if let Some(entry) = legacy.cloudflare.first() {
        if !entry.authentication.api_token.is_empty()
            && entry.authentication.api_token != "api_token_here"
        {
            Auth::Token(entry.authentication.api_token.clone())
        } else if let Some(api_key) = &entry.authentication.api_key {
            Auth::Key {
                api_key: api_key.api_key.clone(),
                email: api_key.account_email.clone(),
            }
        } else {
            Auth::Token(String::new())
        }
    } else {
        Auth::Token(String::new())
    };

    // Build providers — ip4_provider/ip6_provider override the default cloudflare.trace
    let mut providers = HashMap::new();
    if legacy.a {
        let provider = match &legacy.ip4_provider {
            Some(s) => ProviderType::parse(s)
                .map_err(|e| format!("Invalid ip4_provider in config.json: {e}"))?,
            None => ProviderType::CloudflareTrace { url: None },
        };
        if !matches!(provider, ProviderType::None) {
            providers.insert(IpType::V4, provider);
        }
    }
    if legacy.aaaa {
        let provider = match &legacy.ip6_provider {
            Some(s) => ProviderType::parse(s)
                .map_err(|e| format!("Invalid ip6_provider in config.json: {e}"))?,
            None => ProviderType::CloudflareTrace { url: None },
        };
        if !matches!(provider, ProviderType::None) {
            providers.insert(IpType::V6, provider);
        }
    }

    let ttl = TTL::new(legacy.ttl);
    let schedule = if repeat {
        // Use TTL as interval in legacy mode
        CronSchedule::Every(Duration::from_secs(legacy.ttl.max(1) as u64))
    } else {
        CronSchedule::Once
    };

    Ok(AppConfig {
        auth,
        providers,
        domains: HashMap::new(),
        waf_lists: Vec::new(),
        update_cron: schedule,
        update_on_start: true,
        delete_on_stop: false,
        ttl,
        proxied_expression: None,
        record_comment: None,
        managed_comment_regex: None,
        waf_list_description: None,
        waf_list_item_comment: None,
        managed_waf_comment_regex: None,
        detection_timeout: Duration::from_secs(5),
        update_timeout: Duration::from_secs(30),
        reject_cloudflare_ips: getenv_bool("REJECT_CLOUDFLARE_IPS", true),
        dry_run,
        emoji: false,
        quiet: false,
        legacy_mode: true,
        legacy_config: Some(legacy),
        repeat,
    })
}

// ============================================================
// Detect config mode and load
// ============================================================

/// Determine whether to use env var config (cf-ddns mode) or legacy JSON config.
pub fn is_env_config_mode() -> bool {
    // If any cf-ddns env vars are set, use env mode
    getenv("CLOUDFLARE_API_TOKEN").is_some()
        || getenv("CF_API_TOKEN").is_some()
        || getenv("CLOUDFLARE_API_TOKEN_FILE").is_some()
        || getenv("CF_API_TOKEN_FILE").is_some()
        || getenv("DOMAINS").is_some()
        || getenv("IP4_DOMAINS").is_some()
        || getenv("IP6_DOMAINS").is_some()
}

/// Load configuration from environment variables (cf-ddns mode).
pub fn load_env_config(ppfmt: &PP) -> Result<AppConfig, String> {
    // Deprecated warnings
    if getenv("PUID").is_some() {
        ppfmt.warningf(pp::EMOJI_WARNING, "PUID is deprecated since v1.13.0 and ignored. Use Docker's built-in mechanism instead.");
    }
    if getenv("PGID").is_some() {
        ppfmt.warningf(pp::EMOJI_WARNING, "PGID is deprecated since v1.13.0 and ignored. Use Docker's built-in mechanism instead.");
    }

    let auth = read_auth_from_env(ppfmt)
        .ok_or_else(|| "No authentication configured. Set CLOUDFLARE_API_TOKEN.".to_string())?;

    let providers = read_providers_from_env(ppfmt)?;
    let domains = read_domains_from_env(ppfmt);
    let waf_lists = read_waf_lists_from_env(ppfmt);
    let update_cron = read_cron_from_env(ppfmt)?;
    let update_on_start = getenv_bool("UPDATE_ON_START", true);
    let delete_on_stop = getenv_bool("DELETE_ON_STOP", false);

    let ttl_val = getenv("TTL")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(1);
    let ttl = TTL::new(ttl_val);

    let proxied_expr_str = getenv("PROXIED").unwrap_or_else(|| "false".to_string());
    let proxied_expression = match domain::parse_proxied_expression(&proxied_expr_str) {
        Ok(pred) => Some(pred),
        Err(e) => {
            ppfmt.errorf(pp::EMOJI_ERROR, &format!("Invalid PROXIED expression: {e}"));
            None
        }
    };

    let record_comment = getenv("RECORD_COMMENT");
    let managed_comment_regex = read_regex("MANAGED_RECORDS_COMMENT_REGEX", ppfmt);
    let waf_list_description = getenv("WAF_LIST_DESCRIPTION");
    let waf_list_item_comment = getenv("WAF_LIST_ITEM_COMMENT");
    let managed_waf_comment_regex = read_regex("MANAGED_WAF_LIST_ITEMS_COMMENT_REGEX", ppfmt);

    let detection_timeout = getenv_duration("DETECTION_TIMEOUT", Duration::from_secs(5));
    let update_timeout = getenv_duration("UPDATE_TIMEOUT", Duration::from_secs(30));

    let emoji = getenv_bool("EMOJI", true);
    let quiet = getenv_bool("QUIET", false);
    let reject_cloudflare_ips = getenv_bool("REJECT_CLOUDFLARE_IPS", true);

    // Validate: must have at least one update target
    if domains.is_empty() && waf_lists.is_empty() {
        return Err(
            "No update targets configured. Set DOMAINS, IP4_DOMAINS, IP6_DOMAINS, or WAF_LISTS."
                .to_string(),
        );
    }

    // Validate: @once constraints
    if matches!(update_cron, CronSchedule::Once) {
        if !update_on_start {
            return Err("UPDATE_ON_START must be true when UPDATE_CRON=@once".to_string());
        }
        if delete_on_stop {
            return Err("DELETE_ON_STOP must be false when UPDATE_CRON=@once".to_string());
        }
    }

    // Validate comment/regex compatibility
    if let (Some(ref comment), Some(ref regex)) = (&record_comment, &managed_comment_regex) {
        if !regex.is_match(comment) {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!(
                    "RECORD_COMMENT '{}' does not match MANAGED_RECORDS_COMMENT_REGEX '{}'",
                    comment,
                    regex.as_str()
                ),
            );
        }
    }

    Ok(AppConfig {
        auth,
        providers,
        domains,
        waf_lists,
        update_cron,
        update_on_start,
        delete_on_stop,
        ttl,
        proxied_expression,
        record_comment,
        managed_comment_regex,
        waf_list_description,
        waf_list_item_comment,
        managed_waf_comment_regex,
        detection_timeout,
        update_timeout,
        reject_cloudflare_ips,
        dry_run: false, // Set later from CLI args
        emoji,
        quiet,
        legacy_mode: false,
        legacy_config: None,
        repeat: false, // Set later
    })
}

/// Load config (auto-detect mode).
pub fn load_config(dry_run: bool, repeat: bool, ppfmt: &PP) -> Result<AppConfig, String> {
    if is_env_config_mode() {
        ppfmt.infof(pp::EMOJI_CONFIG, "Using environment variable configuration");
        let mut config = load_env_config(ppfmt)?;
        config.dry_run = dry_run;
        config.repeat = !matches!(config.update_cron, CronSchedule::Once);
        Ok(config)
    } else {
        ppfmt.infof(pp::EMOJI_CONFIG, "Using config.json configuration");
        let legacy = load_legacy_config()?;
        legacy_to_app_config(legacy, dry_run, repeat)
    }
}

// ============================================================
// Setup reporters (notifiers + heartbeats)
// ============================================================

pub fn setup_notifiers(ppfmt: &PP) -> CompositeNotifier {
    let mut notifiers: Vec<Box<dyn NotifierDyn>> = Vec::new();

    let shoutrrr_urls = getenv_list("SHOUTRRR", '\n');
    if !shoutrrr_urls.is_empty() {
        match ShoutrrrNotifier::new(&shoutrrr_urls) {
            Ok(n) => {
                ppfmt.infof(pp::EMOJI_NOTIFY, &format!("Notifications: {}", n.describe()));
                notifiers.push(Box::new(n));
            }
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("Failed to setup notifications: {e}"));
            }
        }
    }

    CompositeNotifier::new(notifiers)
}

pub fn setup_heartbeats(ppfmt: &PP) -> Heartbeat {
    let mut monitors: Vec<Box<dyn HeartbeatMonitor>> = Vec::new();

    if let Some(url) = getenv("HEALTHCHECKS") {
        ppfmt.infof(pp::EMOJI_HEARTBEAT, "Heartbeat: Healthchecks.io");
        monitors.push(Box::new(HealthchecksMonitor::new(&url)));
    }

    if let Some(url) = getenv("UPTIMEKUMA") {
        ppfmt.infof(pp::EMOJI_HEARTBEAT, "Heartbeat: Uptime Kuma");
        monitors.push(Box::new(UptimeKumaMonitor::new(&url)));
    }

    Heartbeat::new(monitors)
}

// ============================================================
// Print config summary
// ============================================================

pub fn print_config_summary(config: &AppConfig, ppfmt: &PP) {
    if config.legacy_mode {
        // Legacy mode output (backwards compatible)
        return;
    }

    let inner = ppfmt.indent();

    if !config.domains.is_empty() {
        ppfmt.noticef(pp::EMOJI_CONFIG, "Domains to update:");
        for (ip_type, domains) in &config.domains {
            inner.noticef("", &format!("{}: {}", ip_type.describe(), domains.join(", ")));
        }
    }

    if !config.waf_lists.is_empty() {
        ppfmt.noticef(pp::EMOJI_CONFIG, "WAF lists:");
        for waf in &config.waf_lists {
            inner.noticef("", &waf.describe());
        }
    }

    for (ip_type, provider) in &config.providers {
        inner.infof("", &format!("{} provider: {}", ip_type.describe(), provider.name()));
    }

    inner.infof("", &format!("TTL: {}", config.ttl.describe()));
    inner.infof("", &format!("Schedule: {}", config.update_cron.describe()));

    if config.delete_on_stop {
        inner.infof("", "Delete on stop: enabled");
    }

    if !config.reject_cloudflare_ips {
        inner.warningf("", "Cloudflare IP rejection: DISABLED (REJECT_CLOUDFLARE_IPS=false)");
    }

    if let Some(ref comment) = config.record_comment {
        inner.infof("", &format!("Record comment: {comment}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_legacy_config_minimal() {
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
    fn test_parse_legacy_config_low_ttl() {
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
    fn test_cron_schedule_every() {
        let sched = CronSchedule::Every(Duration::from_secs(300));
        assert_eq!(sched.next_duration(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_cron_schedule_once() {
        let sched = CronSchedule::Once;
        assert_eq!(sched.next_duration(), None);
    }

    #[test]
    fn test_parse_duration_string() {
        assert_eq!(parse_duration_string("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration_string("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration_string("30s"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_substitute_env_vars() {
        std::env::set_var("CF_DDNS_TEST_VAR", "test_value");
        let result = substitute_env_vars("token: ${CF_DDNS_TEST_VAR}");
        assert_eq!(result, "token: test_value");
        let result2 = substitute_env_vars("token: $CF_DDNS_TEST_VAR");
        assert_eq!(result2, "token: test_value");
        std::env::remove_var("CF_DDNS_TEST_VAR");
    }

    // --- parse_duration_string edge cases ---

    #[test]
    fn test_parse_duration_string_plain_number() {
        assert_eq!(parse_duration_string("60"), Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_parse_duration_string_whitespace() {
        assert_eq!(parse_duration_string("  5m  "), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_parse_duration_string_invalid() {
        assert_eq!(parse_duration_string("abc"), None);
        assert_eq!(parse_duration_string(""), None);
    }

    // --- CronSchedule ---

    #[test]
    fn test_cron_schedule_describe() {
        assert_eq!(
            CronSchedule::Every(Duration::from_secs(300)).describe(),
            "@every 300s"
        );
        assert_eq!(CronSchedule::Once.describe(), "@once");
    }

    // --- read_cron_from_env ---

    #[test]
    fn test_read_cron_default() {
        // No env var set -> default 5m
        std::env::remove_var("UPDATE_CRON");
        let pp = PP::new(false, false);
        let sched = read_cron_from_env(&pp).unwrap();
        assert!(matches!(sched, CronSchedule::Every(d) if d == Duration::from_secs(300)));
    }

    #[test]
    fn test_read_cron_once() {
        std::env::set_var("UPDATE_CRON", "@once");
        let pp = PP::new(false, false);
        let sched = read_cron_from_env(&pp).unwrap();
        assert!(matches!(sched, CronSchedule::Once));
        std::env::remove_var("UPDATE_CRON");
    }

    #[test]
    fn test_read_cron_every() {
        std::env::set_var("UPDATE_CRON", "@every 10m");
        let pp = PP::new(false, false);
        let sched = read_cron_from_env(&pp).unwrap();
        assert!(matches!(sched, CronSchedule::Every(d) if d == Duration::from_secs(600)));
        std::env::remove_var("UPDATE_CRON");
    }

    #[test]
    fn test_read_cron_deprecated_disabled() {
        std::env::set_var("UPDATE_CRON", "@disabled");
        let pp = PP::new(false, false);
        let sched = read_cron_from_env(&pp).unwrap();
        assert!(matches!(sched, CronSchedule::Once));
        std::env::remove_var("UPDATE_CRON");
    }

    #[test]
    fn test_read_cron_unsupported_format() {
        std::env::set_var("UPDATE_CRON", "*/5 * * * *");
        let pp = PP::new(false, false);
        let result = read_cron_from_env(&pp);
        assert!(result.is_err());
        std::env::remove_var("UPDATE_CRON");
    }

    // --- getenv helpers ---

    #[test]
    fn test_getenv_empty_string_is_none() {
        std::env::set_var("TEST_GETENV_EMPTY", "");
        assert!(getenv("TEST_GETENV_EMPTY").is_none());
        std::env::remove_var("TEST_GETENV_EMPTY");
    }

    #[test]
    fn test_getenv_whitespace_is_none() {
        std::env::set_var("TEST_GETENV_WS", "   ");
        assert!(getenv("TEST_GETENV_WS").is_none());
        std::env::remove_var("TEST_GETENV_WS");
    }

    #[test]
    fn test_getenv_trims() {
        std::env::set_var("TEST_GETENV_TRIM", "  hello  ");
        assert_eq!(getenv("TEST_GETENV_TRIM"), Some("hello".to_string()));
        std::env::remove_var("TEST_GETENV_TRIM");
    }

    #[test]
    fn test_getenv_bool_true_values() {
        for val in &["true", "1", "yes", "True", "YES"] {
            std::env::set_var("TEST_BOOL", val);
            assert!(getenv_bool("TEST_BOOL", false));
        }
        std::env::remove_var("TEST_BOOL");
    }

    #[test]
    fn test_getenv_bool_false_values() {
        for val in &["false", "0", "no", "anything"] {
            std::env::set_var("TEST_BOOL", val);
            assert!(!getenv_bool("TEST_BOOL", true));
        }
        std::env::remove_var("TEST_BOOL");
    }

    #[test]
    fn test_getenv_bool_default() {
        std::env::remove_var("TEST_BOOL_MISSING");
        assert!(getenv_bool("TEST_BOOL_MISSING", true));
        assert!(!getenv_bool("TEST_BOOL_MISSING", false));
    }

    #[test]
    fn test_getenv_duration_valid() {
        std::env::set_var("TEST_DUR", "10s");
        let d = getenv_duration("TEST_DUR", Duration::from_secs(99));
        assert_eq!(d, Duration::from_secs(10));
        std::env::remove_var("TEST_DUR");
    }

    #[test]
    fn test_getenv_duration_default() {
        std::env::remove_var("TEST_DUR_MISSING");
        let d = getenv_duration("TEST_DUR_MISSING", Duration::from_secs(42));
        assert_eq!(d, Duration::from_secs(42));
    }

    #[test]
    fn test_getenv_list() {
        std::env::set_var("TEST_LIST", "a,b,,c");
        let list = getenv_list("TEST_LIST", ',');
        assert_eq!(list, vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST");
    }

    #[test]
    fn test_getenv_list_empty() {
        std::env::remove_var("TEST_LIST_MISSING");
        let list = getenv_list("TEST_LIST_MISSING", ',');
        assert!(list.is_empty());
    }

    // --- read_regex ---

    #[test]
    fn test_read_regex_valid() {
        std::env::set_var("TEST_REGEX", "cloudflare-ddns");
        let pp = PP::new(false, false);
        let regex = read_regex("TEST_REGEX", &pp);
        assert!(regex.is_some());
        assert!(regex.unwrap().is_match("managed by cloudflare-ddns"));
        std::env::remove_var("TEST_REGEX");
    }

    #[test]
    fn test_read_regex_invalid() {
        std::env::set_var("TEST_REGEX_BAD", "[invalid(");
        let pp = PP::new(false, false);
        let regex = read_regex("TEST_REGEX_BAD", &pp);
        assert!(regex.is_none());
        std::env::remove_var("TEST_REGEX_BAD");
    }

    #[test]
    fn test_read_regex_empty() {
        std::env::set_var("TEST_REGEX_E", "");
        let pp = PP::new(false, false);
        let regex = read_regex("TEST_REGEX_E", &pp);
        assert!(regex.is_none());
        std::env::remove_var("TEST_REGEX_E");
    }

    // --- read_domains_from_env ---

    #[test]
    fn test_read_domains_both() {
        std::env::set_var("DOMAINS", "example.com,www.example.com");
        std::env::remove_var("IP4_DOMAINS");
        std::env::remove_var("IP6_DOMAINS");
        let pp = PP::new(false, false);
        let domains = read_domains_from_env(&pp);
        assert_eq!(domains.get(&IpType::V4).unwrap().len(), 2);
        assert_eq!(domains.get(&IpType::V6).unwrap().len(), 2);
        std::env::remove_var("DOMAINS");
    }

    #[test]
    fn test_read_domains_ip4_only() {
        std::env::remove_var("DOMAINS");
        std::env::set_var("IP4_DOMAINS", "v4.example.com");
        std::env::remove_var("IP6_DOMAINS");
        let pp = PP::new(false, false);
        let domains = read_domains_from_env(&pp);
        assert_eq!(domains.get(&IpType::V4).unwrap(), &vec!["v4.example.com".to_string()]);
        assert!(domains.get(&IpType::V6).is_none());
        std::env::remove_var("IP4_DOMAINS");
    }

    #[test]
    fn test_read_domains_empty() {
        std::env::remove_var("DOMAINS");
        std::env::remove_var("IP4_DOMAINS");
        std::env::remove_var("IP6_DOMAINS");
        let pp = PP::new(false, false);
        let domains = read_domains_from_env(&pp);
        assert!(domains.is_empty());
    }

    // --- read_waf_lists_from_env ---

    #[test]
    fn test_read_waf_lists_valid() {
        std::env::set_var("WAF_LISTS", "acc123/my_list");
        let pp = PP::new(false, false);
        let lists = read_waf_lists_from_env(&pp);
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].account_id, "acc123");
        assert_eq!(lists[0].list_name, "my_list");
        std::env::remove_var("WAF_LISTS");
    }

    #[test]
    fn test_read_waf_lists_invalid_skipped() {
        std::env::set_var("WAF_LISTS", "no-slash");
        let pp = PP::new(false, false);
        let lists = read_waf_lists_from_env(&pp);
        assert!(lists.is_empty());
        std::env::remove_var("WAF_LISTS");
    }

    // --- legacy_to_app_config ---

    #[test]
    fn test_legacy_to_app_config_basic() {
        let legacy = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "my-token".to_string(),
                    api_key: None,
                },
                zone_id: "zone1".to_string(),
                subdomains: vec![LegacySubdomainEntry::Simple("@".to_string())],
                proxied: false,
            }],
            a: true,
            aaaa: false,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: None,
            ip6_provider: None,
        };
        let config = legacy_to_app_config(legacy, false, false).unwrap();
        assert!(config.legacy_mode);
        assert!(matches!(config.auth, Auth::Token(ref t) if t == "my-token"));
        assert!(config.providers.contains_key(&IpType::V4));
        assert!(!config.providers.contains_key(&IpType::V6));
        assert!(matches!(config.update_cron, CronSchedule::Once));
        assert!(!config.dry_run);
    }

    #[test]
    fn test_legacy_to_app_config_repeat() {
        let legacy = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "tok".to_string(),
                    api_key: None,
                },
                zone_id: "z".to_string(),
                subdomains: vec![],
                proxied: false,
            }],
            a: true,
            aaaa: true,
            purge_unknown_records: false,
            ttl: 120,
            ip4_provider: None,
            ip6_provider: None,
        };
        let config = legacy_to_app_config(legacy, true, true).unwrap();
        assert!(matches!(config.update_cron, CronSchedule::Every(d) if d == Duration::from_secs(120)));
        assert!(config.repeat);
        assert!(config.dry_run);
    }

    #[test]
    fn test_legacy_to_app_config_api_key() {
        let legacy = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: String::new(),
                    api_key: Some(LegacyApiKey {
                        api_key: "key123".to_string(),
                        account_email: "test@example.com".to_string(),
                    }),
                },
                zone_id: "z".to_string(),
                subdomains: vec![],
                proxied: false,
            }],
            a: true,
            aaaa: true,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: None,
            ip6_provider: None,
        };
        let config = legacy_to_app_config(legacy, false, false).unwrap();
        assert!(matches!(config.auth, Auth::Key { ref api_key, ref email }
            if api_key == "key123" && email == "test@example.com"));
    }

    #[test]
    fn test_legacy_to_app_config_custom_providers() {
        let legacy = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "tok".to_string(),
                    api_key: None,
                },
                zone_id: "z".to_string(),
                subdomains: vec![],
                proxied: false,
            }],
            a: true,
            aaaa: true,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: Some("ipify".to_string()),
            ip6_provider: Some("cloudflare.doh".to_string()),
        };
        let config = legacy_to_app_config(legacy, false, false).unwrap();
        assert!(matches!(config.providers[&IpType::V4], ProviderType::Ipify));
        assert!(matches!(config.providers[&IpType::V6], ProviderType::CloudflareDOH));
    }

    #[test]
    fn test_legacy_to_app_config_provider_none_overrides_a_flag() {
        let legacy = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "tok".to_string(),
                    api_key: None,
                },
                zone_id: "z".to_string(),
                subdomains: vec![],
                proxied: false,
            }],
            a: true,
            aaaa: true,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: Some("none".to_string()),
            ip6_provider: None,
        };
        let config = legacy_to_app_config(legacy, false, false).unwrap();
        // ip4_provider=none should exclude V4 even though a=true
        assert!(!config.providers.contains_key(&IpType::V4));
        assert!(config.providers.contains_key(&IpType::V6));
    }

    #[test]
    fn test_legacy_to_app_config_invalid_provider_returns_error() {
        let legacy = LegacyConfig {
            cloudflare: vec![LegacyCloudflareEntry {
                authentication: LegacyAuthentication {
                    api_token: "tok".to_string(),
                    api_key: None,
                },
                zone_id: "z".to_string(),
                subdomains: vec![],
                proxied: false,
            }],
            a: true,
            aaaa: false,
            purge_unknown_records: false,
            ttl: 300,
            ip4_provider: Some("totally_invalid".to_string()),
            ip6_provider: None,
        };
        let result = legacy_to_app_config(legacy, false, false);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("ip4_provider"));
    }

    #[test]
    fn test_legacy_config_deserializes_providers() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok" },
                "zone_id": "z",
                "subdomains": ["@"]
            }],
            "ip4_provider": "ipify",
            "ip6_provider": "none"
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert_eq!(config.ip4_provider, Some("ipify".to_string()));
        assert_eq!(config.ip6_provider, Some("none".to_string()));
    }

    #[test]
    fn test_legacy_config_deserializes_without_providers() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok" },
                "zone_id": "z",
                "subdomains": ["@"]
            }]
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert!(config.ip4_provider.is_none());
        assert!(config.ip6_provider.is_none());
    }

    // --- is_env_config_mode ---

    #[test]
    fn test_is_env_config_mode_with_token() {
        std::env::set_var("CLOUDFLARE_API_TOKEN", "test");
        assert!(is_env_config_mode());
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
    }

    #[test]
    fn test_is_env_config_mode_with_domains() {
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
        std::env::remove_var("CF_API_TOKEN");
        std::env::remove_var("CLOUDFLARE_API_TOKEN_FILE");
        std::env::remove_var("CF_API_TOKEN_FILE");
        std::env::set_var("DOMAINS", "example.com");
        assert!(is_env_config_mode());
        std::env::remove_var("DOMAINS");
    }

    // --- parse_legacy_config edge cases ---

    #[test]
    fn test_parse_legacy_config_with_detailed_subdomains() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok" },
                "zone_id": "z",
                "subdomains": [
                    { "name": "www", "proxied": true },
                    "vpn"
                ]
            }]
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert_eq!(config.cloudflare[0].subdomains.len(), 2);
        match &config.cloudflare[0].subdomains[0] {
            LegacySubdomainEntry::Detailed { name, proxied } => {
                assert_eq!(name, "www");
                assert!(*proxied);
            }
            _ => panic!("Expected Detailed"),
        }
        match &config.cloudflare[0].subdomains[1] {
            LegacySubdomainEntry::Simple(name) => assert_eq!(name, "vpn"),
            _ => panic!("Expected Simple"),
        }
    }

    #[test]
    fn test_parse_legacy_config_with_api_key() {
        let json = r#"{
            "cloudflare": [{
                "authentication": {
                    "api_key": {
                        "api_key": "key123",
                        "account_email": "user@example.com"
                    }
                },
                "zone_id": "z",
                "subdomains": ["@"]
            }]
        }"#;
        let config = parse_legacy_config(json).unwrap();
        let auth = &config.cloudflare[0].authentication;
        assert!(auth.api_key.is_some());
        assert_eq!(auth.api_key.as_ref().unwrap().api_key, "key123");
    }

    #[test]
    fn test_parse_legacy_config_invalid_json() {
        let result = parse_legacy_config("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_legacy_config_ttl_exactly_30() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok" },
                "zone_id": "z",
                "subdomains": ["@"]
            }],
            "ttl": 30
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert_eq!(config.ttl, 30);
    }

    #[test]
    fn test_parse_legacy_config_purge_unknown() {
        let json = r#"{
            "cloudflare": [{
                "authentication": { "api_token": "tok" },
                "zone_id": "z",
                "subdomains": ["@"],
                "proxied": true
            }],
            "purgeUnknownRecords": true,
            "a": true,
            "aaaa": false
        }"#;
        let config = parse_legacy_config(json).unwrap();
        assert!(config.purge_unknown_records);
        assert!(config.a);
        assert!(!config.aaaa);
        assert!(config.cloudflare[0].proxied);
    }

    // --- substitute_env_vars ---

    #[test]
    fn test_substitute_no_match() {
        let result = substitute_env_vars("no variables here");
        assert_eq!(result, "no variables here");
    }

    #[test]
    fn test_substitute_non_cf_ddns_vars_ignored() {
        std::env::set_var("HOME", "/home/user");
        let result = substitute_env_vars("home: $HOME");
        assert_eq!(result, "home: $HOME"); // HOME doesn't start with CF_DDNS_
    }

    // --- print_config_summary ---

    #[test]
    fn test_print_config_summary_legacy_noop() {
        let config = AppConfig {
            auth: Auth::Token(String::new()),
            providers: HashMap::new(),
            domains: HashMap::new(),
            waf_lists: Vec::new(),
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
            update_timeout: Duration::from_secs(30),
            reject_cloudflare_ips: false,
            dry_run: false,
            emoji: false,
            quiet: false,
            legacy_mode: true,
            legacy_config: None,
            repeat: false,
        };
        let pp = PP::new(false, false);
        // Should return early without panicking for legacy mode
        print_config_summary(&config, &pp);
    }

    #[test]
    fn test_print_config_summary_env_mode() {
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["example.com".to_string()]);
        let config = AppConfig {
            auth: Auth::Token("tok".to_string()),
            providers: HashMap::new(),
            domains,
            waf_lists: Vec::new(),
            update_cron: CronSchedule::Every(Duration::from_secs(300)),
            update_on_start: true,
            delete_on_stop: true,
            ttl: TTL::new(60),
            proxied_expression: None,
            record_comment: Some("managed".to_string()),
            managed_comment_regex: None,
            waf_list_description: None,
            waf_list_item_comment: None,
            managed_waf_comment_regex: None,
            detection_timeout: Duration::from_secs(5),
            update_timeout: Duration::from_secs(30),
            reject_cloudflare_ips: false,
            dry_run: false,
            emoji: false,
            quiet: false,
            legacy_mode: false,
            legacy_config: None,
            repeat: false,
        };
        let pp = PP::new(false, false);
        // Should print without panicking
        print_config_summary(&config, &pp);
    }

    // ============================================================
    // EnvGuard helper for safe env-var tests
    // ============================================================

    // Mutex to serialize env-var-dependent tests (prevents parallel interference)
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        keys: Vec<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let lock = ENV_MUTEX.lock().unwrap();
            std::env::set_var(key, value);
            Self { keys: vec![key.to_string()], _lock: lock }
        }

        fn add(&mut self, key: &str, value: &str) {
            std::env::set_var(key, value);
            self.keys.push(key.to_string());
        }

        /// Remove a key from the environment and record it so Drop cleans up properly.
        fn remove(&mut self, key: &str) {
            std::env::remove_var(key);
            self.keys.push(key.to_string());
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in &self.keys {
                std::env::remove_var(key);
            }
        }
    }

    // ============================================================
    // read_auth_from_env
    // ============================================================

    #[test]
    fn test_read_auth_cloudflare_api_token() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN_RA1", "secret-token");
        g.remove("CF_API_TOKEN_RA1");
        // We test via the real env-var names the function uses.
        // Use a unique suffix to avoid cross-test pollution; the function reads
        // fixed names, so we must use the real names. Accept the race risk in
        // exchange for genuine coverage by running tests single-threaded or with
        // the real variable names in isolation.
        drop(g);

        // Re-run using the canonical names the function actually reads.
        let mut g2 = EnvGuard::set("CLOUDFLARE_API_TOKEN", "real-token-abc");
        g2.remove("CF_API_TOKEN");
        g2.remove("CLOUDFLARE_API_TOKEN_FILE");
        g2.remove("CF_API_TOKEN_FILE");
        g2.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g2);
        assert!(matches!(auth, Some(Auth::Token(ref t)) if t == "real-token-abc"));
    }

    #[test]
    fn test_read_auth_placeholder_token_returns_none() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "YOUR-CLOUDFLARE-API-TOKEN");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        assert!(auth.is_none());
    }

    #[test]
    fn test_read_auth_cf_api_token_deprecated_fallback() {
        let mut g = EnvGuard::set("CF_API_TOKEN", "deprecated-token");
        g.remove("CLOUDFLARE_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        assert!(matches!(auth, Some(Auth::Token(ref t)) if t == "deprecated-token"));
    }

    #[test]
    fn test_read_auth_no_vars_returns_none() {
        let mut g = EnvGuard::set("_PLACEHOLDER_RA", "x"); // just to create guard
        g.remove("CLOUDFLARE_API_TOKEN");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        assert!(auth.is_none());
    }

    #[test]
    fn test_read_auth_token_file_valid() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("cf_ddns_test_token_file_valid.txt");
        {
            let mut f = std::fs::File::create(&path).expect("create temp file");
            write!(f, "  file-token-xyz  ").unwrap();
        }
        let path_str = path.to_str().unwrap().to_string();

        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN_FILE", &path_str);
        g.remove("CLOUDFLARE_API_TOKEN");
        g.remove("CF_API_TOKEN");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(auth, Some(Auth::Token(ref t)) if t == "file-token-xyz"));
    }

    #[test]
    fn test_read_auth_token_file_missing_returns_none() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN_FILE", "/nonexistent/path/token.txt");
        g.remove("CLOUDFLARE_API_TOKEN");
        g.remove("CF_API_TOKEN");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        assert!(auth.is_none());
    }

    #[test]
    fn test_read_auth_cf_account_id_deprecated_warning() {
        // CF_ACCOUNT_ID should emit a deprecation warning but not affect auth result.
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-with-account-id");
        g.add("CF_ACCOUNT_ID", "acc123");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        // Auth should still succeed with the token; CF_ACCOUNT_ID is just ignored.
        assert!(matches!(auth, Some(Auth::Token(ref t)) if t == "tok-with-account-id"));
    }

    #[test]
    fn test_read_auth_cf_api_token_file_deprecated_fallback() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("cf_ddns_test_token_file_deprecated.txt");
        {
            let mut f = std::fs::File::create(&path).expect("create temp file");
            write!(f, "old-file-token").unwrap();
        }
        let path_str = path.to_str().unwrap().to_string();

        let mut g = EnvGuard::set("CF_API_TOKEN_FILE", &path_str);
        g.remove("CLOUDFLARE_API_TOKEN");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        let pp = PP::new(false, true);
        let auth = read_auth_from_env(&pp);
        drop(g);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(auth, Some(Auth::Token(ref t)) if t == "old-file-token"));
    }

    // ============================================================
    // read_providers_from_env
    // ============================================================

    #[test]
    fn test_read_providers_defaults() {
        let mut g = EnvGuard::set("_PLACEHOLDER_RP", "x");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        let pp = PP::new(false, true);
        let providers = read_providers_from_env(&pp).unwrap();
        drop(g);
        // Both V4 and V6 default to CloudflareTrace.
        assert!(providers.contains_key(&IpType::V4));
        assert!(providers.contains_key(&IpType::V6));
        assert!(matches!(
            providers[&IpType::V4],
            ProviderType::CloudflareTrace { url: None }
        ));
        assert!(matches!(
            providers[&IpType::V6],
            ProviderType::CloudflareTrace { url: None }
        ));
    }

    #[test]
    fn test_read_providers_ip4_none_excludes_v4() {
        let mut g = EnvGuard::set("IP4_PROVIDER", "none");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        let pp = PP::new(false, true);
        let providers = read_providers_from_env(&pp).unwrap();
        drop(g);
        assert!(!providers.contains_key(&IpType::V4));
        assert!(providers.contains_key(&IpType::V6));
    }

    #[test]
    fn test_read_providers_ip6_none_excludes_v6() {
        let mut g = EnvGuard::set("IP6_PROVIDER", "none");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_POLICY");
        let pp = PP::new(false, true);
        let providers = read_providers_from_env(&pp).unwrap();
        drop(g);
        assert!(providers.contains_key(&IpType::V4));
        assert!(!providers.contains_key(&IpType::V6));
    }

    #[test]
    fn test_read_providers_invalid_returns_error() {
        let mut g = EnvGuard::set("IP4_PROVIDER", "totally_invalid_provider");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        let pp = PP::new(false, true);
        let result = read_providers_from_env(&pp);
        drop(g);
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("IP4_PROVIDER"));
    }

    #[test]
    fn test_read_providers_ip4_policy_deprecated() {
        // IP4_POLICY is deprecated alias for IP4_PROVIDER.
        let mut g = EnvGuard::set("IP4_POLICY", "ipify");
        g.remove("IP4_PROVIDER");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        let pp = PP::new(false, true);
        let providers = read_providers_from_env(&pp).unwrap();
        drop(g);
        assert!(matches!(providers[&IpType::V4], ProviderType::Ipify));
    }

    #[test]
    fn test_read_providers_ip6_policy_deprecated() {
        // IP6_POLICY is deprecated alias for IP6_PROVIDER.
        let mut g = EnvGuard::set("IP6_POLICY", "ipify");
        g.remove("IP6_PROVIDER");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        let pp = PP::new(false, true);
        let providers = read_providers_from_env(&pp).unwrap();
        drop(g);
        assert!(matches!(providers[&IpType::V6], ProviderType::Ipify));
    }

    // ============================================================
    // read_cron_from_env: @nevermore deprecated alias
    // ============================================================

    #[test]
    fn test_read_cron_deprecated_nevermore() {
        let g = EnvGuard::set("UPDATE_CRON", "@nevermore");
        let pp = PP::new(false, true);
        let sched = read_cron_from_env(&pp).unwrap();
        drop(g);
        assert!(matches!(sched, CronSchedule::Once));
    }

    #[test]
    fn test_read_cron_invalid_duration_in_every() {
        let g = EnvGuard::set("UPDATE_CRON", "@every notaduration");
        let pp = PP::new(false, true);
        let result = read_cron_from_env(&pp);
        drop(g);
        assert!(result.is_err());
    }

    // ============================================================
    // load_env_config
    // ============================================================

    #[test]
    fn test_load_env_config_basic_success() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-load-test");
        g.add("DOMAINS", "example.com");
        // Clear potentially interfering vars.
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("UPDATE_CRON");
        g.remove("UPDATE_ON_START");
        g.remove("DELETE_ON_STOP");
        g.remove("TTL");
        g.remove("PROXIED");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let config = load_env_config(&pp).unwrap();
        drop(g);
        assert!(matches!(config.auth, Auth::Token(ref t) if t == "tok-load-test"));
        assert!(!config.domains.is_empty());
        assert!(!config.legacy_mode);
    }

    #[test]
    fn test_load_env_config_missing_auth_returns_error() {
        let mut g = EnvGuard::set("DOMAINS", "example.com");
        g.remove("CLOUDFLARE_API_TOKEN");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("WAF_LISTS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("UPDATE_CRON");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("No authentication") || err.contains("CLOUDFLARE_API_TOKEN"));
    }

    #[test]
    fn test_load_env_config_missing_domains_returns_error() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-no-domains");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("DOMAINS");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("UPDATE_CRON");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("No update targets") || err.contains("DOMAINS"));
    }

    #[test]
    fn test_load_env_config_once_update_on_start_false_errors() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-once-test");
        g.add("DOMAINS", "example.com");
        g.add("UPDATE_CRON", "@once");
        g.add("UPDATE_ON_START", "false");
        g.add("DELETE_ON_STOP", "false");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("UPDATE_ON_START"));
    }

    #[test]
    fn test_load_env_config_once_delete_on_stop_true_errors() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-once-del");
        g.add("DOMAINS", "example.com");
        g.add("UPDATE_CRON", "@once");
        g.add("UPDATE_ON_START", "true");
        g.add("DELETE_ON_STOP", "true");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("DELETE_ON_STOP"));
    }

    #[test]
    fn test_load_env_config_with_waf_list_only() {
        // WAF_LISTS alone (no DOMAINS) should succeed.
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-waf-only");
        g.add("WAF_LISTS", "acc123/my_list");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("DOMAINS");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("UPDATE_CRON");
        g.remove("UPDATE_ON_START");
        g.remove("DELETE_ON_STOP");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.waf_lists.len(), 1);
        assert!(config.domains.is_empty());
    }

    #[test]
    fn test_load_env_config_puid_pgid_deprecated_still_succeeds() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-puid");
        g.add("DOMAINS", "example.com");
        g.add("PUID", "1000");
        g.add("PGID", "1000");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("UPDATE_CRON");
        g.remove("UPDATE_ON_START");
        g.remove("DELETE_ON_STOP");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        // PUID/PGID are deprecated and ignored; config should still load.
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_env_config_invalid_provider_returns_error() {
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-bad-provider");
        g.add("DOMAINS", "example.com");
        g.add("IP4_PROVIDER", "not_a_real_provider");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("UPDATE_CRON");
        g.remove("UPDATE_ON_START");
        g.remove("DELETE_ON_STOP");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("IP4_PROVIDER"));
    }

    #[test]
    fn test_load_env_config_comment_regex_mismatch_still_succeeds() {
        // A mismatch between RECORD_COMMENT and MANAGED_RECORDS_COMMENT_REGEX should
        // emit a warning but not fail.
        let mut g = EnvGuard::set("CLOUDFLARE_API_TOKEN", "tok-regex-warn");
        g.add("DOMAINS", "example.com");
        g.add("RECORD_COMMENT", "my comment");
        g.add("MANAGED_RECORDS_COMMENT_REGEX", "^cloudflare-ddns");
        g.remove("CF_API_TOKEN");
        g.remove("CLOUDFLARE_API_TOKEN_FILE");
        g.remove("CF_API_TOKEN_FILE");
        g.remove("CF_ACCOUNT_ID");
        g.remove("IP4_DOMAINS");
        g.remove("IP6_DOMAINS");
        g.remove("WAF_LISTS");
        g.remove("IP4_PROVIDER");
        g.remove("IP4_POLICY");
        g.remove("IP6_PROVIDER");
        g.remove("IP6_POLICY");
        g.remove("UPDATE_CRON");
        g.remove("UPDATE_ON_START");
        g.remove("DELETE_ON_STOP");
        g.remove("PUID");
        g.remove("PGID");
        let pp = PP::new(false, true);
        let result = load_env_config(&pp);
        drop(g);
        assert!(result.is_ok());
    }

    // ============================================================
    // setup_notifiers
    // ============================================================

    #[test]
    fn test_setup_notifiers_no_shoutrrr_returns_empty() {
        let mut g = EnvGuard::set("_PLACEHOLDER_SN", "x");
        g.remove("SHOUTRRR");
        let pp = PP::new(false, true);
        let notifier = setup_notifiers(&pp);
        drop(g);
        assert!(notifier.is_empty());
    }

    #[test]
    fn test_setup_notifiers_empty_shoutrrr_returns_empty() {
        let g = EnvGuard::set("SHOUTRRR", "");
        let pp = PP::new(false, true);
        let notifier = setup_notifiers(&pp);
        drop(g);
        // Empty string is treated as unset by getenv_list.
        assert!(notifier.is_empty());
    }

    // ============================================================
    // setup_heartbeats
    // ============================================================

    #[test]
    fn test_setup_heartbeats_no_vars_returns_empty() {
        let mut g = EnvGuard::set("_PLACEHOLDER_HB", "x");
        g.remove("HEALTHCHECKS");
        g.remove("UPTIMEKUMA");
        let pp = PP::new(false, true);
        let hb = setup_heartbeats(&pp);
        drop(g);
        assert!(hb.is_empty());
    }

    #[test]
    fn test_setup_heartbeats_healthchecks_only() {
        let mut g = EnvGuard::set("HEALTHCHECKS", "https://hc-ping.com/abc123");
        g.remove("UPTIMEKUMA");
        let pp = PP::new(false, true);
        let hb = setup_heartbeats(&pp);
        drop(g);
        assert!(!hb.is_empty());
    }

    #[test]
    fn test_setup_heartbeats_uptimekuma_only() {
        let mut g = EnvGuard::set("UPTIMEKUMA", "https://status.example.com/api/push/abc");
        g.remove("HEALTHCHECKS");
        let pp = PP::new(false, true);
        let hb = setup_heartbeats(&pp);
        drop(g);
        assert!(!hb.is_empty());
    }

    #[test]
    fn test_setup_heartbeats_both_monitors() {
        let mut g = EnvGuard::set("HEALTHCHECKS", "https://hc-ping.com/abc");
        g.add("UPTIMEKUMA", "https://status.example.com/api/push/def");
        let pp = PP::new(false, true);
        let hb = setup_heartbeats(&pp);
        drop(g);
        assert!(!hb.is_empty());
    }

    // ============================================================
    // print_config_summary - additional coverage paths
    // ============================================================

    #[test]
    fn test_print_config_summary_with_waf_lists() {
        use crate::cloudflare::WAFList;
        let waf_list = WAFList {
            account_id: "acc123".to_string(),
            list_name: "my_list".to_string(),
        };
        let config = AppConfig {
            auth: Auth::Token("tok".to_string()),
            providers: HashMap::new(),
            domains: HashMap::new(),
            waf_lists: vec![waf_list],
            update_cron: CronSchedule::Every(Duration::from_secs(300)),
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
            update_timeout: Duration::from_secs(30),
            reject_cloudflare_ips: false,
            dry_run: false,
            emoji: false,
            quiet: false,
            legacy_mode: false,
            legacy_config: None,
            repeat: false,
        };
        let pp = PP::new(false, true);
        print_config_summary(&config, &pp); // must not panic
    }

    #[test]
    fn test_print_config_summary_with_providers_and_delete_on_stop() {
        let mut providers = HashMap::new();
        providers.insert(IpType::V4, ProviderType::CloudflareTrace { url: None });
        providers.insert(IpType::V6, ProviderType::Ipify);
        let mut domains = HashMap::new();
        domains.insert(IpType::V4, vec!["v4.example.com".to_string()]);
        let config = AppConfig {
            auth: Auth::Token("tok".to_string()),
            providers,
            domains,
            waf_lists: Vec::new(),
            update_cron: CronSchedule::Every(Duration::from_secs(600)),
            update_on_start: true,
            delete_on_stop: true,
            ttl: TTL::new(120),
            proxied_expression: None,
            record_comment: Some("cf-ddns".to_string()),
            managed_comment_regex: None,
            waf_list_description: None,
            waf_list_item_comment: None,
            managed_waf_comment_regex: None,
            detection_timeout: Duration::from_secs(5),
            update_timeout: Duration::from_secs(30),
            reject_cloudflare_ips: false,
            dry_run: false,
            emoji: false,
            quiet: true,
            legacy_mode: false,
            legacy_config: None,
            repeat: true,
        };
        let pp = PP::new(false, true);
        print_config_summary(&config, &pp); // must not panic
    }

    #[test]
    fn test_print_config_summary_once_schedule() {
        let mut domains = HashMap::new();
        domains.insert(IpType::V6, vec!["ipv6.example.com".to_string()]);
        let config = AppConfig {
            auth: Auth::Token("tok".to_string()),
            providers: HashMap::new(),
            domains,
            waf_lists: Vec::new(),
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
            update_timeout: Duration::from_secs(30),
            reject_cloudflare_ips: false,
            dry_run: false,
            emoji: false,
            quiet: false,
            legacy_mode: false,
            legacy_config: None,
            repeat: false,
        };
        let pp = PP::new(false, true);
        print_config_summary(&config, &pp); // must not panic
    }
}
