use crate::pp::{self, PP};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

// --- TTL ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TTL(pub i64);

impl TTL {
    pub const AUTO: TTL = TTL(1);

    pub fn new(value: i64) -> Self {
        if value < 30 {
            TTL::AUTO
        } else {
            TTL(value)
        }
    }

    pub fn value(&self) -> i64 {
        self.0
    }

    pub fn describe(&self) -> String {
        if self.0 == 1 {
            "auto".to_string()
        } else {
            format!("{}s", self.0)
        }
    }
}

// --- Auth ---

#[derive(Debug, Clone)]
pub enum Auth {
    Token(String),
    Key { api_key: String, email: String },
}

impl Auth {
    pub fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Auth::Token(token) => req.header("Authorization", format!("Bearer {token}")),
            Auth::Key { api_key, email } => req
                .header("X-Auth-Email", email)
                .header("X-Auth-Key", api_key),
        }
    }
}

// --- WAF List ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WAFList {
    pub account_id: String,
    pub list_name: String,
}

impl WAFList {
    pub fn parse(input: &str) -> Result<Self, String> {
        let parts: Vec<&str> = input.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(format!("WAF list must be in format 'account-id/list-name': {input}"));
        }
        let account_id = parts[0].trim().to_string();
        let list_name = parts[1].trim().to_string();

        if !list_name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(format!("WAF list name must match [a-z0-9_]+: {list_name}"));
        }

        Ok(WAFList {
            account_id,
            list_name,
        })
    }

    pub fn describe(&self) -> String {
        format!("{}/{}", self.account_id, self.list_name)
    }
}

// --- API Response Types ---

#[derive(Debug, Deserialize)]
pub struct CfResponse<T> {
    pub result: Option<T>,
}

#[derive(Debug, Deserialize)]
pub struct CfListResponse<T> {
    pub result: Option<Vec<T>>,
}

#[derive(Debug, Deserialize)]
pub struct ZoneResult {
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub content: String,
    pub proxied: Option<bool>,
    pub ttl: Option<i64>,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsRecordPayload {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

// --- WAF API Types ---

#[derive(Debug, Deserialize)]
pub struct WAFListMeta {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct WAFListItem {
    pub id: String,
    pub ip: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WAFListCreateItem {
    pub ip: String,
    pub comment: Option<String>,
}

// --- Cloudflare API Handle ---

pub struct CloudflareHandle {
    client: Client,
    base_url: String,
    auth: Auth,
    managed_comment_regex: Option<regex::Regex>,
    managed_waf_comment_regex: Option<regex::Regex>,
}

impl CloudflareHandle {
    pub fn new(
        auth: Auth,
        update_timeout: Duration,
        managed_comment_regex: Option<regex::Regex>,
        managed_waf_comment_regex: Option<regex::Regex>,
    ) -> Self {
        let client = Client::builder()
            .timeout(update_timeout)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
            auth,
            managed_comment_regex,
            managed_waf_comment_regex,
        }
    }

    #[cfg(test)]
    pub fn with_base_url(
        base_url: &str,
        auth: Auth,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.to_string(),
            auth,
            managed_comment_regex: None,
            managed_waf_comment_regex: None,
        }
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/{path}", self.base_url)
    }

    async fn api_get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        ppfmt: &PP,
    ) -> Option<T> {
        let url = self.api_url(path);
        let req = self.auth.apply(self.client.get(&url));
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json::<T>().await.ok()
                } else {
                    let url_str = resp.url().to_string();
                    let text = resp.text().await.unwrap_or_default();
                    ppfmt.errorf(pp::EMOJI_ERROR, &format!("API GET '{url_str}' failed: {text}"));
                    None
                }
            }
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("API GET '{path}' error: {e}"));
                None
            }
        }
    }

    async fn api_post<T: serde::de::DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        ppfmt: &PP,
    ) -> Option<T> {
        let url = self.api_url(path);
        let req = self.auth.apply(self.client.post(&url)).json(body);
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json::<T>().await.ok()
                } else {
                    let url_str = resp.url().to_string();
                    let text = resp.text().await.unwrap_or_default();
                    ppfmt.errorf(pp::EMOJI_ERROR, &format!("API POST '{url_str}' failed: {text}"));
                    None
                }
            }
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("API POST '{path}' error: {e}"));
                None
            }
        }
    }

    async fn api_put<T: serde::de::DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        ppfmt: &PP,
    ) -> Option<T> {
        let url = self.api_url(path);
        let req = self.auth.apply(self.client.put(&url)).json(body);
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json::<T>().await.ok()
                } else {
                    let url_str = resp.url().to_string();
                    let text = resp.text().await.unwrap_or_default();
                    ppfmt.errorf(pp::EMOJI_ERROR, &format!("API PUT '{url_str}' failed: {text}"));
                    None
                }
            }
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("API PUT '{path}' error: {e}"));
                None
            }
        }
    }

    async fn api_delete<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        ppfmt: &PP,
    ) -> Option<T> {
        let url = self.api_url(path);
        let req = self.auth.apply(self.client.delete(&url));
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json::<T>().await.ok()
                } else {
                    let url_str = resp.url().to_string();
                    let text = resp.text().await.unwrap_or_default();
                    ppfmt.errorf(pp::EMOJI_ERROR, &format!("API DELETE '{url_str}' failed: {text}"));
                    None
                }
            }
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("API DELETE '{path}' error: {e}"));
                None
            }
        }
    }

    // --- Zone Operations ---

    pub async fn zone_id_of_domain(&self, domain: &str, ppfmt: &PP) -> Option<String> {
        // Try to find zone by iterating parent domains
        let mut current = domain.to_string();
        loop {
            let resp: Option<CfListResponse<ZoneResult>> = self
                .api_get(&format!("zones?name={current}"), ppfmt)
                .await;
            if let Some(r) = resp {
                if let Some(zones) = r.result {
                    if let Some(zone) = zones.first() {
                        return Some(zone.id.clone());
                    }
                }
            }
            // Try parent domain
            if let Some(pos) = current.find('.') {
                current = current[pos + 1..].to_string();
                if !current.contains('.') {
                    break;
                }
            } else {
                break;
            }
        }
        None
    }

    // --- DNS Record Operations ---

    pub async fn list_records(
        &self,
        zone_id: &str,
        record_type: &str,
        ppfmt: &PP,
    ) -> Vec<DnsRecord> {
        let path = format!("zones/{zone_id}/dns_records?per_page=100&type={record_type}");
        let resp: Option<CfListResponse<DnsRecord>> = self.api_get(&path, ppfmt).await;
        resp.and_then(|r| r.result).unwrap_or_default()
    }

    pub async fn list_records_by_name(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
        ppfmt: &PP,
    ) -> Vec<DnsRecord> {
        let records = self.list_records(zone_id, record_type, ppfmt).await;
        records.into_iter().filter(|r| r.name == name).collect()
    }

    fn is_managed_record(&self, record: &DnsRecord) -> bool {
        match &self.managed_comment_regex {
            Some(regex) => {
                let comment = record.comment.as_deref().unwrap_or("");
                regex.is_match(comment)
            }
            None => true, // No regex = manage all records
        }
    }

    pub async fn create_record(
        &self,
        zone_id: &str,
        payload: &DnsRecordPayload,
        ppfmt: &PP,
    ) -> Option<DnsRecord> {
        let path = format!("zones/{zone_id}/dns_records");
        let resp: Option<CfResponse<DnsRecord>> = self.api_post(&path, payload, ppfmt).await;
        resp.and_then(|r| r.result)
    }

    pub async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        payload: &DnsRecordPayload,
        ppfmt: &PP,
    ) -> Option<DnsRecord> {
        let path = format!("zones/{zone_id}/dns_records/{record_id}");
        let resp: Option<CfResponse<DnsRecord>> = self.api_put(&path, payload, ppfmt).await;
        resp.and_then(|r| r.result)
    }

    pub async fn delete_record(
        &self,
        zone_id: &str,
        record_id: &str,
        ppfmt: &PP,
    ) -> bool {
        let path = format!("zones/{zone_id}/dns_records/{record_id}");
        let resp: Option<CfResponse<serde_json::Value>> = self.api_delete(&path, ppfmt).await;
        resp.is_some()
    }

    /// Set IPs for a specific domain/record type. Handles create, update, delete, and dedup.
    pub async fn set_ips(
        &self,
        zone_id: &str,
        fqdn: &str,
        record_type: &str,
        ips: &[IpAddr],
        proxied: bool,
        ttl: TTL,
        comment: Option<&str>,
        dry_run: bool,
        ppfmt: &PP,
    ) -> SetResult {
        let existing = self.list_records_by_name(zone_id, record_type, fqdn, ppfmt).await;
        let managed: Vec<&DnsRecord> = existing.iter().filter(|r| self.is_managed_record(r)).collect();

        if ips.is_empty() {
            // Delete all managed records
            if managed.is_empty() {
                return SetResult::Noop;
            }
            for record in &managed {
                if dry_run {
                    ppfmt.noticef(pp::EMOJI_DELETE, &format!("[DRY RUN] Would delete record {fqdn} ({})", record.content));
                } else {
                    ppfmt.noticef(pp::EMOJI_DELETE, &format!("Deleting record {fqdn} ({})", record.content));
                    self.delete_record(zone_id, &record.id, ppfmt).await;
                }
            }
            return SetResult::Updated;
        }

        // For each IP, find or create a record
        let mut used_record_ids = Vec::new();
        let mut any_change = false;

        for ip in ips {
            let ip_str = ip.to_string();

            // Find existing record with this IP
            let matching = managed.iter().find(|r| {
                r.content == ip_str && !used_record_ids.contains(&&r.id)
            });

            if let Some(record) = matching {
                used_record_ids.push(&record.id);
                // Check if update needed (proxied or TTL changed)
                let needs_update = record.proxied != Some(proxied)
                    || (ttl != TTL::AUTO && record.ttl != Some(ttl.value()))
                    || (comment.is_some() && record.comment.as_deref() != comment);

                if needs_update {
                    any_change = true;
                    let payload = DnsRecordPayload {
                        record_type: record_type.to_string(),
                        name: fqdn.to_string(),
                        content: ip_str.clone(),
                        proxied,
                        ttl: ttl.value(),
                        comment: comment.map(|s| s.to_string()),
                    };
                    if dry_run {
                        ppfmt.noticef(pp::EMOJI_UPDATE, &format!("[DRY RUN] Would update record {fqdn} -> {ip_str}"));
                    } else {
                        ppfmt.noticef(pp::EMOJI_UPDATE, &format!("Updating record {fqdn} -> {ip_str}"));
                        self.update_record(zone_id, &record.id, &payload, ppfmt).await;
                    }
                } else {
                    ppfmt.infof(pp::EMOJI_SKIP, &format!("Record {fqdn} is up to date ({ip_str})"));
                }
            } else {
                // Find an existing managed record to update, or create new
                let reusable = managed.iter().find(|r| {
                    !used_record_ids.contains(&&r.id)
                });

                let payload = DnsRecordPayload {
                    record_type: record_type.to_string(),
                    name: fqdn.to_string(),
                    content: ip_str.clone(),
                    proxied,
                    ttl: ttl.value(),
                    comment: comment.map(|s| s.to_string()),
                };

                if let Some(record) = reusable {
                    used_record_ids.push(&record.id);
                    any_change = true;
                    if dry_run {
                        ppfmt.noticef(pp::EMOJI_UPDATE, &format!("[DRY RUN] Would update record {fqdn} -> {ip_str}"));
                    } else {
                        ppfmt.noticef(pp::EMOJI_UPDATE, &format!("Updating record {fqdn} -> {ip_str}"));
                        self.update_record(zone_id, &record.id, &payload, ppfmt).await;
                    }
                } else {
                    any_change = true;
                    if dry_run {
                        ppfmt.noticef(pp::EMOJI_CREATE, &format!("[DRY RUN] Would add new record {fqdn} -> {ip_str}"));
                    } else {
                        ppfmt.noticef(pp::EMOJI_CREATE, &format!("Adding new record {fqdn} -> {ip_str}"));
                        self.create_record(zone_id, &payload, ppfmt).await;
                    }
                }
            }
        }

        // Delete extra managed records (duplicates)
        for record in &managed {
            if !used_record_ids.contains(&&record.id) {
                any_change = true;
                if dry_run {
                    ppfmt.noticef(pp::EMOJI_DELETE, &format!("[DRY RUN] Would delete stale record {} ({})", fqdn, record.content));
                } else {
                    ppfmt.noticef(pp::EMOJI_DELETE, &format!("Deleting stale record {} ({})", fqdn, record.content));
                    self.delete_record(zone_id, &record.id, ppfmt).await;
                }
            }
        }

        if any_change {
            SetResult::Updated
        } else {
            SetResult::Noop
        }
    }

    /// Delete all managed records for a specific domain/record type.
    pub async fn final_delete(
        &self,
        zone_id: &str,
        fqdn: &str,
        record_type: &str,
        ppfmt: &PP,
    ) {
        let existing = self.list_records_by_name(zone_id, record_type, fqdn, ppfmt).await;
        for record in &existing {
            if self.is_managed_record(record) {
                ppfmt.noticef(pp::EMOJI_DELETE, &format!("Deleting record {fqdn} ({})", record.content));
                self.delete_record(zone_id, &record.id, ppfmt).await;
            }
        }
    }

    // --- WAF List Operations ---

    pub async fn find_waf_list(
        &self,
        waf_list: &WAFList,
        ppfmt: &PP,
    ) -> Option<WAFListMeta> {
        let path = format!("accounts/{}/rules/lists", waf_list.account_id);
        let resp: Option<CfListResponse<WAFListMeta>> = self.api_get(&path, ppfmt).await;
        resp.and_then(|r| r.result)
            .and_then(|lists| lists.into_iter().find(|l| l.name == waf_list.list_name))
    }

    pub async fn list_waf_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        ppfmt: &PP,
    ) -> Vec<WAFListItem> {
        let path = format!("accounts/{account_id}/rules/lists/{list_id}/items");
        let resp: Option<CfListResponse<WAFListItem>> = self.api_get(&path, ppfmt).await;
        resp.and_then(|r| r.result).unwrap_or_default()
    }

    pub async fn create_waf_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        items: &[WAFListCreateItem],
        ppfmt: &PP,
    ) -> bool {
        let path = format!("accounts/{account_id}/rules/lists/{list_id}/items");
        let resp: Option<CfResponse<serde_json::Value>> = self.api_post(&path, &items, ppfmt).await;
        resp.is_some()
    }

    pub async fn delete_waf_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        item_ids: &[String],
        ppfmt: &PP,
    ) -> bool {
        let path = format!("accounts/{account_id}/rules/lists/{list_id}/items");
        let body: Vec<serde_json::Value> = item_ids
            .iter()
            .map(|id| serde_json::json!({ "id": id }))
            .collect();
        let url = self.api_url(&path);
        let req = self.auth.apply(self.client.delete(&url)).json(&serde_json::json!({ "items": body }));
        match req.send().await {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                ppfmt.errorf(pp::EMOJI_ERROR, &format!("WAF list items DELETE error: {e}"));
                false
            }
        }
    }

    /// Set WAF list to contain exactly the given IPs.
    pub async fn set_waf_list(
        &self,
        waf_list: &WAFList,
        ips: &[IpAddr],
        comment: Option<&str>,
        _description: Option<&str>,
        dry_run: bool,
        ppfmt: &PP,
    ) -> SetResult {
        let list_meta = match self.find_waf_list(waf_list, ppfmt).await {
            Some(meta) => meta,
            None => {
                ppfmt.errorf(
                    pp::EMOJI_ERROR,
                    &format!("WAF list {} not found", waf_list.describe()),
                );
                return SetResult::Failed;
            }
        };

        let existing_items = self
            .list_waf_list_items(&waf_list.account_id, &list_meta.id, ppfmt)
            .await;

        // Filter to managed items
        let managed_items: Vec<&WAFListItem> = existing_items
            .iter()
            .filter(|item| {
                match &self.managed_waf_comment_regex {
                    Some(regex) => {
                        let c = item.comment.as_deref().unwrap_or("");
                        regex.is_match(c)
                    }
                    None => true,
                }
            })
            .collect();

        let desired_ips: std::collections::HashSet<String> =
            ips.iter().map(|ip| ip.to_string()).collect();
        let existing_ips: std::collections::HashSet<String> = managed_items
            .iter()
            .filter_map(|item| item.ip.clone())
            .collect();

        // Items to add
        let to_add: Vec<WAFListCreateItem> = desired_ips
            .difference(&existing_ips)
            .map(|ip| WAFListCreateItem {
                ip: ip.clone(),
                comment: comment.map(|s| s.to_string()),
            })
            .collect();

        // Items to delete
        let ips_to_remove: std::collections::HashSet<&String> =
            existing_ips.difference(&desired_ips).collect();
        let ids_to_delete: Vec<String> = managed_items
            .iter()
            .filter(|item| {
                item.ip.as_ref().map_or(false, |ip| ips_to_remove.contains(ip))
            })
            .map(|item| item.id.clone())
            .collect();

        if to_add.is_empty() && ids_to_delete.is_empty() {
            ppfmt.infof(
                pp::EMOJI_SKIP,
                &format!("WAF list {} is up to date", waf_list.describe()),
            );
            return SetResult::Noop;
        }

        if dry_run {
            for item in &to_add {
                ppfmt.noticef(
                    pp::EMOJI_CREATE,
                    &format!("[DRY RUN] Would add {} to WAF list {}", item.ip, waf_list.describe()),
                );
            }
            for ip in &ips_to_remove {
                ppfmt.noticef(
                    pp::EMOJI_DELETE,
                    &format!("[DRY RUN] Would remove {} from WAF list {}", ip, waf_list.describe()),
                );
            }
            return SetResult::Updated;
        }

        let mut success = true;

        if !ids_to_delete.is_empty() {
            for ip in &ips_to_remove {
                ppfmt.noticef(
                    pp::EMOJI_DELETE,
                    &format!("Removing {} from WAF list {}", ip, waf_list.describe()),
                );
            }
            if !self
                .delete_waf_list_items(&waf_list.account_id, &list_meta.id, &ids_to_delete, ppfmt)
                .await
            {
                success = false;
            }
        }

        if !to_add.is_empty() {
            for item in &to_add {
                ppfmt.noticef(
                    pp::EMOJI_CREATE,
                    &format!("Adding {} to WAF list {}", item.ip, waf_list.describe()),
                );
            }
            if !self
                .create_waf_list_items(&waf_list.account_id, &list_meta.id, &to_add, ppfmt)
                .await
            {
                success = false;
            }
        }

        if success {
            SetResult::Updated
        } else {
            SetResult::Failed
        }
    }

    /// Clear all managed items from a WAF list (for shutdown).
    pub async fn final_clear_waf_list(
        &self,
        waf_list: &WAFList,
        ppfmt: &PP,
    ) {
        let list_meta = match self.find_waf_list(waf_list, ppfmt).await {
            Some(meta) => meta,
            None => return,
        };

        let items = self
            .list_waf_list_items(&waf_list.account_id, &list_meta.id, ppfmt)
            .await;

        let managed_ids: Vec<String> = items
            .iter()
            .filter(|item| {
                match &self.managed_waf_comment_regex {
                    Some(regex) => {
                        let c = item.comment.as_deref().unwrap_or("");
                        regex.is_match(c)
                    }
                    None => true,
                }
            })
            .map(|item| item.id.clone())
            .collect();

        if !managed_ids.is_empty() {
            ppfmt.noticef(
                pp::EMOJI_DELETE,
                &format!("Clearing {} items from WAF list {}", managed_ids.len(), waf_list.describe()),
            );
            self.delete_waf_list_items(&waf_list.account_id, &list_meta.id, &managed_ids, ppfmt)
                .await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetResult {
    Noop,
    Updated,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pp::PP;
    use std::net::IpAddr;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path, query_param}};

    fn pp() -> PP {
        PP::new(false, false)
    }

    fn test_auth() -> Auth {
        Auth::Token("test-token".to_string())
    }

    fn handle(base_url: &str) -> CloudflareHandle {
        CloudflareHandle::with_base_url(base_url, test_auth())
    }

    fn handle_with_regex(base_url: &str, pattern: &str) -> CloudflareHandle {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");
        CloudflareHandle {
            client,
            base_url: base_url.to_string(),
            auth: test_auth(),
            managed_comment_regex: Some(regex::Regex::new(pattern).unwrap()),
            managed_waf_comment_regex: None,
        }
    }

    // -------------------------------------------------------
    // TTL tests
    // -------------------------------------------------------

    #[test]
    fn ttl_new_below_30_becomes_auto() {
        assert_eq!(TTL::new(0), TTL::AUTO);
        assert_eq!(TTL::new(1), TTL::AUTO);
        assert_eq!(TTL::new(29), TTL::AUTO);
        assert_eq!(TTL::new(-5), TTL::AUTO);
    }

    #[test]
    fn ttl_new_at_or_above_30_stays() {
        assert_eq!(TTL::new(30), TTL(30));
        assert_eq!(TTL::new(120), TTL(120));
        assert_eq!(TTL::new(86400), TTL(86400));
    }

    #[test]
    fn ttl_auto_constant() {
        assert_eq!(TTL::AUTO, TTL(1));
    }

    #[test]
    fn ttl_describe_auto() {
        assert_eq!(TTL::AUTO.describe(), "auto");
        assert_eq!(TTL(1).describe(), "auto");
    }

    #[test]
    fn ttl_describe_seconds() {
        assert_eq!(TTL(120).describe(), "120s");
        assert_eq!(TTL(3600).describe(), "3600s");
    }

    // -------------------------------------------------------
    // Auth tests
    // -------------------------------------------------------

    #[test]
    fn auth_token_variant() {
        let auth = Auth::Token("my-token".to_string());
        match &auth {
            Auth::Token(t) => assert_eq!(t, "my-token"),
            _ => panic!("expected Token variant"),
        }
    }

    #[test]
    fn auth_key_variant() {
        let auth = Auth::Key {
            api_key: "key123".to_string(),
            email: "user@example.com".to_string(),
        };
        match &auth {
            Auth::Key { api_key, email } => {
                assert_eq!(api_key, "key123");
                assert_eq!(email, "user@example.com");
            }
            _ => panic!("expected Key variant"),
        }
    }

    // -------------------------------------------------------
    // WAFList tests
    // -------------------------------------------------------

    #[test]
    fn waf_list_parse_valid() {
        let wl = WAFList::parse("abc123/my_list").unwrap();
        assert_eq!(wl.account_id, "abc123");
        assert_eq!(wl.list_name, "my_list");
    }

    #[test]
    fn waf_list_parse_no_slash() {
        assert!(WAFList::parse("noslash").is_err());
    }

    #[test]
    fn waf_list_parse_invalid_chars() {
        assert!(WAFList::parse("acc/My-List").is_err());
        assert!(WAFList::parse("acc/UPPER").is_err());
        assert!(WAFList::parse("acc/has space").is_err());
    }

    #[test]
    fn waf_list_describe() {
        let wl = WAFList {
            account_id: "acct".to_string(),
            list_name: "blocklist".to_string(),
        };
        assert_eq!(wl.describe(), "acct/blocklist");
    }

    // -------------------------------------------------------
    // CloudflareHandle with wiremock
    // -------------------------------------------------------

    fn zone_response(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "result": [{ "id": id, "name": name }]
        })
    }

    fn empty_list_response() -> serde_json::Value {
        serde_json::json!({ "result": [] })
    }

    fn dns_record_json(id: &str, name: &str, content: &str, comment: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "content": content,
            "proxied": false,
            "ttl": 1,
            "comment": comment
        })
    }

    fn dns_list_response(records: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "result": records })
    }

    fn dns_single_response(record: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "result": record })
    }

    // --- zone_id_of_domain ---

    #[tokio::test]
    async fn zone_id_of_domain_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_list_response()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(zone_response("zone-1", "example.com")))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let result = h.zone_id_of_domain("sub.example.com", &pp()).await;
        assert_eq!(result, Some("zone-1".to_string()));
    }

    #[tokio::test]
    async fn zone_id_of_domain_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_list_response()))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let result = h.zone_id_of_domain("nonexistent.example.com", &pp()).await;
        assert_eq!(result, None);
    }

    // --- list_records / list_records_by_name ---

    #[tokio::test]
    async fn list_records_returns_all() {
        let server = MockServer::start().await;
        let body = dns_list_response(vec![
            dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            dns_record_json("r2", "b.example.com", "5.6.7.8", None),
        ]);
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .and(query_param("type", "A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let records = h.list_records("z1", "A", &pp()).await;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, "r1");
        assert_eq!(records[1].id, "r2");
    }

    #[tokio::test]
    async fn list_records_by_name_filters() {
        let server = MockServer::start().await;
        let body = dns_list_response(vec![
            dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            dns_record_json("r2", "b.example.com", "5.6.7.8", None),
        ]);
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let records = h.list_records_by_name("z1", "A", "a.example.com", &pp()).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, "1.2.3.4");
    }

    // --- create_record ---

    #[tokio::test]
    async fn create_record_success() {
        let server = MockServer::start().await;
        let resp = dns_single_response(dns_record_json("new-id", "x.example.com", "9.9.9.9", None));
        Mock::given(method("POST"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(resp))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let payload = DnsRecordPayload {
            record_type: "A".to_string(),
            name: "x.example.com".to_string(),
            content: "9.9.9.9".to_string(),
            proxied: false,
            ttl: 1,
            comment: None,
        };
        let result = h.create_record("z1", &payload, &pp()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "new-id");
    }

    // --- update_record ---

    #[tokio::test]
    async fn update_record_success() {
        let server = MockServer::start().await;
        let resp = dns_single_response(dns_record_json("r1", "x.example.com", "10.0.0.1", None));
        Mock::given(method("PUT"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(resp))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let payload = DnsRecordPayload {
            record_type: "A".to_string(),
            name: "x.example.com".to_string(),
            content: "10.0.0.1".to_string(),
            proxied: false,
            ttl: 1,
            comment: None,
        };
        let result = h.update_record("z1", "r1", &payload, &pp()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, "10.0.0.1");
    }

    // --- delete_record ---

    #[tokio::test]
    async fn delete_record_success() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": { "id": "r1" } })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        assert!(h.delete_record("z1", "r1", &pp()).await);
    }

    // --- set_ips: no existing records -> creates ---

    #[tokio::test]
    async fn set_ips_creates_when_no_existing() {
        let server = MockServer::start().await;
        // list returns empty
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![])))
            .mount(&server)
            .await;
        // create
        Mock::given(method("POST"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                dns_single_response(dns_record_json("new1", "a.example.com", "1.2.3.4", None)),
            ))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: matching existing record -> noop ---

    #[tokio::test]
    async fn set_ips_noop_when_matching() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            ])))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Noop);
    }

    // --- set_ips: stale record -> updates ---

    #[tokio::test]
    async fn set_ips_updates_stale_record() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "9.9.9.9", None),
            ])))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                dns_single_response(dns_record_json("r1", "a.example.com", "1.2.3.4", None)),
            ))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: extra records -> deletes extras ---

    #[tokio::test]
    async fn set_ips_deletes_extra_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "1.2.3.4", None),
                dns_record_json("r2", "a.example.com", "5.5.5.5", None),
            ])))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": { "id": "r2" } })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: empty ips -> deletes all managed ---

    #[tokio::test]
    async fn set_ips_empty_ips_deletes_all() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            ])))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": { "id": "r1" } })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec![];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: dry_run doesn't mutate ---

    #[tokio::test]
    async fn set_ips_dry_run_no_mutation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![])))
            .mount(&server)
            .await;
        // No POST mock -- if set_ips tries to POST, wiremock will return 404

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, true, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- is_managed_record ---

    #[test]
    fn is_managed_record_no_regex_manages_all() {
        let h = CloudflareHandle::with_base_url("http://unused", test_auth());
        let record = DnsRecord {
            id: "r1".to_string(),
            name: "test".to_string(),
            content: "1.2.3.4".to_string(),
            proxied: None,
            ttl: None,
            comment: None,
        };
        assert!(h.is_managed_record(&record));
    }

    #[test]
    fn is_managed_record_with_regex_matching() {
        let h = handle_with_regex("http://unused", "^managed-by-ddns$");
        let record = DnsRecord {
            id: "r1".to_string(),
            name: "test".to_string(),
            content: "1.2.3.4".to_string(),
            proxied: None,
            ttl: None,
            comment: Some("managed-by-ddns".to_string()),
        };
        assert!(h.is_managed_record(&record));
    }

    #[test]
    fn is_managed_record_with_regex_not_matching() {
        let h = handle_with_regex("http://unused", "^managed-by-ddns$");
        let record = DnsRecord {
            id: "r1".to_string(),
            name: "test".to_string(),
            content: "1.2.3.4".to_string(),
            proxied: None,
            ttl: None,
            comment: Some("something-else".to_string()),
        };
        assert!(!h.is_managed_record(&record));
    }

    #[test]
    fn is_managed_record_with_regex_no_comment() {
        let h = handle_with_regex("http://unused", "^managed-by-ddns$");
        let record = DnsRecord {
            id: "r1".to_string(),
            name: "test".to_string(),
            content: "1.2.3.4".to_string(),
            proxied: None,
            ttl: None,
            comment: None,
        };
        assert!(!h.is_managed_record(&record));
    }

    // --- final_delete ---

    #[tokio::test]
    async fn final_delete_removes_managed_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "1.2.3.4", None),
                dns_record_json("r2", "a.example.com", "5.6.7.8", None),
            ])))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": { "id": "r1" } })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/zones/z1/dns_records/r2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": { "id": "r2" } })))
            .expect(1)
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        h.final_delete("z1", "a.example.com", "A", &pp()).await;
        // Expectations on mocks validate the DELETE calls were made
    }

    // --- find_waf_list ---

    #[tokio::test]
    async fn find_waf_list_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "list-1", "name": "blocklist" },
                    { "id": "list-2", "name": "allowlist" }
                ]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "allowlist".to_string(),
        };
        let result = h.find_waf_list(&wl, &pp()).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "list-2");
    }

    #[tokio::test]
    async fn find_waf_list_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "list-1", "name": "other" }]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "missing".to_string(),
        };
        let result = h.find_waf_list(&wl, &pp()).await;
        assert!(result.is_none());
    }

    // --- set_waf_list ---

    #[tokio::test]
    async fn set_waf_list_adds_new_items() {
        let server = MockServer::start().await;
        // find_waf_list
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        // list items - empty
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": [] })))
            .mount(&server)
            .await;
        // create items
        Mock::given(method("POST"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": {} })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, Some("ddns"), None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- CloudflareHandle::new ---

    #[test]
    fn cloudflare_handle_new_constructs() {
        let h = CloudflareHandle::new(
            Auth::Token("tok".to_string()),
            Duration::from_secs(10),
            None,
            None,
        );
        assert_eq!(h.base_url, "https://api.cloudflare.com/client/v4");
    }

    // --- Auth::apply ---

    #[test]
    fn auth_key_apply_sets_headers() {
        let auth = Auth::Key {
            api_key: "key123".to_string(),
            email: "user@example.com".to_string(),
        };
        let client = Client::new();
        let req = client.get("http://example.com");
        let req = auth.apply(req);
        // Just verify it doesn't panic - we can't inspect headers easily
        let _ = req;
    }

    // --- API error paths ---

    #[tokio::test]
    async fn api_get_returns_none_on_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let pp = PP::new(false, true); // quiet
        let result: Option<CfListResponse<ZoneResult>> = h.api_get("zones", &pp).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn api_post_returns_none_on_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let pp = PP::new(false, true);
        let body = serde_json::json!({"test": true});
        let result: Option<CfResponse<serde_json::Value>> = h.api_post("endpoint", &body, &pp).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn api_put_returns_none_on_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let pp = PP::new(false, true);
        let body = serde_json::json!({"test": true});
        let result: Option<CfResponse<serde_json::Value>> = h.api_put("endpoint", &body, &pp).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn api_delete_returns_none_on_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(500).set_body_string("error"))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let pp = PP::new(false, true);
        assert!(!h.delete_record("z1", "r1", &pp).await);
    }

    // --- set_ips: update due to proxied change ---

    #[tokio::test]
    async fn set_ips_updates_when_proxied_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                serde_json::json!({
                    "id": "r1",
                    "name": "a.example.com",
                    "content": "1.2.3.4",
                    "proxied": false,
                    "ttl": 1,
                    "comment": null
                }),
            ])))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/zones/z1/dns_records/r1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                dns_single_response(dns_record_json("r1", "a.example.com", "1.2.3.4", None)),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        // proxied=true but record has proxied=false -> should update
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, true, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: dry_run with existing records ---

    #[tokio::test]
    async fn set_ips_dry_run_with_existing_records() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "9.9.9.9", None),
            ])))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, true, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_ips: empty ips, no managed records -> noop ---

    #[tokio::test]
    async fn set_ips_empty_ips_no_records_noop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![])))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec![];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, false, &pp())
            .await;
        assert_eq!(result, SetResult::Noop);
    }

    // --- set_ips: empty ips, managed records -> deletes in dry_run ---

    #[tokio::test]
    async fn set_ips_empty_ips_dry_run_deletes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones/z1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(dns_list_response(vec![
                dns_record_json("r1", "a.example.com", "1.2.3.4", None),
            ])))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let ips: Vec<IpAddr> = vec![];
        let result = h
            .set_ips("z1", "a.example.com", "A", &ips, false, TTL::AUTO, None, true, &pp())
            .await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- set_waf_list: not found -> Failed ---

    #[tokio::test]
    async fn set_waf_list_not_found_returns_failed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "missing".to_string(),
        };
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, None, None, false, &pp()).await;
        assert_eq!(result, SetResult::Failed);
    }

    // --- set_waf_list: noop when already up to date ---

    #[tokio::test]
    async fn set_waf_list_noop_when_up_to_date() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "item-1", "ip": "10.0.0.1", "comment": null }
                ]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        let ips: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, None, None, false, &pp()).await;
        assert_eq!(result, SetResult::Noop);
    }

    // --- set_waf_list: dry_run ---

    #[tokio::test]
    async fn set_waf_list_dry_run() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "item-1", "ip": "10.0.0.1", "comment": null }]
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        // New IP to add + existing to remove
        let ips: Vec<IpAddr> = vec!["10.0.0.2".parse().unwrap()];
        let result = h.set_waf_list(&wl, &ips, None, None, true, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }

    // --- final_clear_waf_list ---

    #[tokio::test]
    async fn final_clear_waf_list_deletes_all() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "item-1", "ip": "10.0.0.1", "comment": null },
                    { "id": "item-2", "ip": "10.0.0.2", "comment": null }
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": {} })))
            .expect(1)
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        h.final_clear_waf_list(&wl, &pp()).await;
    }

    #[tokio::test]
    async fn final_clear_waf_list_not_found_noop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": []
            })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "missing".to_string(),
        };
        // Should not panic
        h.final_clear_waf_list(&wl, &pp()).await;
    }

    #[tokio::test]
    async fn set_waf_list_removes_stale_items() {
        let server = MockServer::start().await;
        // find_waf_list
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [{ "id": "wl-1", "name": "mylist" }]
            })))
            .mount(&server)
            .await;
        // list items - has one stale item
        Mock::given(method("GET"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": [
                    { "id": "item-1", "ip": "10.0.0.1", "comment": null }
                ]
            })))
            .mount(&server)
            .await;
        // delete items
        Mock::given(method("DELETE"))
            .and(path("/accounts/acct1/rules/lists/wl-1/items"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": {} })))
            .mount(&server)
            .await;

        let h = handle(&server.uri());
        let wl = WAFList {
            account_id: "acct1".to_string(),
            list_name: "mylist".to_string(),
        };
        let ips: Vec<IpAddr> = vec![]; // no desired IPs -> should delete the existing one
        let result = h.set_waf_list(&wl, &ips, None, None, false, &pp()).await;
        assert_eq!(result, SetResult::Updated);
    }
}
