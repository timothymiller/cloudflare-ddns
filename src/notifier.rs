use crate::pp::{self, PP};
use reqwest::Client;
use std::time::Duration;

// --- Message ---

#[derive(Debug, Clone)]
pub struct Message {
    pub lines: Vec<String>,
    pub ok: bool,
}

impl Message {
    pub fn new_ok(msg: &str) -> Self {
        Self {
            lines: vec![msg.to_string()],
            ok: true,
        }
    }

    pub fn new_fail(msg: &str) -> Self {
        Self {
            lines: vec![msg.to_string()],
            ok: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn format(&self) -> String {
        self.lines.join("\n")
    }

    pub fn merge(messages: Vec<Message>) -> Message {
        let mut lines = Vec::new();
        let mut ok = true;
        for m in messages {
            lines.extend(m.lines);
            if !m.ok {
                ok = false;
            }
        }
        Message { lines, ok }
    }
}

// --- Composite Notifier ---

pub struct CompositeNotifier {
    notifiers: Vec<Box<dyn NotifierDyn>>,
}

// Object-safe version of Notifier
pub trait NotifierDyn: Send + Sync {
    fn send_dyn<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

impl CompositeNotifier {
    pub fn new(notifiers: Vec<Box<dyn NotifierDyn>>) -> Self {
        Self { notifiers }
    }

    pub async fn send(&self, msg: &Message) {
        if msg.is_empty() {
            return;
        }
        for notifier in &self.notifiers {
            notifier.send_dyn(msg).await;
        }
    }
}

// --- Shoutrrr Notifier ---

pub struct ShoutrrrNotifier {
    client: Client,
    urls: Vec<ShoutrrrService>,
}

struct ShoutrrrService {
    original_url: String,
    service_type: ShoutrrrServiceType,
    webhook_url: String,
}

enum ShoutrrrServiceType {
    Generic,
    Discord,
    Slack,
    Telegram,
    Gotify,
    Pushover,
    Other(String),
}

impl ShoutrrrNotifier {
    pub fn new(urls: &[String]) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build notifier HTTP client: {e}"))?;

        let mut services = Vec::new();
        for url_str in urls {
            let url_str = url_str.trim();
            if url_str.is_empty() {
                continue;
            }
            let service = parse_shoutrrr_url(url_str)?;
            services.push(service);
        }

        Ok(Self {
            client,
            urls: services,
        })
    }

    pub fn describe(&self) -> String {
        let services: Vec<String> = self
            .urls
            .iter()
            .map(|s| match &s.service_type {
                ShoutrrrServiceType::Generic => "generic webhook".to_string(),
                ShoutrrrServiceType::Discord => "Discord".to_string(),
                ShoutrrrServiceType::Slack => "Slack".to_string(),
                ShoutrrrServiceType::Telegram => "Telegram".to_string(),
                ShoutrrrServiceType::Gotify => "Gotify".to_string(),
                ShoutrrrServiceType::Pushover => "Pushover".to_string(),
                ShoutrrrServiceType::Other(name) => name.clone(),
            })
            .collect();
        services.join(", ")
    }

    pub async fn send(&self, msg: &Message, ppfmt: &PP) -> bool {
        let text = msg.format();
        if text.is_empty() {
            return true;
        }

        let mut all_ok = true;
        for service in &self.urls {
            let ok = match &service.service_type {
                ShoutrrrServiceType::Generic => self.send_generic(&service.webhook_url, &text).await,
                ShoutrrrServiceType::Discord => self.send_discord(&service.webhook_url, &text).await,
                ShoutrrrServiceType::Slack => self.send_slack(&service.webhook_url, &text).await,
                ShoutrrrServiceType::Telegram => {
                    self.send_telegram(&service.webhook_url, &text).await
                }
                ShoutrrrServiceType::Gotify => self.send_gotify(&service.webhook_url, &text).await,
                ShoutrrrServiceType::Pushover => {
                    self.send_pushover(&service.webhook_url, &text).await
                }
                ShoutrrrServiceType::Other(_) => self.send_generic(&service.webhook_url, &text).await,
            };
            if !ok {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!("Failed to send notification via {}", service.original_url),
                );
                all_ok = false;
            }
        }
        all_ok
    }

    async fn send_generic(&self, url: &str, text: &str) -> bool {
        let body = serde_json::json!({ "message": text });
        self.client
            .post(url)
            .json(&body)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn send_discord(&self, webhook_url: &str, text: &str) -> bool {
        let body = serde_json::json!({ "content": text });
        self.client
            .post(webhook_url)
            .json(&body)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn send_slack(&self, webhook_url: &str, text: &str) -> bool {
        let body = serde_json::json!({ "text": text });
        self.client
            .post(webhook_url)
            .json(&body)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn send_telegram(&self, api_url: &str, text: &str) -> bool {
        // api_url should be like https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
        let body = serde_json::json!({
            "text": text,
            "parse_mode": "Markdown"
        });
        self.client
            .post(api_url)
            .json(&body)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn send_gotify(&self, url: &str, text: &str) -> bool {
        let body = serde_json::json!({
            "title": "Cloudflare DDNS",
            "message": text,
            "priority": 5
        });
        self.client
            .post(url)
            .json(&body)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn send_pushover(&self, url: &str, text: &str) -> bool {
        // Pushover expects form data with token, user, and message.
        // The webhook_url has token and user as query params, so we parse them out.
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let mut token = String::new();
        let mut user = String::new();
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "token" => token = value.to_string(),
                "user" => user = value.to_string(),
                _ => {}
            }
        }
        let params = [
            ("token", token.as_str()),
            ("user", user.as_str()),
            ("message", text),
        ];
        self.client
            .post("https://api.pushover.net/1/messages.json")
            .form(&params)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

impl NotifierDyn for ShoutrrrNotifier {
    fn send_dyn<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        let pp = PP::default_pp();
        Box::pin(async move { self.send(msg, &pp).await })
    }
}

fn parse_shoutrrr_url(url_str: &str) -> Result<ShoutrrrService, String> {
    // Shoutrrr URL formats:
    // discord://token@id -> https://discord.com/api/webhooks/id/token
    // slack://token-a/token-b/token-c -> https://hooks.slack.com/services/token-a/token-b/token-c
    // telegram://token@telegram?chats=chatid -> https://api.telegram.org/bot{token}/sendMessage?chat_id={chatid}
    // gotify://host/path?token=TOKEN -> https://host/path/message?token=TOKEN
    // generic://host/path -> https://host/path
    // generic+https://host/path -> https://host/path

    if let Some(rest) = url_str.strip_prefix("discord://") {
        let parts: Vec<&str> = rest.splitn(2, '@').collect();
        if parts.len() == 2 {
            let token = parts[0];
            let id = parts[1];
            return Ok(ShoutrrrService {
                original_url: url_str.to_string(),
                service_type: ShoutrrrServiceType::Discord,
                webhook_url: format!("https://discord.com/api/webhooks/{id}/{token}"),
            });
        }
        return Err(format!("Invalid Discord shoutrrr URL: {url_str}"));
    }

    if let Some(rest) = url_str.strip_prefix("slack://") {
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() == 3 {
            return Ok(ShoutrrrService {
                original_url: url_str.to_string(),
                service_type: ShoutrrrServiceType::Slack,
                webhook_url: format!(
                    "https://hooks.slack.com/services/{}/{}/{}",
                    parts[0], parts[1], parts[2]
                ),
            });
        }
        return Err(format!("Invalid Slack shoutrrr URL: {url_str}"));
    }

    if let Some(rest) = url_str.strip_prefix("telegram://") {
        let parts: Vec<&str> = rest.splitn(2, '@').collect();
        if parts.len() == 2 {
            let token = parts[0];
            let remainder = parts[1];
            // Extract chat ID from query params
            if let Some(chats_start) = remainder.find("chats=") {
                let chats_str = &remainder[chats_start + 6..];
                let chat_id = chats_str.split('&').next().unwrap_or(chats_str);
                let chat_id = chat_id.split(',').next().unwrap_or(chat_id);
                return Ok(ShoutrrrService {
                    original_url: url_str.to_string(),
                    service_type: ShoutrrrServiceType::Telegram,
                    webhook_url: format!(
                        "https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}"
                    ),
                });
            }
        }
        return Err(format!("Invalid Telegram shoutrrr URL: {url_str}"));
    }

    if let Some(rest) = url_str
        .strip_prefix("gotify://")
        .or_else(|| url_str.strip_prefix("gotify+https://"))
    {
        return Ok(ShoutrrrService {
            original_url: url_str.to_string(),
            service_type: ShoutrrrServiceType::Gotify,
            webhook_url: format!("https://{rest}/message"),
        });
    }

    if let Some(rest) = url_str
        .strip_prefix("generic://")
        .or_else(|| url_str.strip_prefix("generic+https://"))
    {
        return Ok(ShoutrrrService {
            original_url: url_str.to_string(),
            service_type: ShoutrrrServiceType::Generic,
            webhook_url: format!("https://{rest}"),
        });
    }

    if let Some(rest) = url_str.strip_prefix("generic+http://") {
        return Ok(ShoutrrrService {
            original_url: url_str.to_string(),
            service_type: ShoutrrrServiceType::Generic,
            webhook_url: format!("http://{rest}"),
        });
    }

    if let Some(rest) = url_str.strip_prefix("pushover://") {
        let parts: Vec<&str> = rest.splitn(2, '@').collect();
        if parts.len() == 2 {
            return Ok(ShoutrrrService {
                original_url: url_str.to_string(),
                service_type: ShoutrrrServiceType::Pushover,
                webhook_url: format!(
                    "https://api.pushover.net/1/messages.json?token={}&user={}",
                    parts[0], parts[1]
                ),
            });
        }
        return Err(format!("Invalid Pushover shoutrrr URL: {url_str}"));
    }

    // Unknown scheme - treat as generic with original URL as-is if it looks like a URL
    if url_str.starts_with("http://") || url_str.starts_with("https://") {
        return Ok(ShoutrrrService {
            original_url: url_str.to_string(),
            service_type: ShoutrrrServiceType::Generic,
            webhook_url: url_str.to_string(),
        });
    }

    // Try to parse as scheme://... for unknown services
    if let Some(scheme_end) = url_str.find("://") {
        let scheme = &url_str[..scheme_end];
        return Ok(ShoutrrrService {
            original_url: url_str.to_string(),
            service_type: ShoutrrrServiceType::Other(scheme.to_string()),
            webhook_url: format!("https://{}", &url_str[scheme_end + 3..]),
        });
    }

    Err(format!("Unsupported notification URL: {url_str}"))
}

// --- Heartbeat ---

pub struct Heartbeat {
    monitors: Vec<Box<dyn HeartbeatMonitor>>,
}

pub trait HeartbeatMonitor: Send + Sync {
    fn ping<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
    fn start(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;
    fn exit<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

impl Heartbeat {
    pub fn new(monitors: Vec<Box<dyn HeartbeatMonitor>>) -> Self {
        Self { monitors }
    }

    pub async fn ping(&self, msg: &Message) {
        for monitor in &self.monitors {
            monitor.ping(msg).await;
        }
    }

    pub async fn start(&self) {
        for monitor in &self.monitors {
            monitor.start().await;
        }
    }

    pub async fn exit(&self, msg: &Message) {
        for monitor in &self.monitors {
            monitor.exit(msg).await;
        }
    }
}

// --- Healthchecks.io ---

pub struct HealthchecksMonitor {
    client: Client,
    base_url: String,
}

impl HealthchecksMonitor {
    pub fn new(url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build healthchecks client");

        // Strip trailing slash
        let base_url = url.trim_end_matches('/').to_string();

        Self { client, base_url }
    }

    async fn send_ping(&self, suffix: &str, body: Option<&str>) -> bool {
        let url = if suffix.is_empty() {
            self.base_url.clone()
        } else {
            format!("{}/{suffix}", self.base_url)
        };

        let req = if let Some(body) = body {
            self.client.post(&url).body(body.to_string())
        } else {
            self.client.post(&url)
        };

        req.send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

impl HeartbeatMonitor for HealthchecksMonitor {
    fn ping<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let body = msg.format();
            let suffix = if msg.ok { "" } else { "fail" };
            self.send_ping(suffix, if body.is_empty() { None } else { Some(&body) })
                .await
        })
    }

    fn start(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move { self.send_ping("start", None).await })
    }

    fn exit<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let body = msg.format();
            self.send_ping(
                if msg.ok { "" } else { "fail" },
                if body.is_empty() { None } else { Some(&body) },
            )
            .await
        })
    }
}

// --- Uptime Kuma ---

pub struct UptimeKumaMonitor {
    client: Client,
    base_url: String,
}

impl UptimeKumaMonitor {
    pub fn new(url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build uptime kuma client");

        let base_url = url.trim_end_matches('/').to_string();

        Self { client, base_url }
    }
}

impl HeartbeatMonitor for UptimeKumaMonitor {
    fn ping<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let status = if msg.ok { "up" } else { "down" };
            let text = msg.format();
            let mut url = format!("{}?status={status}", self.base_url);
            if !text.is_empty() {
                url.push_str(&format!("&msg={}", urlencoding(&text)));
            }
            self.client
                .get(&url)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        })
    }

    fn start(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let url = format!("{}?status=up&msg=Starting", self.base_url);
            self.client
                .get(&url)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        })
    }

    fn exit<'a>(
        &'a self,
        msg: &'a Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let status = if msg.ok { "up" } else { "down" };
            let text = msg.format();
            let mut url = format!("{}?status={status}", self.base_url);
            if !text.is_empty() {
                url.push_str(&format!("&msg={}", urlencoding(&text)));
            }
            self.client
                .get(&url)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false)
        })
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ---- Message tests ----

    #[test]
    fn test_message_new_ok() {
        let msg = Message::new_ok("hello");
        assert_eq!(msg.lines, vec!["hello".to_string()]);
        assert!(msg.ok);
    }

    #[test]
    fn test_message_new_fail() {
        let msg = Message::new_fail("error occurred");
        assert_eq!(msg.lines, vec!["error occurred".to_string()]);
        assert!(!msg.ok);
    }

    #[test]
    fn test_message_is_empty_false() {
        let msg = Message::new_ok("something");
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_message_format_single_line() {
        let msg = Message::new_ok("line1");
        assert_eq!(msg.format(), "line1");
    }

    #[test]
    fn test_message_merge_all_ok() {
        let m1 = Message::new_ok("a");
        let m2 = Message::new_ok("b");
        let merged = Message::merge(vec![m1, m2]);
        assert_eq!(merged.lines, vec!["a".to_string(), "b".to_string()]);
        assert!(merged.ok);
    }

    #[test]
    fn test_message_merge_one_fail() {
        let m1 = Message::new_ok("a");
        let m2 = Message::new_fail("b");
        let m3 = Message::new_ok("c");
        let merged = Message::merge(vec![m1, m2, m3]);
        assert_eq!(
            merged.lines,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(!merged.ok);
    }

    #[test]
    fn test_message_merge_all_fail() {
        let m1 = Message::new_fail("x");
        let m2 = Message::new_fail("y");
        let merged = Message::merge(vec![m1, m2]);
        assert!(!merged.ok);
    }

    #[test]
    fn test_message_merge_empty_vec() {
        let merged = Message::merge(vec![]);
        assert!(merged.lines.is_empty());
        assert!(merged.ok);
    }

    // ---- CompositeNotifier tests ----

    #[tokio::test]
    async fn test_composite_notifier_empty_send_does_nothing() {
        let notifier = CompositeNotifier::new(vec![]);
        let msg = Message::new_ok("test");
        notifier.send(&msg).await;
    }

    // ---- parse_shoutrrr_url tests ----

    #[test]
    fn test_parse_discord() {
        let result = parse_shoutrrr_url("discord://mytoken@myid").unwrap();
        assert_eq!(
            result.webhook_url,
            "https://discord.com/api/webhooks/myid/mytoken"
        );
        assert!(matches!(result.service_type, ShoutrrrServiceType::Discord));
        assert_eq!(result.original_url, "discord://mytoken@myid");
    }

    #[test]
    fn test_parse_discord_invalid() {
        let result = parse_shoutrrr_url("discord://noatsign");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_slack() {
        let result = parse_shoutrrr_url("slack://aaa/bbb/ccc").unwrap();
        assert_eq!(
            result.webhook_url,
            "https://hooks.slack.com/services/aaa/bbb/ccc"
        );
        assert!(matches!(result.service_type, ShoutrrrServiceType::Slack));
    }

    #[test]
    fn test_parse_slack_invalid() {
        let result = parse_shoutrrr_url("slack://only-one-part");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_telegram() {
        let result =
            parse_shoutrrr_url("telegram://bottoken123@telegram?chats=12345").unwrap();
        assert_eq!(
            result.webhook_url,
            "https://api.telegram.org/botbottoken123/sendMessage?chat_id=12345"
        );
        assert!(matches!(
            result.service_type,
            ShoutrrrServiceType::Telegram
        ));
    }

    #[test]
    fn test_parse_telegram_invalid_no_chats() {
        let result = parse_shoutrrr_url("telegram://token@telegram");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_gotify() {
        let result = parse_shoutrrr_url("gotify://myhost.com/somepath").unwrap();
        assert_eq!(
            result.webhook_url,
            "https://myhost.com/somepath/message"
        );
        assert!(matches!(result.service_type, ShoutrrrServiceType::Gotify));
    }

    #[test]
    fn test_parse_generic() {
        let result = parse_shoutrrr_url("generic://example.com/webhook").unwrap();
        assert_eq!(result.webhook_url, "https://example.com/webhook");
        assert!(matches!(result.service_type, ShoutrrrServiceType::Generic));
    }

    #[test]
    fn test_parse_generic_plus_https() {
        let result =
            parse_shoutrrr_url("generic+https://example.com/webhook").unwrap();
        assert_eq!(result.webhook_url, "https://example.com/webhook");
        assert!(matches!(result.service_type, ShoutrrrServiceType::Generic));
    }

    #[test]
    fn test_parse_generic_plus_http() {
        let result =
            parse_shoutrrr_url("generic+http://example.com/webhook").unwrap();
        assert_eq!(result.webhook_url, "http://example.com/webhook");
        assert!(matches!(result.service_type, ShoutrrrServiceType::Generic));
    }

    #[test]
    fn test_parse_pushover() {
        let result = parse_shoutrrr_url("pushover://apitoken@userkey").unwrap();
        assert_eq!(
            result.webhook_url,
            "https://api.pushover.net/1/messages.json?token=apitoken&user=userkey"
        );
        assert!(matches!(
            result.service_type,
            ShoutrrrServiceType::Pushover
        ));
    }

    #[test]
    fn test_parse_pushover_invalid() {
        let result = parse_shoutrrr_url("pushover://noatsign");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_plain_https_url() {
        let result =
            parse_shoutrrr_url("https://hooks.example.com/notify").unwrap();
        assert_eq!(result.webhook_url, "https://hooks.example.com/notify");
        assert!(matches!(result.service_type, ShoutrrrServiceType::Generic));
    }

    #[test]
    fn test_parse_plain_http_url() {
        let result =
            parse_shoutrrr_url("http://hooks.example.com/notify").unwrap();
        assert_eq!(result.webhook_url, "http://hooks.example.com/notify");
        assert!(matches!(result.service_type, ShoutrrrServiceType::Generic));
    }

    #[test]
    fn test_parse_unknown_scheme() {
        let result = parse_shoutrrr_url("custom://myhost.example.com/path").unwrap();
        assert_eq!(result.webhook_url, "https://myhost.example.com/path");
        assert!(matches!(
            result.service_type,
            ShoutrrrServiceType::Other(ref s) if s == "custom"
        ));
    }

    #[test]
    fn test_parse_invalid_no_scheme() {
        let result = parse_shoutrrr_url("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty() {
        let result = parse_shoutrrr_url("");
        assert!(result.is_err());
    }

    // ---- urlencoding tests ----

    #[test]
    fn test_urlencoding_basic_ascii() {
        assert_eq!(urlencoding("hello"), "hello");
    }

    #[test]
    fn test_urlencoding_spaces() {
        assert_eq!(urlencoding("hello world"), "hello+world");
    }

    #[test]
    fn test_urlencoding_special_chars() {
        let encoded = urlencoding("a=b&c=d");
        assert_eq!(encoded, "a%3Db%26c%3Dd");
    }

    #[test]
    fn test_urlencoding_empty() {
        assert_eq!(urlencoding(""), "");
    }

    // ---- HealthchecksMonitor with wiremock ----

    #[tokio::test]
    async fn test_healthchecks_ping_ok() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = HealthchecksMonitor::new(&server.uri());
        let msg = Message::new_ok("all good");
        let result = monitor.ping(&msg).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_healthchecks_ping_fail() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = HealthchecksMonitor::new(&server.uri());
        let msg = Message::new_fail("something broke");
        let result = monitor.ping(&msg).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_healthchecks_start() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = HealthchecksMonitor::new(&server.uri());
        let result = monitor.start().await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_healthchecks_exit_ok() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = HealthchecksMonitor::new(&server.uri());
        let msg = Message::new_ok("done");
        let result = monitor.exit(&msg).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_healthchecks_exit_fail() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = HealthchecksMonitor::new(&server.uri());
        let msg = Message::new_fail("exit with error");
        let result = monitor.exit(&msg).await;
        assert!(result);
    }

    // ---- UptimeKumaMonitor with wiremock ----

    #[tokio::test]
    async fn test_uptime_kuma_ping_ok() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = UptimeKumaMonitor::new(&server.uri());
        let msg = Message::new_ok("up and running");
        let result = monitor.ping(&msg).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_uptime_kuma_ping_fail() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = UptimeKumaMonitor::new(&server.uri());
        let msg = Message::new_fail("down");
        let result = monitor.ping(&msg).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_uptime_kuma_start() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = UptimeKumaMonitor::new(&server.uri());
        let result = monitor.start().await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_uptime_kuma_exit() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let monitor = UptimeKumaMonitor::new(&server.uri());
        let msg = Message::new_ok("exiting cleanly");
        let result = monitor.exit(&msg).await;
        assert!(result);
    }

    // ---- ShoutrrrNotifier with wiremock ----

    #[tokio::test]
    async fn test_shoutrrr_send_discord() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        // Build a notifier that points discord webhook at our mock server
        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "discord://token@id".to_string(),
                service_type: ShoutrrrServiceType::Discord,
                webhook_url: format!("{}/api/webhooks/id/token", server.uri()),
            }],
        };
        let msg = Message::new_ok("discord test");
        let pp = PP::default_pp();
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_shoutrrr_send_slack() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "slack://a/b/c".to_string(),
                service_type: ShoutrrrServiceType::Slack,
                webhook_url: format!("{}/services/a/b/c", server.uri()),
            }],
        };
        let msg = Message::new_ok("slack test");
        let pp = PP::default_pp();
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_shoutrrr_send_generic() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "generic://example.com/hook".to_string(),
                service_type: ShoutrrrServiceType::Generic,
                webhook_url: format!("{}/hook", server.uri()),
            }],
        };
        let msg = Message::new_ok("generic test");
        let pp = PP::default_pp();
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_shoutrrr_send_empty_message() {
        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![],
        };
        let msg = Message { lines: Vec::new(), ok: true };
        let pp = PP::default_pp();
        // Empty message should return true immediately
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    // ---- ShoutrrrNotifier::new and describe ----

    #[test]
    fn test_shoutrrr_notifier_new_valid() {
        let urls = vec!["discord://token@id".to_string(), "slack://a/b/c".to_string()];
        let notifier = ShoutrrrNotifier::new(&urls).unwrap();
        assert_eq!(notifier.urls.len(), 2);
    }

    #[test]
    fn test_shoutrrr_notifier_new_skips_empty() {
        let urls = vec!["".to_string(), "  ".to_string(), "discord://token@id".to_string()];
        let notifier = ShoutrrrNotifier::new(&urls).unwrap();
        assert_eq!(notifier.urls.len(), 1);
    }

    #[test]
    fn test_shoutrrr_notifier_new_invalid_url() {
        let urls = vec!["not-a-url".to_string()];
        let result = ShoutrrrNotifier::new(&urls);
        assert!(result.is_err());
    }

    #[test]
    fn test_shoutrrr_notifier_describe() {
        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![
                ShoutrrrService {
                    original_url: "discord://t@i".to_string(),
                    service_type: ShoutrrrServiceType::Discord,
                    webhook_url: "https://example.com".to_string(),
                },
                ShoutrrrService {
                    original_url: "slack://a/b/c".to_string(),
                    service_type: ShoutrrrServiceType::Slack,
                    webhook_url: "https://example.com".to_string(),
                },
                ShoutrrrService {
                    original_url: "telegram://t@t?chats=1".to_string(),
                    service_type: ShoutrrrServiceType::Telegram,
                    webhook_url: "https://example.com".to_string(),
                },
                ShoutrrrService {
                    original_url: "gotify://h/p".to_string(),
                    service_type: ShoutrrrServiceType::Gotify,
                    webhook_url: "https://example.com".to_string(),
                },
                ShoutrrrService {
                    original_url: "pushover://u@t".to_string(),
                    service_type: ShoutrrrServiceType::Pushover,
                    webhook_url: "https://example.com".to_string(),
                },
                ShoutrrrService {
                    original_url: "generic://h/p".to_string(),
                    service_type: ShoutrrrServiceType::Generic,
                    webhook_url: "https://example.com".to_string(),
                },
                ShoutrrrService {
                    original_url: "custom://h/p".to_string(),
                    service_type: ShoutrrrServiceType::Other("custom".to_string()),
                    webhook_url: "https://example.com".to_string(),
                },
            ],
        };
        let desc = notifier.describe();
        assert_eq!(desc, "Discord, Slack, Telegram, Gotify, Pushover, generic webhook, custom");
    }

    // ---- send_telegram, send_gotify, send_pushover with wiremock ----

    #[tokio::test]
    async fn test_shoutrrr_send_telegram() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "telegram://token@telegram?chats=123".to_string(),
                service_type: ShoutrrrServiceType::Telegram,
                webhook_url: format!("{}/bottoken/sendMessage?chat_id=123", server.uri()),
            }],
        };
        let msg = Message::new_ok("telegram test");
        let pp = PP::new(false, true);
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_shoutrrr_send_gotify() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "gotify://host/path".to_string(),
                service_type: ShoutrrrServiceType::Gotify,
                webhook_url: format!("{}/message", server.uri()),
            }],
        };
        let msg = Message::new_ok("gotify test");
        let pp = PP::new(false, true);
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    #[test]
    fn test_pushover_url_query_parsing() {
        // Verify that the pushover webhook URL format contains the right params
        // shoutrrr format: pushover://token@user
        let service = parse_shoutrrr_url("pushover://mytoken@myuser").unwrap();
        let parsed = url::Url::parse(&service.webhook_url).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
        assert_eq!(params.get("token").unwrap().as_ref(), "mytoken");
        assert_eq!(params.get("user").unwrap().as_ref(), "myuser");
    }

    #[tokio::test]
    async fn test_shoutrrr_send_other_type() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "custom://host/path".to_string(),
                service_type: ShoutrrrServiceType::Other("custom".to_string()),
                webhook_url: format!("{}/path", server.uri()),
            }],
        };
        let msg = Message::new_ok("other test");
        let pp = PP::new(false, true);
        let result = notifier.send(&msg, &pp).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_shoutrrr_send_failure_logs_warning() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "discord://t@i".to_string(),
                service_type: ShoutrrrServiceType::Discord,
                webhook_url: format!("{}/webhook", server.uri()),
            }],
        };
        let msg = Message::new_ok("will fail");
        let pp = PP::new(false, true);
        let result = notifier.send(&msg, &pp).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_heartbeat_ping_no_monitors() {
        let hb = Heartbeat::new(vec![]);
        let msg = Message::new_ok("test");
        // Should not panic
        hb.ping(&msg).await;
    }

    #[tokio::test]
    async fn test_heartbeat_start_no_monitors() {
        let hb = Heartbeat::new(vec![]);
        hb.start().await;
    }

    #[tokio::test]
    async fn test_heartbeat_exit_no_monitors() {
        let hb = Heartbeat::new(vec![]);
        let msg = Message::new_ok("bye");
        hb.exit(&msg).await;
    }

    #[tokio::test]
    async fn test_shoutrrr_send_server_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let notifier = ShoutrrrNotifier {
            client: crate::test_client(),
            urls: vec![ShoutrrrService {
                original_url: "generic://example.com/hook".to_string(),
                service_type: ShoutrrrServiceType::Generic,
                webhook_url: format!("{}/hook", server.uri()),
            }],
        };
        let msg = Message::new_ok("will fail");
        let pp = PP::default_pp();
        let result = notifier.send(&msg, &pp).await;
        assert!(!result);
    }
}
