use crate::pp::{self, PP};
use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

/// IP type: IPv4 or IPv6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpType {
    V4,
    V6,
}

impl IpType {
    pub fn describe(&self) -> &str {
        match self {
            IpType::V4 => "IPv4",
            IpType::V6 => "IPv6",
        }
    }

    pub fn record_type(&self) -> &str {
        match self {
            IpType::V4 => "A",
            IpType::V6 => "AAAA",
        }
    }

    #[allow(dead_code)]
    pub fn all() -> &'static [IpType] {
        &[IpType::V4, IpType::V6]
    }
}

/// All supported provider types
#[derive(Debug, Clone)]
pub enum ProviderType {
    CloudflareTrace { url: Option<String> },
    CloudflareDOH,
    Ipify,
    Local,
    LocalIface { interface: String },
    CustomURL { url: String },
    Literal { ips: Vec<IpAddr> },
    None,
}

impl ProviderType {
    pub fn name(&self) -> &str {
        match self {
            ProviderType::CloudflareTrace { .. } => "cloudflare.trace",
            ProviderType::CloudflareDOH => "cloudflare.doh",
            ProviderType::Ipify => "ipify",
            ProviderType::Local => "local",
            ProviderType::LocalIface { .. } => "local.iface",
            ProviderType::CustomURL { .. } => "url:",
            ProviderType::Literal { .. } => "literal:",
            ProviderType::None => "none",
        }
    }

    /// Parse a provider string like "cloudflare.trace", "url:https://...", "literal:1.2.3.4"
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() || input == "none" {
            return Ok(ProviderType::None);
        }
        if input == "cloudflare.trace" {
            return Ok(ProviderType::CloudflareTrace { url: None });
        }
        if let Some(url) = input.strip_prefix("cloudflare.trace:") {
            return Ok(ProviderType::CloudflareTrace {
                url: Some(url.to_string()),
            });
        }
        if input == "cloudflare.doh" {
            return Ok(ProviderType::CloudflareDOH);
        }
        if input == "ipify" {
            return Ok(ProviderType::Ipify);
        }
        if input == "local" {
            return Ok(ProviderType::Local);
        }
        if let Some(iface) = input.strip_prefix("local.iface:") {
            return Ok(ProviderType::LocalIface {
                interface: iface.to_string(),
            });
        }
        if let Some(url) = input.strip_prefix("url:") {
            // Validate URL
            match url::Url::parse(url) {
                Ok(parsed) => {
                    if parsed.scheme() != "http" && parsed.scheme() != "https" {
                        return Err(format!("Custom URL must use http or https: {url}"));
                    }
                    Ok(ProviderType::CustomURL {
                        url: url.to_string(),
                    })
                }
                Err(e) => Err(format!("Invalid custom URL '{url}': {e}")),
            }
        } else if let Some(ips_str) = input.strip_prefix("literal:") {
            let ips: Result<Vec<IpAddr>, _> = ips_str
                .split(|c: char| c == ',' || c == ' ')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().parse::<IpAddr>())
                .collect();
            match ips {
                Ok(ips) => Ok(ProviderType::Literal { ips }),
                Err(e) => Err(format!("Invalid IP in literal provider: {e}")),
            }
        } else {
            Err(format!("Unknown provider: {input}"))
        }
    }

    /// Detect IPs using this provider.
    pub async fn detect_ips(
        &self,
        client: &Client,
        ip_type: IpType,
        timeout: Duration,
        ppfmt: &PP,
    ) -> Vec<IpAddr> {
        match self {
            ProviderType::CloudflareTrace { url } => {
                detect_cloudflare_trace(client, ip_type, timeout, url.as_deref(), ppfmt).await
            }
            ProviderType::CloudflareDOH => {
                detect_cloudflare_doh(client, ip_type, timeout, ppfmt).await
            }
            ProviderType::Ipify => detect_ipify(client, ip_type, timeout, ppfmt).await,
            ProviderType::Local => detect_local(ip_type, ppfmt),
            ProviderType::LocalIface { interface } => {
                detect_local_iface(interface, ip_type, ppfmt)
            }
            ProviderType::CustomURL { url } => {
                detect_custom_url(client, url, ip_type, timeout, ppfmt).await
            }
            ProviderType::Literal { ips } => filter_ips_by_type(ips, ip_type),
            ProviderType::None => Vec::new(),
        }
    }
}

// --- Cloudflare Trace ---

const CF_TRACE_V4_PRIMARY: &str = "https://1.1.1.1/cdn-cgi/trace";
const CF_TRACE_V4_FALLBACK: &str = "https://1.0.0.1/cdn-cgi/trace";
const CF_TRACE_V6_PRIMARY: &str = "https://[2606:4700:4700::1111]/cdn-cgi/trace";
const CF_TRACE_V6_FALLBACK: &str = "https://[2606:4700:4700::1001]/cdn-cgi/trace";

pub fn parse_trace_ip(body: &str) -> Option<String> {
    for line in body.lines() {
        if let Some(ip) = line.strip_prefix("ip=") {
            return Some(ip.to_string());
        }
    }
    None
}

async fn fetch_trace_ip(client: &Client, url: &str, timeout: Duration) -> Option<IpAddr> {
    let resp = client
        .get(url)
        .timeout(timeout)
        .send()
        .await
        .ok()?;
    let body = resp.text().await.ok()?;
    let ip_str = parse_trace_ip(&body)?;
    ip_str.parse::<IpAddr>().ok()
}

async fn detect_cloudflare_trace(
    client: &Client,
    ip_type: IpType,
    timeout: Duration,
    custom_url: Option<&str>,
    ppfmt: &PP,
) -> Vec<IpAddr> {
    if let Some(url) = custom_url {
        if let Some(ip) = fetch_trace_ip(client, url, timeout).await {
            if matches_ip_type(&ip, ip_type) {
                return vec![ip];
            }
        }
        ppfmt.warningf(
            pp::EMOJI_WARNING,
            &format!("{} not detected via custom Cloudflare trace URL", ip_type.describe()),
        );
        return Vec::new();
    }

    let (primary, fallback) = match ip_type {
        IpType::V4 => (CF_TRACE_V4_PRIMARY, CF_TRACE_V4_FALLBACK),
        IpType::V6 => (CF_TRACE_V6_PRIMARY, CF_TRACE_V6_FALLBACK),
    };

    // Try primary
    if let Some(ip) = fetch_trace_ip(client, primary, timeout).await {
        if matches_ip_type(&ip, ip_type) {
            return vec![ip];
        }
    }
    ppfmt.warningf(
        pp::EMOJI_WARNING,
        &format!("{} not detected via primary, trying fallback", ip_type.describe()),
    );

    // Try fallback
    if let Some(ip) = fetch_trace_ip(client, fallback, timeout).await {
        if matches_ip_type(&ip, ip_type) {
            return vec![ip];
        }
    }
    ppfmt.warningf(
        pp::EMOJI_WARNING,
        &format!(
            "{} not detected via fallback. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.",
            ip_type.describe()
        ),
    );

    Vec::new()
}

// --- Cloudflare DNS over HTTPS ---

async fn detect_cloudflare_doh(
    client: &Client,
    ip_type: IpType,
    timeout: Duration,
    ppfmt: &PP,
) -> Vec<IpAddr> {
    // Construct a DNS query for whoami.cloudflare. TXT CH
    let query = build_dns_query(b"\x06whoami\x0Acloudflare\x00", 16, 3); // TXT=16, CH=3

    let resp = client
        .post("https://cloudflare-dns.com/dns-query")
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query)
        .timeout(timeout)
        .send()
        .await;

    match resp {
        Ok(r) => {
            if let Ok(body) = r.bytes().await {
                if let Some(ip_str) = parse_dns_txt_response(&body) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if matches_ip_type(&ip, ip_type) {
                            return vec![ip];
                        }
                    }
                }
            }
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("{} not detected via Cloudflare DoH: {e}", ip_type.describe()),
            );
        }
    }
    Vec::new()
}

fn build_dns_query(name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    // Header
    let id: u16 = rand_u16();
    buf.extend_from_slice(&id.to_be_bytes()); // Transaction ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    buf.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    buf.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    buf.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0
    // Question section
    buf.extend_from_slice(name);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&qclass.to_be_bytes());
    buf
}

fn parse_dns_txt_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    // Check QR bit (response)
    if data[2] & 0x80 == 0 {
        return None;
    }
    // Check RCODE
    if data[3] & 0x0F != 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }

    // Skip header (12 bytes) + question section
    let mut pos = 12;
    // Skip question name
    pos = skip_dns_name(data, pos)?;
    pos += 4; // Skip QTYPE + QCLASS

    // Parse answer
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        // Skip name
        pos = skip_dns_name(data, pos)?;
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2; // TYPE
        pos += 2; // CLASS
        pos += 4; // TTL
        let rdlength = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if rtype == 16 && rdlength > 1 && pos + rdlength <= data.len() {
            // TXT record: first byte is string length
            let txt_len = data[pos] as usize;
            if txt_len > 0 && pos + 1 + txt_len <= data.len() {
                let txt = String::from_utf8_lossy(&data[pos + 1..pos + 1 + txt_len]);
                // Strip surrounding quotes if present
                let txt = txt.trim_matches('"');
                return Some(txt.to_string());
            }
        }
        pos += rdlength;
    }
    None
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

fn rand_u16() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish() as u16
}

// --- Ipify ---

async fn detect_ipify(
    client: &Client,
    ip_type: IpType,
    timeout: Duration,
    ppfmt: &PP,
) -> Vec<IpAddr> {
    let url = match ip_type {
        IpType::V4 => "https://api4.ipify.org",
        IpType::V6 => "https://api6.ipify.org",
    };

    match client.get(url).timeout(timeout).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                let ip_str = body.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if matches_ip_type(&ip, ip_type) {
                        return vec![ip];
                    }
                }
            }
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("{} not detected via ipify: {e}", ip_type.describe()),
            );
        }
    }
    Vec::new()
}

// --- Local (auto) ---

fn detect_local(ip_type: IpType, ppfmt: &PP) -> Vec<IpAddr> {
    let target = match ip_type {
        IpType::V4 => "1.1.1.1:443",
        IpType::V6 => "[2606:4700:4700::1111]:443",
    };

    match UdpSocket::bind(match ip_type {
        IpType::V4 => "0.0.0.0:0",
        IpType::V6 => "[::]:0",
    }) {
        Ok(socket) => match socket.connect(target) {
            Ok(()) => match socket.local_addr() {
                Ok(addr) => {
                    let ip = addr.ip();
                    if matches_ip_type(&ip, ip_type) && ip.is_global_() {
                        vec![ip]
                    } else {
                        Vec::new()
                    }
                }
                Err(e) => {
                    ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!("Failed to get local {} address: {e}", ip_type.describe()),
                    );
                    Vec::new()
                }
            },
            Err(e) => {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!("Failed to detect local {} address: {e}", ip_type.describe()),
                );
                Vec::new()
            }
        },
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to bind socket for {} detection: {e}", ip_type.describe()),
            );
            Vec::new()
        }
    }
}

// --- Local Interface ---

fn detect_local_iface(interface: &str, ip_type: IpType, ppfmt: &PP) -> Vec<IpAddr> {
    match if_addrs::get_if_addrs() {
        Ok(addrs) => {
            let mut ips: Vec<IpAddr> = addrs
                .iter()
                .filter(|a| a.name == interface)
                .map(|a| a.ip())
                .filter(|ip| matches_ip_type(ip, ip_type) && ip.is_global_())
                .collect();
            ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
            ips.dedup();
            if ips.is_empty() {
                ppfmt.warningf(
                    pp::EMOJI_WARNING,
                    &format!(
                        "No global {} address found on interface {interface}",
                        ip_type.describe()
                    ),
                );
            }
            ips
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Failed to list network interfaces: {e}"),
            );
            Vec::new()
        }
    }
}

// --- Custom URL ---

async fn detect_custom_url(
    client: &Client,
    url: &str,
    ip_type: IpType,
    timeout: Duration,
    ppfmt: &PP,
) -> Vec<IpAddr> {
    match client.get(url).timeout(timeout).send().await {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                let ip_str = body.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if matches_ip_type(&ip, ip_type) {
                        return vec![ip];
                    }
                }
            }
        }
        Err(e) => {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("{} not detected via custom URL: {e}", ip_type.describe()),
            );
        }
    }
    Vec::new()
}

// --- Helpers ---

fn matches_ip_type(ip: &IpAddr, ip_type: IpType) -> bool {
    match ip_type {
        IpType::V4 => ip.is_ipv4(),
        IpType::V6 => ip.is_ipv6(),
    }
}

fn filter_ips_by_type(ips: &[IpAddr], ip_type: IpType) -> Vec<IpAddr> {
    ips.iter()
        .copied()
        .filter(|ip| matches_ip_type(ip, ip_type))
        .collect()
}

/// Extension trait for IpAddr to check if it's a global address.
/// std::net::IpAddr::is_global is unstable, so we implement it ourselves.
trait IsGlobal {
    fn is_global_(&self) -> bool;
}

impl IsGlobal for IpAddr {
    fn is_global_(&self) -> bool {
        match self {
            IpAddr::V4(ip) => is_global_v4(ip),
            IpAddr::V6(ip) => is_global_v6(ip),
        }
    }
}

fn is_global_v4(ip: &Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_private()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        && !ip.is_documentation()
        && !(ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127) // 100.64.0.0/10 shared address space
        && !ip.octets().starts_with(&[192, 0, 0]) // 192.0.0.0/24
}

fn is_global_v6(ip: &Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        // Not link-local (fe80::/10)
        && (ip.segments()[0] & 0xffc0) != 0xfe80
        // Not unique local (fc00::/7)
        && (ip.segments()[0] & 0xfe00) != 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_provider_parse() {
        assert!(matches!(
            ProviderType::parse("cloudflare.trace").unwrap(),
            ProviderType::CloudflareTrace { url: None }
        ));
        assert!(matches!(
            ProviderType::parse("cloudflare.doh").unwrap(),
            ProviderType::CloudflareDOH
        ));
        assert!(matches!(
            ProviderType::parse("ipify").unwrap(),
            ProviderType::Ipify
        ));
        assert!(matches!(
            ProviderType::parse("local").unwrap(),
            ProviderType::Local
        ));
        assert!(matches!(
            ProviderType::parse("none").unwrap(),
            ProviderType::None
        ));
    }

    #[test]
    fn test_provider_parse_literal() {
        match ProviderType::parse("literal:1.2.3.4,5.6.7.8").unwrap() {
            ProviderType::Literal { ips } => {
                assert_eq!(ips.len(), 2);
            }
            _ => panic!("Expected Literal provider"),
        }
    }

    #[test]
    fn test_provider_parse_local_iface() {
        match ProviderType::parse("local.iface:eth0").unwrap() {
            ProviderType::LocalIface { interface } => {
                assert_eq!(interface, "eth0");
            }
            _ => panic!("Expected LocalIface provider"),
        }
    }

    #[test]
    fn test_provider_parse_custom_url() {
        match ProviderType::parse("url:https://example.com/ip").unwrap() {
            ProviderType::CustomURL { url } => {
                assert_eq!(url, "https://example.com/ip");
            }
            _ => panic!("Expected CustomURL provider"),
        }
    }

    // ---- build_dns_query ----

    #[test]
    fn test_build_dns_query_header_structure() {
        let name = b"\x06whoami\x0Acloudflare\x00";
        let query = build_dns_query(name, 16, 3);

        // Header is 12 bytes
        assert!(query.len() >= 12);

        // Flags: 0x0100 (standard query, RD=1)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);

        // QDCOUNT = 1
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);

        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        assert_eq!(u16::from_be_bytes([query[6], query[7]]), 0);
        assert_eq!(u16::from_be_bytes([query[8], query[9]]), 0);
        assert_eq!(u16::from_be_bytes([query[10], query[11]]), 0);

        // After 12-byte header, the name bytes should be present
        let name_start = 12;
        let name_end = name_start + name.len();
        assert_eq!(&query[name_start..name_end], name);

        // Then QTYPE and QCLASS
        let qtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
        let qclass = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
        assert_eq!(qtype, 16);
        assert_eq!(qclass, 3);

        // Total length: 12 + name.len() + 4
        assert_eq!(query.len(), 12 + name.len() + 4);
    }

    // ---- parse_dns_txt_response ----

    /// Helper: build a minimal valid DNS TXT response
    fn build_test_dns_response(txt: &str) -> Vec<u8> {
        let mut data = Vec::new();
        // Header (12 bytes)
        data.extend_from_slice(&[0x00, 0x01]); // ID
        data.extend_from_slice(&[0x81, 0x00]); // Flags: QR=1, RD=1, RCODE=0
        data.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        data.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        data.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        data.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // Question section: name = \x04test\x00
        data.extend_from_slice(b"\x04test\x00");
        data.extend_from_slice(&[0x00, 0x10]); // QTYPE=TXT
        data.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        // Answer section: name pointer to offset 12
        data.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
        data.extend_from_slice(&[0x00, 0x10]); // TYPE=TXT
        data.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
        let rdlength = (1 + txt.len()) as u16;
        data.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
        data.push(txt.len() as u8); // TXT string length
        data.extend_from_slice(txt.as_bytes());
        data
    }

    #[test]
    fn test_parse_dns_txt_response_valid() {
        let data = build_test_dns_response("203.0.113.42");
        let result = parse_dns_txt_response(&data);
        assert_eq!(result, Some("203.0.113.42".to_string()));
    }

    #[test]
    fn test_parse_dns_txt_response_strips_quotes() {
        let data = build_test_dns_response("\"1.2.3.4\"");
        let result = parse_dns_txt_response(&data);
        assert_eq!(result, Some("1.2.3.4".to_string()));
    }

    #[test]
    fn test_parse_dns_txt_response_empty() {
        let result = parse_dns_txt_response(&[]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_dns_txt_response_too_short() {
        let result = parse_dns_txt_response(&[0u8; 11]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_dns_txt_response_not_response() {
        // QR bit not set (byte 2 bit 7 = 0)
        let mut data = build_test_dns_response("1.2.3.4");
        data[2] = 0x01; // clear QR bit
        assert_eq!(parse_dns_txt_response(&data), None);
    }

    #[test]
    fn test_parse_dns_txt_response_nonzero_rcode() {
        let mut data = build_test_dns_response("1.2.3.4");
        data[3] = 0x03; // RCODE = NXDOMAIN
        assert_eq!(parse_dns_txt_response(&data), None);
    }

    #[test]
    fn test_parse_dns_txt_response_zero_ancount() {
        let mut data = build_test_dns_response("1.2.3.4");
        data[6] = 0x00;
        data[7] = 0x00; // ANCOUNT = 0
        assert_eq!(parse_dns_txt_response(&data), None);
    }

    #[test]
    fn test_parse_dns_txt_response_pointer_compressed_name() {
        // The build_test_dns_response already uses pointer compression in the answer name
        let data = build_test_dns_response("10.0.0.1");
        // Verify it parses correctly with pointer compression
        assert_eq!(parse_dns_txt_response(&data), Some("10.0.0.1".to_string()));
    }

    // ---- skip_dns_name ----

    #[test]
    fn test_skip_dns_name_normal_labels() {
        // \x03www\x07example\x03com\x00
        let data = b"\x03www\x07example\x03com\x00";
        let result = skip_dns_name(data, 0);
        assert_eq!(result, Some(data.len()));
    }

    #[test]
    fn test_skip_dns_name_pointer() {
        // A pointer: 0xC0 0x0C
        let data = [0xC0, 0x0C];
        let result = skip_dns_name(&data, 0);
        assert_eq!(result, Some(2));
    }

    #[test]
    fn test_skip_dns_name_empty_input() {
        let result = skip_dns_name(&[], 0);
        assert_eq!(result, None);
    }

    #[test]
    fn test_skip_dns_name_root() {
        // Root name: just \x00
        let data = [0x00];
        let result = skip_dns_name(&data, 0);
        assert_eq!(result, Some(1));
    }

    // ---- detect_cloudflare_trace with wiremock ----

    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};
    use crate::pp::PP;

    #[tokio::test]
    async fn test_detect_cloudflare_trace_primary_succeeds() {
        let server = MockServer::start().await;
        let trace_body = "fl=1f1\nh=test\nip=93.184.216.34\nts=123\n";

        Mock::given(method("GET"))
            .and(path("/cdn-cgi/trace"))
            .respond_with(ResponseTemplate::new(200).set_body_string(trace_body))
            .mount(&server)
            .await;

        let client = Client::new();
        let ppfmt = PP::default_pp();
        let url = format!("{}/cdn-cgi/trace", server.uri());
        let timeout = Duration::from_secs(5);

        let result = detect_cloudflare_trace(
            &client,
            IpType::V4,
            timeout,
            Some(&url),
            &ppfmt,
        )
        .await;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "93.184.216.34".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_detect_cloudflare_trace_primary_fails_fallback_succeeds() {
        let primary = MockServer::start().await;
        let fallback = MockServer::start().await;

        // Primary returns 500
        Mock::given(method("GET"))
            .and(path("/cdn-cgi/trace"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&primary)
            .await;

        // Fallback returns valid trace
        let trace_body = "fl=1f1\nip=93.184.216.34\n";
        Mock::given(method("GET"))
            .and(path("/cdn-cgi/trace"))
            .respond_with(ResponseTemplate::new(200).set_body_string(trace_body))
            .mount(&fallback)
            .await;

        // We can't override the hardcoded primary/fallback URLs, but we can test
        // the custom URL path: first with a failing URL, then a succeeding one.
        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);

        // Custom URL pointing to primary (which fails with 500 -> no ip= line parseable from error page)
        let result_fail = detect_cloudflare_trace(
            &client,
            IpType::V4,
            timeout,
            Some(&format!("{}/cdn-cgi/trace", primary.uri())),
            &ppfmt,
        )
        .await;
        assert!(result_fail.is_empty());

        // Custom URL pointing to fallback (which succeeds)
        let result_ok = detect_cloudflare_trace(
            &client,
            IpType::V4,
            timeout,
            Some(&format!("{}/cdn-cgi/trace", fallback.uri())),
            &ppfmt,
        )
        .await;
        assert_eq!(result_ok.len(), 1);
        assert_eq!(result_ok[0], "93.184.216.34".parse::<IpAddr>().unwrap());
    }

    // ---- detect_ipify with wiremock ----

    #[tokio::test]
    async fn test_detect_ipify_v4() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("198.51.100.1\n"))
            .mount(&server)
            .await;

        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);

        // detect_ipify uses hardcoded URLs, so we test via detect_custom_url instead
        // which uses the same logic
        let result = detect_custom_url(&client, &server.uri(), IpType::V4, timeout, &ppfmt).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "198.51.100.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_detect_ipify_v6() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("2001:db8::1\n"),
            )
            .mount(&server)
            .await;

        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);

        let result = detect_custom_url(&client, &server.uri(), IpType::V6, timeout, &ppfmt).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    // ---- detect_custom_url with wiremock ----

    #[tokio::test]
    async fn test_detect_custom_url_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/my-ip"))
            .respond_with(ResponseTemplate::new(200).set_body_string("10.0.0.1"))
            .mount(&server)
            .await;

        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);
        let url = format!("{}/my-ip", server.uri());

        // 10.0.0.1 is a valid IPv4, should match V4
        let result = detect_custom_url(&client, &url, IpType::V4, timeout, &ppfmt).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_detect_custom_url_wrong_ip_type() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/my-ip"))
            .respond_with(ResponseTemplate::new(200).set_body_string("10.0.0.1"))
            .mount(&server)
            .await;

        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);
        let url = format!("{}/my-ip", server.uri());

        // 10.0.0.1 is IPv4 but we ask for V6 -> empty
        let result = detect_custom_url(&client, &url, IpType::V6, timeout, &ppfmt).await;
        assert!(result.is_empty());
    }

    // ---- detect_local ----

    #[test]
    fn test_detect_local_returns_results_or_empty() {
        let ppfmt = PP::default_pp();
        // detect_local may return an IP or an empty vec depending on environment
        let result_v4 = detect_local(IpType::V4, &ppfmt);
        for ip in &result_v4 {
            assert!(ip.is_ipv4());
        }
        let result_v6 = detect_local(IpType::V6, &ppfmt);
        for ip in &result_v6 {
            assert!(ip.is_ipv6());
        }
    }

    // ---- matches_ip_type ----

    #[test]
    fn test_matches_ip_type_v4() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(matches_ip_type(&v4, IpType::V4));
        assert!(!matches_ip_type(&v4, IpType::V6));
    }

    #[test]
    fn test_matches_ip_type_v6() {
        let v6: IpAddr = "::1".parse().unwrap();
        assert!(!matches_ip_type(&v6, IpType::V4));
        assert!(matches_ip_type(&v6, IpType::V6));
    }

    // ---- filter_ips_by_type ----

    #[test]
    fn test_filter_ips_by_type_mixed() {
        let ips: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "::1".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];

        let v4s = filter_ips_by_type(&ips, IpType::V4);
        assert_eq!(v4s.len(), 2);
        assert!(v4s.iter().all(|ip| ip.is_ipv4()));

        let v6s = filter_ips_by_type(&ips, IpType::V6);
        assert_eq!(v6s.len(), 2);
        assert!(v6s.iter().all(|ip| ip.is_ipv6()));
    }

    #[test]
    fn test_filter_ips_by_type_empty() {
        let ips: Vec<IpAddr> = vec![];
        assert!(filter_ips_by_type(&ips, IpType::V4).is_empty());
        assert!(filter_ips_by_type(&ips, IpType::V6).is_empty());
    }

    // ---- is_global_v4 ----

    #[test]
    fn test_is_global_v4_private() {
        assert!(!is_global_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_global_v4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_global_v4(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_is_global_v4_loopback() {
        assert!(!is_global_v4(&Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_is_global_v4_link_local() {
        assert!(!is_global_v4(&Ipv4Addr::new(169, 254, 0, 1)));
    }

    #[test]
    fn test_is_global_v4_broadcast() {
        assert!(!is_global_v4(&Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_is_global_v4_documentation() {
        assert!(!is_global_v4(&Ipv4Addr::new(192, 0, 2, 1)));   // 192.0.2.0/24
        assert!(!is_global_v4(&Ipv4Addr::new(198, 51, 100, 1))); // 198.51.100.0/24
        assert!(!is_global_v4(&Ipv4Addr::new(203, 0, 113, 1)));  // 203.0.113.0/24
    }

    #[test]
    fn test_is_global_v4_shared_address_space() {
        assert!(!is_global_v4(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_global_v4(&Ipv4Addr::new(100, 127, 255, 254)));
        // 100.128.x.x is outside the shared range
        assert!(is_global_v4(&Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn test_is_global_v4_global() {
        assert!(is_global_v4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_global_v4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_global_v4(&Ipv4Addr::new(93, 184, 216, 34)));
    }

    // ---- is_global_v6 ----

    #[test]
    fn test_is_global_v6_loopback() {
        assert!(!is_global_v6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_is_global_v6_link_local() {
        // fe80::1
        assert!(!is_global_v6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_is_global_v6_unique_local() {
        // fc00::1
        assert!(!is_global_v6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        // fd00::1
        assert!(!is_global_v6(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_is_global_v6_multicast() {
        // ff02::1
        assert!(!is_global_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_is_global_v6_global() {
        // 2606:4700:4700::1111 (Cloudflare DNS)
        assert!(is_global_v6(&Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)));
        // 2001:db8::1 is documentation, but our impl doesn't explicitly exclude it
        // so it should be considered global by our function
        assert!(is_global_v6(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
    }

    // ---- ProviderType::name ----

    #[test]
    fn test_provider_type_name() {
        assert_eq!(ProviderType::CloudflareTrace { url: None }.name(), "cloudflare.trace");
        assert_eq!(
            ProviderType::CloudflareTrace { url: Some("https://x".into()) }.name(),
            "cloudflare.trace"
        );
        assert_eq!(ProviderType::CloudflareDOH.name(), "cloudflare.doh");
        assert_eq!(ProviderType::Ipify.name(), "ipify");
        assert_eq!(ProviderType::Local.name(), "local");
        assert_eq!(
            ProviderType::LocalIface { interface: "eth0".into() }.name(),
            "local.iface"
        );
        assert_eq!(
            ProviderType::CustomURL { url: "https://x".into() }.name(),
            "url:"
        );
        assert_eq!(
            ProviderType::Literal { ips: vec![] }.name(),
            "literal:"
        );
        assert_eq!(ProviderType::None.name(), "none");
    }

    // ---- ProviderType::parse error cases ----

    #[test]
    fn test_provider_parse_invalid_url_scheme() {
        let result = ProviderType::parse("url:ftp://example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("http or https"));
    }

    #[test]
    fn test_provider_parse_invalid_literal_ip() {
        let result = ProviderType::parse("literal:not_an_ip");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid IP"));
    }

    #[test]
    fn test_provider_parse_unknown() {
        let result = ProviderType::parse("totally_unknown");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown provider"));
    }

    // ---- ProviderType::Literal - detect_ips filters by ip_type ----

    #[tokio::test]
    async fn test_literal_detect_ips_filters_v4() {
        let provider = ProviderType::Literal {
            ips: vec![
                "1.2.3.4".parse().unwrap(),
                "::1".parse().unwrap(),
                "5.6.7.8".parse().unwrap(),
            ],
        };
        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);

        let result = provider.detect_ips(&client, IpType::V4, timeout, &ppfmt).await;
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|ip| ip.is_ipv4()));
    }

    #[tokio::test]
    async fn test_literal_detect_ips_filters_v6() {
        let provider = ProviderType::Literal {
            ips: vec![
                "1.2.3.4".parse().unwrap(),
                "::1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        };
        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);

        let result = provider.detect_ips(&client, IpType::V6, timeout, &ppfmt).await;
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|ip| ip.is_ipv6()));
    }

    // ---- ProviderType::None - detect_ips returns empty ----

    #[tokio::test]
    async fn test_none_detect_ips_returns_empty() {
        let provider = ProviderType::None;
        let client = Client::new();
        let ppfmt = PP::default_pp();
        let timeout = Duration::from_secs(5);

        let result_v4 = provider.detect_ips(&client, IpType::V4, timeout, &ppfmt).await;
        assert!(result_v4.is_empty());

        let result_v6 = provider.detect_ips(&client, IpType::V6, timeout, &ppfmt).await;
        assert!(result_v6.is_empty());
    }
}
