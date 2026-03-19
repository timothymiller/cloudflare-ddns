use crate::pp::{self, PP};
use reqwest::Client;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const CF_IPV4_URL: &str = "https://www.cloudflare.com/ips-v4";
const CF_IPV6_URL: &str = "https://www.cloudflare.com/ips-v6";

/// A CIDR range parsed from "address/prefix" notation.
struct CidrRange {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    fn parse(s: &str) -> Option<Self> {
        let (addr_str, prefix_str) = s.split_once('/')?;
        let addr: IpAddr = addr_str.parse().ok()?;
        let prefix_len: u8 = prefix_str.parse().ok()?;
        match addr {
            IpAddr::V4(_) if prefix_len > 32 => None,
            IpAddr::V6(_) if prefix_len > 128 => None,
            _ => Some(Self { addr, prefix_len }),
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let net_bits = u32::from(net);
                let ip_bits = u32::from(*ip);
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - self.prefix_len);
                (net_bits & mask) == (ip_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net_bits = u128::from(net);
                let ip_bits = u128::from(*ip);
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - self.prefix_len);
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false,
        }
    }
}

/// Holds parsed Cloudflare CIDR ranges for IP filtering.
pub struct CloudflareIpFilter {
    ranges: Vec<CidrRange>,
}

impl CloudflareIpFilter {
    /// Fetch Cloudflare IP ranges from their published URLs and parse them.
    pub async fn fetch(client: &Client, timeout: Duration, ppfmt: &PP) -> Option<Self> {
        let mut ranges = Vec::new();

        let (v4_result, v6_result) = tokio::join!(
            client.get(CF_IPV4_URL).timeout(timeout).send(),
            client.get(CF_IPV6_URL).timeout(timeout).send(),
        );

        for (url, result) in [(CF_IPV4_URL, v4_result), (CF_IPV6_URL, v6_result)] {
            match result {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(body) => {
                        for line in body.lines() {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            match CidrRange::parse(line) {
                                Some(range) => ranges.push(range),
                                None => {
                                    ppfmt.warningf(
                                        pp::EMOJI_WARNING,
                                        &format!(
                                            "Failed to parse Cloudflare IP range '{line}'"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        ppfmt.warningf(
                            pp::EMOJI_WARNING,
                            &format!("Failed to read Cloudflare IP ranges from {url}: {e}"),
                        );
                        return None;
                    }
                },
                Ok(resp) => {
                    ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!(
                            "Failed to fetch Cloudflare IP ranges from {url}: HTTP {}",
                            resp.status()
                        ),
                    );
                    return None;
                }
                Err(e) => {
                    ppfmt.warningf(
                        pp::EMOJI_WARNING,
                        &format!("Failed to fetch Cloudflare IP ranges from {url}: {e}"),
                    );
                    return None;
                }
            }
        }

        if ranges.is_empty() {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                "No Cloudflare IP ranges loaded; skipping filter",
            );
            return None;
        }

        ppfmt.infof(
            pp::EMOJI_DETECT,
            &format!("Loaded {} Cloudflare IP ranges for filtering", ranges.len()),
        );

        Some(Self { ranges })
    }

    /// Parse ranges from raw text lines (for testing).
    #[cfg(test)]
    pub fn from_lines(lines: &str) -> Option<Self> {
        let ranges: Vec<CidrRange> = lines
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() {
                    None
                } else {
                    CidrRange::parse(l)
                }
            })
            .collect();
        if ranges.is_empty() {
            None
        } else {
            Some(Self { ranges })
        }
    }

    /// Check if an IP address falls within any Cloudflare range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ranges.iter().any(|net| net.contains(ip))
    }
}

/// Refresh interval for Cloudflare IP ranges (24 hours).
const CF_RANGE_REFRESH: Duration = Duration::from_secs(24 * 60 * 60);

/// Cached wrapper around [`CloudflareIpFilter`].
///
/// Fetches once, then re-uses the cached ranges for [`CF_RANGE_REFRESH`].
/// If a refresh fails, the previously cached ranges are kept.
pub struct CachedCloudflareFilter {
    filter: Option<CloudflareIpFilter>,
    fetched_at: Option<Instant>,
}

impl CachedCloudflareFilter {
    pub fn new() -> Self {
        Self {
            filter: None,
            fetched_at: None,
        }
    }

    /// Return a reference to the current filter, refreshing if stale or absent.
    pub async fn get(
        &mut self,
        client: &Client,
        timeout: Duration,
        ppfmt: &PP,
    ) -> Option<&CloudflareIpFilter> {
        let stale = match self.fetched_at {
            Some(t) => t.elapsed() >= CF_RANGE_REFRESH,
            None => true,
        };

        if stale {
            match CloudflareIpFilter::fetch(client, timeout, ppfmt).await {
                Some(new_filter) => {
                    self.filter = Some(new_filter);
                    self.fetched_at = Some(Instant::now());
                }
                None => {
                    if self.filter.is_some() {
                        ppfmt.warningf(
                            pp::EMOJI_WARNING,
                            "Failed to refresh Cloudflare IP ranges; using cached version",
                        );
                        // Keep using cached filter, but don't update fetched_at
                        // so we retry next cycle.
                    }
                    // If no cached filter exists, return None (caller handles fail-safe).
                }
            }
        }

        self.filter.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SAMPLE_RANGES: &str = "\
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
104.16.0.0/13
2400:cb00::/32
2606:4700::/32
";

    #[test]
    fn test_parse_ranges() {
        let filter = CloudflareIpFilter::from_lines(SAMPLE_RANGES).unwrap();
        assert_eq!(filter.ranges.len(), 6);
    }

    #[test]
    fn test_contains_cloudflare_ipv4() {
        let filter = CloudflareIpFilter::from_lines(SAMPLE_RANGES).unwrap();
        // 104.16.0.1 is within 104.16.0.0/13
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1));
        assert!(filter.contains(&ip));
    }

    #[test]
    fn test_rejects_non_cloudflare_ipv4() {
        let filter = CloudflareIpFilter::from_lines(SAMPLE_RANGES).unwrap();
        // 203.0.113.42 is a documentation IP, not Cloudflare
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        assert!(!filter.contains(&ip));
    }

    #[test]
    fn test_contains_cloudflare_ipv6() {
        let filter = CloudflareIpFilter::from_lines(SAMPLE_RANGES).unwrap();
        // 2606:4700::1 is within 2606:4700::/32
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        assert!(filter.contains(&ip));
    }

    #[test]
    fn test_rejects_non_cloudflare_ipv6() {
        let filter = CloudflareIpFilter::from_lines(SAMPLE_RANGES).unwrap();
        // 2001:db8::1 is a documentation address, not Cloudflare
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(!filter.contains(&ip));
    }

    #[test]
    fn test_empty_input() {
        assert!(CloudflareIpFilter::from_lines("").is_none());
        assert!(CloudflareIpFilter::from_lines("  \n  \n").is_none());
    }

    #[test]
    fn test_edge_of_range() {
        let filter = CloudflareIpFilter::from_lines("104.16.0.0/13").unwrap();
        // First IP in range
        assert!(filter.contains(&IpAddr::V4(Ipv4Addr::new(104, 16, 0, 0))));
        // Last IP in range (104.23.255.255)
        assert!(filter.contains(&IpAddr::V4(Ipv4Addr::new(104, 23, 255, 255))));
        // Just outside range (104.24.0.0)
        assert!(!filter.contains(&IpAddr::V4(Ipv4Addr::new(104, 24, 0, 0))));
    }

    #[test]
    fn test_invalid_prefix_rejected() {
        assert!(CidrRange::parse("10.0.0.0/33").is_none());
        assert!(CidrRange::parse("::1/129").is_none());
        assert!(CidrRange::parse("not-an-ip/24").is_none());
    }

    #[test]
    fn test_v4_does_not_match_v6() {
        let filter = CloudflareIpFilter::from_lines("104.16.0.0/13").unwrap();
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        assert!(!filter.contains(&ip));
    }

    /// All real Cloudflare ranges as of 2026-03. Verifies every range parses
    /// and that the first and last IP in each range is matched while the
    /// address just past the end is not.
    const ALL_CF_RANGES: &str = "\
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
";

    #[test]
    fn test_all_real_ranges_parse() {
        let filter = CloudflareIpFilter::from_lines(ALL_CF_RANGES).unwrap();
        assert_eq!(filter.ranges.len(), 22);
    }

    /// For a /N IPv4 range starting at `base`, return (first, last, just_outside).
    fn v4_range_bounds(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> (Ipv4Addr, Ipv4Addr, Ipv4Addr) {
        let base = u32::from(Ipv4Addr::new(a, b, c, d));
        let size = 1u32 << (32 - prefix);
        let first = Ipv4Addr::from(base);
        let last = Ipv4Addr::from(base + size - 1);
        let outside = Ipv4Addr::from(base + size);
        (first, last, outside)
    }

    #[test]
    fn test_all_real_ipv4_ranges_match() {
        // Test each range individually so adjacent ranges (e.g. 104.16.0.0/13
        // and 104.24.0.0/14) don't cause false failures on boundary checks.
        let ranges: &[(u8, u8, u8, u8, u8)] = &[
            (173, 245, 48, 0, 20),
            (103, 21, 244, 0, 22),
            (103, 22, 200, 0, 22),
            (103, 31, 4, 0, 22),
            (141, 101, 64, 0, 18),
            (108, 162, 192, 0, 18),
            (190, 93, 240, 0, 20),
            (188, 114, 96, 0, 20),
            (197, 234, 240, 0, 22),
            (198, 41, 128, 0, 17),
            (162, 158, 0, 0, 15),
            (104, 16, 0, 0, 13),
            (104, 24, 0, 0, 14),
            (172, 64, 0, 0, 13),
            (131, 0, 72, 0, 22),
        ];

        for &(a, b, c, d, prefix) in ranges {
            let cidr = format!("{a}.{b}.{c}.{d}/{prefix}");
            let filter = CloudflareIpFilter::from_lines(&cidr).unwrap();
            let (first, last, outside) = v4_range_bounds(a, b, c, d, prefix);
            assert!(
                filter.contains(&IpAddr::V4(first)),
                "First IP {first} should be in {cidr}"
            );
            assert!(
                filter.contains(&IpAddr::V4(last)),
                "Last IP {last} should be in {cidr}"
            );
            assert!(
                !filter.contains(&IpAddr::V4(outside)),
                "IP {outside} should NOT be in {cidr}"
            );
        }
    }

    #[test]
    fn test_all_real_ipv6_ranges_match() {
        let filter = CloudflareIpFilter::from_lines(ALL_CF_RANGES).unwrap();

        // (base high 16-bit segment, prefix len)
        let ranges: &[(u16, u16, u8)] = &[
            (0x2400, 0xcb00, 32),
            (0x2606, 0x4700, 32),
            (0x2803, 0xf800, 32),
            (0x2405, 0xb500, 32),
            (0x2405, 0x8100, 32),
            (0x2a06, 0x98c0, 29),
            (0x2c0f, 0xf248, 32),
        ];

        for &(seg0, seg1, prefix) in ranges {
            let base = u128::from(Ipv6Addr::new(seg0, seg1, 0, 0, 0, 0, 0, 0));
            let size = 1u128 << (128 - prefix);

            let first = Ipv6Addr::from(base);
            let last = Ipv6Addr::from(base + size - 1);
            let outside = Ipv6Addr::from(base + size);

            assert!(
                filter.contains(&IpAddr::V6(first)),
                "First IP {first} should be in {seg0:x}:{seg1:x}::/{prefix}"
            );
            assert!(
                filter.contains(&IpAddr::V6(last)),
                "Last IP {last} should be in {seg0:x}:{seg1:x}::/{prefix}"
            );
            assert!(
                !filter.contains(&IpAddr::V6(outside)),
                "IP {outside} should NOT be in {seg0:x}:{seg1:x}::/{prefix}"
            );
        }
    }
}
