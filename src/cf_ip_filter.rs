use crate::pp::{self, PP};
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;

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

        for url in [CF_IPV4_URL, CF_IPV6_URL] {
            match client.get(url).timeout(timeout).send().await {
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
}
