use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum AllowEntry {
    Domain(String),
    Ip(IpAddr),
    Cidr(IpAddr, u8),
}

pub struct Whitelist {
    domains: Vec<String>,
    ips: HashSet<IpAddr>,
    cidrs: Vec<CidrEntry>,
    resolved_ips: HashSet<IpAddr>,
}

#[derive(Clone)]
struct CidrEntry {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrEntry {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - self.prefix_len);
                u32::from(target) & mask == u32::from(net) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net = u128::from(net);
                let target = u128::from(target);
                let mask = !0u128 << (128 - self.prefix_len);
                target & mask == net & mask
            }
            _ => false, // v4 CIDR doesn't match v6 address and vice versa
        }
    }
}

impl Whitelist {
    pub fn new(entries: Vec<AllowEntry>) -> Self {
        let mut wl = Whitelist {
            domains: Vec::new(),
            ips: HashSet::new(),
            cidrs: Vec::new(),
            resolved_ips: HashSet::new(),
        };
        for entry in entries {
            match entry {
                AllowEntry::Domain(d) => wl.domains.push(d),
                AllowEntry::Ip(ip) => {
                    wl.ips.insert(ip);
                }
                AllowEntry::Cidr(addr, prefix_len) => {
                    wl.cidrs.push(CidrEntry { addr, prefix_len });
                }
            }
        }
        wl
    }

    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        for d in &self.domains {
            if d == domain {
                return true;
            }
            if domain.ends_with(&format!(".{d}")) {
                return true;
            }
        }
        false
    }

    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        if self.ips.contains(&ip) {
            return true;
        }
        if self.resolved_ips.contains(&ip) {
            return true;
        }
        for cidr in &self.cidrs {
            if cidr.contains(ip) {
                return true;
            }
        }
        false
    }

    pub fn add_resolved_ip(&mut self, ip: IpAddr) {
        self.resolved_ips.insert(ip);
    }
}

pub fn parse_allow_entry(s: &str) -> AllowEntry {
    // Try CIDR notation
    if let Some((addr_str, prefix_str)) = s.split_once('/')
        && let (Ok(addr), Ok(prefix)) = (addr_str.parse::<IpAddr>(), prefix_str.parse::<u8>())
    {
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix <= max_prefix {
            return AllowEntry::Cidr(addr, prefix);
        }
    }
    // Try plain IP (v4 or v6)
    if let Ok(ip) = s.parse::<IpAddr>() {
        return AllowEntry::Ip(ip);
    }
    // Otherwise it's a domain
    AllowEntry::Domain(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -- parse_allow_entry --

    #[test]
    fn parse_entry_domain() {
        assert!(
            matches!(parse_allow_entry("example.com"), AllowEntry::Domain(d) if d == "example.com")
        );
    }

    #[test]
    fn parse_entry_ipv4() {
        assert!(
            matches!(parse_allow_entry("1.2.3.4"), AllowEntry::Ip(IpAddr::V4(ip)) if ip == Ipv4Addr::new(1,2,3,4))
        );
    }

    #[test]
    fn parse_entry_ipv6() {
        assert!(matches!(
            parse_allow_entry("::1"),
            AllowEntry::Ip(IpAddr::V6(_))
        ));
        assert!(matches!(
            parse_allow_entry("2001:db8::1"),
            AllowEntry::Ip(IpAddr::V6(_))
        ));
    }

    #[test]
    fn parse_entry_cidr_v4() {
        assert!(matches!(
            parse_allow_entry("10.0.0.0/8"),
            AllowEntry::Cidr(IpAddr::V4(_), 8)
        ));
        assert!(matches!(
            parse_allow_entry("0.0.0.0/0"),
            AllowEntry::Cidr(IpAddr::V4(_), 0)
        ));
    }

    #[test]
    fn parse_entry_cidr_v6() {
        assert!(matches!(
            parse_allow_entry("fd00::/64"),
            AllowEntry::Cidr(IpAddr::V6(_), 64)
        ));
        assert!(matches!(
            parse_allow_entry("2001:db8::/32"),
            AllowEntry::Cidr(IpAddr::V6(_), 32)
        ));
        assert!(matches!(
            parse_allow_entry("::/0"),
            AllowEntry::Cidr(IpAddr::V6(_), 0)
        ));
    }

    #[test]
    fn parse_entry_invalid_cidr_falls_back_to_domain() {
        assert!(matches!(
            parse_allow_entry("10.0.0.0/33"),
            AllowEntry::Domain(_)
        ));
        assert!(matches!(
            parse_allow_entry("::1/129"),
            AllowEntry::Domain(_)
        ));
    }

    // -- domain matching --

    #[test]
    fn domain_exact_match() {
        let wl = Whitelist::new(vec![AllowEntry::Domain("example.com".into())]);
        assert!(wl.is_domain_allowed("example.com"));
        assert!(!wl.is_domain_allowed("notexample.com"));
        assert!(!wl.is_domain_allowed("example.org"));
    }

    #[test]
    fn domain_subdomain_match() {
        let wl = Whitelist::new(vec![AllowEntry::Domain("example.com".into())]);
        assert!(wl.is_domain_allowed("sub.example.com"));
        assert!(wl.is_domain_allowed("deep.sub.example.com"));
        assert!(!wl.is_domain_allowed("badexample.com"));
    }

    #[test]
    fn domain_trailing_dot_stripped() {
        let wl = Whitelist::new(vec![AllowEntry::Domain("example.com".into())]);
        assert!(wl.is_domain_allowed("example.com."));
    }

    // -- IPv4 matching --

    #[test]
    fn ipv4_exact_match() {
        let wl = Whitelist::new(vec![AllowEntry::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))]);
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5))));
    }

    #[test]
    fn cidr_v4_slash8() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
        )]);
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn cidr_v4_slash0_matches_all_v4() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)]);
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        // v4 CIDR should NOT match v6 addresses
        assert!(!wl.is_ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn cidr_v4_slash32() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            32,
        )]);
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    // -- IPv6 matching --

    #[test]
    fn ipv6_exact_match() {
        let wl = Whitelist::new(vec![AllowEntry::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))]);
        assert!(wl.is_ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!wl.is_ip_allowed(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2))));
    }

    #[test]
    fn cidr_v6_slash64() {
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        let wl = Whitelist::new(vec![AllowEntry::Cidr(IpAddr::V6(net), 64)]);
        assert!(wl.is_ip_allowed("2001:db8::1".parse().unwrap()));
        assert!(wl.is_ip_allowed("2001:db8::ffff".parse().unwrap()));
        assert!(!wl.is_ip_allowed("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_slash0_matches_all_v6() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)]);
        assert!(wl.is_ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // v6 CIDR should NOT match v4 addresses
        assert!(!wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn cidr_v6_slash128() {
        let addr: IpAddr = "fe80::1".parse().unwrap();
        let wl = Whitelist::new(vec![AllowEntry::Cidr(addr, 128)]);
        assert!(wl.is_ip_allowed("fe80::1".parse().unwrap()));
        assert!(!wl.is_ip_allowed("fe80::2".parse().unwrap()));
    }

    // -- resolved IP tracking --

    #[test]
    fn resolved_ip_tracking_v4() {
        let mut wl = Whitelist::new(vec![]);
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(!wl.is_ip_allowed(ip));
        wl.add_resolved_ip(ip);
        assert!(wl.is_ip_allowed(ip));
    }

    #[test]
    fn resolved_ip_tracking_v6() {
        let mut wl = Whitelist::new(vec![]);
        let ip: IpAddr = "2606:4700::1".parse().unwrap();
        assert!(!wl.is_ip_allowed(ip));
        wl.add_resolved_ip(ip);
        assert!(wl.is_ip_allowed(ip));
    }

    // -- mixed --

    #[test]
    fn empty_whitelist_blocks_everything() {
        let wl = Whitelist::new(vec![]);
        assert!(!wl.is_domain_allowed("anything.com"));
        assert!(!wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!wl.is_ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn multiple_entries_mixed() {
        let wl = Whitelist::new(vec![
            AllowEntry::Domain("example.com".into()),
            AllowEntry::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            AllowEntry::Cidr(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
            AllowEntry::Cidr("2001:db8::".parse().unwrap(), 32),
        ]);
        assert!(wl.is_domain_allowed("example.com"));
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!wl.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))));
        assert!(wl.is_ip_allowed("2001:db8::1".parse().unwrap()));
        assert!(!wl.is_ip_allowed("2001:db9::1".parse().unwrap()));
    }
}
