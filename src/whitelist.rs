use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub enum AllowEntry {
    Domain(String),
    Ip(Ipv4Addr),
    Cidr(Ipv4Addr, u8),
}

pub struct Whitelist {
    domains: Vec<String>,
    ips: HashSet<Ipv4Addr>,
    cidrs: Vec<(u32, u32)>, // (network, mask)
    resolved_ips: HashSet<Ipv4Addr>,
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
                AllowEntry::Cidr(addr, prefix) => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    let network = u32::from(addr) & mask;
                    wl.cidrs.push((network, mask));
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

    pub fn is_ip_allowed(&self, ip: Ipv4Addr) -> bool {
        if self.ips.contains(&ip) {
            return true;
        }
        if self.resolved_ips.contains(&ip) {
            return true;
        }
        let ip_u32 = u32::from(ip);
        for &(network, mask) in &self.cidrs {
            if ip_u32 & mask == network {
                return true;
            }
        }
        false
    }

    pub fn add_resolved_ip(&mut self, ip: Ipv4Addr) {
        self.resolved_ips.insert(ip);
    }
}

pub fn parse_allow_entry(s: &str) -> AllowEntry {
    if let Some((addr_str, prefix_str)) = s.split_once('/')
        && let (Ok(addr), Ok(prefix)) = (addr_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>())
        && prefix <= 32
    {
        return AllowEntry::Cidr(addr, prefix);
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return AllowEntry::Ip(ip);
    }
    AllowEntry::Domain(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entry_domain() {
        assert!(
            matches!(parse_allow_entry("example.com"), AllowEntry::Domain(d) if d == "example.com")
        );
        assert!(
            matches!(parse_allow_entry("sub.example.com"), AllowEntry::Domain(d) if d == "sub.example.com")
        );
    }

    #[test]
    fn parse_entry_ip() {
        assert!(
            matches!(parse_allow_entry("1.2.3.4"), AllowEntry::Ip(ip) if ip == Ipv4Addr::new(1,2,3,4))
        );
        assert!(matches!(
            parse_allow_entry("255.255.255.255"),
            AllowEntry::Ip(_)
        ));
    }

    #[test]
    fn parse_entry_cidr() {
        assert!(matches!(
            parse_allow_entry("10.0.0.0/8"),
            AllowEntry::Cidr(_, 8)
        ));
        assert!(matches!(
            parse_allow_entry("192.168.1.0/24"),
            AllowEntry::Cidr(_, 24)
        ));
        assert!(matches!(
            parse_allow_entry("0.0.0.0/0"),
            AllowEntry::Cidr(_, 0)
        ));
    }

    #[test]
    fn parse_entry_invalid_cidr_falls_back_to_domain() {
        assert!(matches!(
            parse_allow_entry("10.0.0.0/33"),
            AllowEntry::Domain(_)
        ));
        assert!(matches!(
            parse_allow_entry("10.0.0.0/abc"),
            AllowEntry::Domain(_)
        ));
    }

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
        assert!(wl.is_domain_allowed("sub.example.com."));
    }

    #[test]
    fn ip_exact_match() {
        let wl = Whitelist::new(vec![AllowEntry::Ip(Ipv4Addr::new(1, 2, 3, 4))]);
        assert!(wl.is_ip_allowed(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(1, 2, 3, 5)));
    }

    #[test]
    fn cidr_match() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(Ipv4Addr::new(10, 0, 0, 0), 8)]);
        assert!(wl.is_ip_allowed(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(wl.is_ip_allowed(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(11, 0, 0, 1)));
    }

    #[test]
    fn cidr_24() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(Ipv4Addr::new(192, 168, 1, 0), 24)]);
        assert!(wl.is_ip_allowed(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(wl.is_ip_allowed(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn cidr_0_matches_everything() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(Ipv4Addr::new(0, 0, 0, 0), 0)]);
        assert!(wl.is_ip_allowed(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(wl.is_ip_allowed(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn cidr_32_matches_single_host() {
        let wl = Whitelist::new(vec![AllowEntry::Cidr(Ipv4Addr::new(10, 0, 0, 1), 32)]);
        assert!(wl.is_ip_allowed(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn resolved_ip_tracking() {
        let mut wl = Whitelist::new(vec![AllowEntry::Domain("example.com".into())]);
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        assert!(!wl.is_ip_allowed(ip));
        wl.add_resolved_ip(ip);
        assert!(wl.is_ip_allowed(ip));
    }

    #[test]
    fn empty_whitelist_blocks_everything() {
        let wl = Whitelist::new(vec![]);
        assert!(!wl.is_domain_allowed("anything.com"));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn multiple_entries() {
        let wl = Whitelist::new(vec![
            AllowEntry::Domain("example.com".into()),
            AllowEntry::Ip(Ipv4Addr::new(8, 8, 8, 8)),
            AllowEntry::Cidr(Ipv4Addr::new(172, 16, 0, 0), 12),
        ]);
        assert!(wl.is_domain_allowed("example.com"));
        assert!(!wl.is_domain_allowed("google.com"));
        assert!(wl.is_ip_allowed(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(8, 8, 4, 4)));
        assert!(wl.is_ip_allowed(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(wl.is_ip_allowed(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!wl.is_ip_allowed(Ipv4Addr::new(172, 32, 0, 0)));
    }
}
