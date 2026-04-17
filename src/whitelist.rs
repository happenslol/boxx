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
            // Wildcard: allow subdomains
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
    // Try CIDR notation: 10.0.0.0/8
    if let Some((addr_str, prefix_str)) = s.split_once('/')
        && let (Ok(addr), Ok(prefix)) = (addr_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>())
        && prefix <= 32
    {
        return AllowEntry::Cidr(addr, prefix);
    }
    // Try plain IP
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return AllowEntry::Ip(ip);
    }
    // Otherwise it's a domain
    AllowEntry::Domain(s.to_string())
}
