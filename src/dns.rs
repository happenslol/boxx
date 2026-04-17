use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extract the queried domain name from a DNS query packet.
pub fn parse_query_domain(data: &[u8]) -> Option<String> {
    // DNS header is 12 bytes
    if data.len() < 12 {
        return None;
    }
    // QDCOUNT should be >= 1
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }
    // Parse the QNAME starting at offset 12
    let mut pos = 12;
    let mut parts = Vec::new();
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        // Pointer compression not expected in queries, but bail if we see it
        if len & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        parts.push(std::str::from_utf8(&data[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

/// Build an NXDOMAIN response for a given DNS query.
pub fn build_nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut response = query.to_vec();
    // Set QR=1 (response), keep opcode, set RA=1, RCODE=3 (NXDOMAIN)
    response[2] = (query[2] & 0x78) | 0x80; // QR=1, preserve opcode
    response[3] = (query[3] & 0x70) | 0x83; // RA=1, RCODE=3
    // Zero out answer/authority/additional counts
    response[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    Some(response)
}

/// Extract A and AAAA record IPs from a DNS response.
pub fn extract_ip_records(data: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if data.len() < 12 {
        return ips;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return ips;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(data, pos);
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return ips;
        }
    }

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        pos = skip_name(data, pos);
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > data.len() {
            break;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                // A record
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                )));
            }
            (28, 16) => {
                // AAAA record
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    ips
}

/// Skip a DNS name (handling pointer compression).
fn skip_name(data: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= data.len() {
            return data.len();
        }
        let len = data[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if len & 0xC0 == 0xC0 {
            // Pointer: 2 bytes total
            return pos + 2;
        }
        pos += 1 + len;
    }
}

/// Forward a DNS query to the system resolver and return the response.
pub fn forward_query(query: &[u8]) -> Option<Vec<u8>> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    sock.send_to(query, "8.8.8.8:53").ok()?;
    let mut buf = [0u8; 4096];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    Some(buf[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query for a given domain.
    fn make_query(domain: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: ID=0x1234, flags=0x0100 (RD), QDCOUNT=1
        buf.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // QNAME
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        // QTYPE=A (1), QCLASS=IN (1)
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        buf
    }

    fn make_a_response(query: &[u8], ips: &[Ipv4Addr]) -> Vec<u8> {
        let mut buf = query.to_vec();
        buf[2] |= 0x80;
        buf[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes());
        for ip in ips {
            buf.extend_from_slice(&[0xC0, 0x0C]);
            buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN
            buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL=300
            buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
            buf.extend_from_slice(&ip.octets());
        }
        buf
    }

    fn make_aaaa_response(query: &[u8], ips: &[Ipv6Addr]) -> Vec<u8> {
        let mut buf = query.to_vec();
        buf[2] |= 0x80;
        buf[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes());
        for ip in ips {
            buf.extend_from_slice(&[0xC0, 0x0C]);
            buf.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // TYPE=AAAA, CLASS=IN
            buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL=300
            buf.extend_from_slice(&[0x00, 0x10]); // RDLENGTH=16
            buf.extend_from_slice(&ip.octets());
        }
        buf
    }

    #[test]
    fn parse_query_simple() {
        let query = make_query("example.com");
        assert_eq!(parse_query_domain(&query), Some("example.com".into()));
    }

    #[test]
    fn parse_query_subdomain() {
        let query = make_query("sub.deep.example.com");
        assert_eq!(
            parse_query_domain(&query),
            Some("sub.deep.example.com".into())
        );
    }

    #[test]
    fn parse_query_single_label() {
        let query = make_query("localhost");
        assert_eq!(parse_query_domain(&query), Some("localhost".into()));
    }

    #[test]
    fn parse_query_too_short() {
        assert_eq!(parse_query_domain(&[0; 11]), None);
        assert_eq!(parse_query_domain(&[]), None);
    }

    #[test]
    fn parse_query_zero_qdcount() {
        // Valid header but QDCOUNT=0
        let mut query = make_query("example.com");
        query[4] = 0;
        query[5] = 0;
        assert_eq!(parse_query_domain(&query), None);
    }

    #[test]
    fn parse_query_truncated_label() {
        let mut query = make_query("example.com");
        // Truncate in the middle of a label
        query.truncate(15);
        assert_eq!(parse_query_domain(&query), None);
    }

    #[test]
    fn nxdomain_response_has_correct_flags() {
        let query = make_query("blocked.com");
        let response = build_nxdomain_response(&query).unwrap();

        // Same length as query (no answer section)
        assert_eq!(response.len(), query.len());
        // QR bit set
        assert_ne!(response[2] & 0x80, 0);
        // RCODE=3 (NXDOMAIN)
        assert_eq!(response[3] & 0x0F, 3);
        // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        // Transaction ID preserved
        assert_eq!(&response[0..2], &query[0..2]);
    }

    #[test]
    fn nxdomain_rejects_short_input() {
        assert!(build_nxdomain_response(&[0; 11]).is_none());
    }

    #[test]
    fn extract_a_record() {
        let query = make_query("example.com");
        let response = make_a_response(&query, &[Ipv4Addr::new(93, 184, 216, 34)]);
        let ips = extract_ip_records(&response);
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[test]
    fn extract_multiple_a_records() {
        let query = make_query("example.com");
        let response = make_a_response(
            &query,
            &[Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)],
        );
        let ips = extract_ip_records(&response);
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))
            ]
        );
    }

    #[test]
    fn extract_aaaa_record() {
        let query = make_query("example.com");
        let v6: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let response = make_aaaa_response(&query, &[v6]);
        let ips = extract_ip_records(&response);
        assert_eq!(ips, vec![IpAddr::V6(v6)]);
    }

    #[test]
    fn extract_no_answers() {
        let query = make_query("example.com");
        let mut response = query.clone();
        response[2] |= 0x80;
        assert!(extract_ip_records(&response).is_empty());
    }

    #[test]
    fn extract_empty_input() {
        assert!(extract_ip_records(&[]).is_empty());
        assert!(extract_ip_records(&[0; 11]).is_empty());
    }

    #[test]
    fn extract_skips_unknown_record_types() {
        let query = make_query("example.com");
        let mut response = query.clone();
        response[2] |= 0x80;
        response[6] = 0;
        response[7] = 1; // ANCOUNT=1
        response.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        response.extend_from_slice(&[0x00, 0x05]); // TYPE=CNAME (5)
        response.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL
        response.extend_from_slice(&[0x00, 0x03]); // RDLENGTH=3
        response.extend_from_slice(&[0x01, 0x78, 0x00]); // some CNAME data

        assert!(extract_ip_records(&response).is_empty());
    }
}
