use std::net::Ipv4Addr;

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

/// Extract A record IPs from a DNS response.
pub fn extract_a_records(data: &[u8]) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if data.len() < 12 {
        return ips;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return ips;
    }

    // Skip the header (12 bytes) and questions section
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        // Skip QNAME
        pos = skip_name(data, pos);
        // Skip QTYPE (2) + QCLASS (2)
        pos += 4;
        if pos > data.len() {
            return ips;
        }
    }

    // Parse answer records
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        // Skip NAME
        pos = skip_name(data, pos);
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if pos + rdlength > data.len() {
            break;
        }
        // A record: type 1, rdlength 4
        if rtype == 1 && rdlength == 4 {
            ips.push(Ipv4Addr::new(
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ));
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
    // Use Google DNS as fallback; ideally we'd read /etc/resolv.conf from the host
    // before entering the namespace, but this works for now.
    sock.send_to(query, "8.8.8.8:53").ok()?;
    let mut buf = [0u8; 4096];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    Some(buf[..len].to_vec())
}
