use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::RawFd;
use std::sync::mpsc;
use std::time::SystemTime;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address};

use crate::dns;
use crate::whitelist::Whitelist;

const GATEWAY_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);
const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
const MTU: usize = 1500;

struct TapDevice {
    fd: RawFd,
    rx_buf: Option<Vec<u8>>,
}

impl TapDevice {
    fn new(fd: RawFd) -> Self {
        TapDevice { fd, rx_buf: None }
    }

    /// Try to read a frame from the TAP device into the rx buffer.
    fn poll_read(&mut self) {
        if self.rx_buf.is_some() {
            return; // already have a pending frame
        }
        let mut buf = vec![0u8; MTU + 14]; // Ethernet frame
        let len = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if len > 0 {
            buf.truncate(len as usize);
            self.rx_buf = Some(buf);
        }
    }

    /// Peek at the current pending frame without consuming it.
    fn peek(&self) -> Option<&[u8]> {
        self.rx_buf.as_deref()
    }

    /// Consume the pending frame (called after we've peeked and handled it).
    fn consume_pending(&mut self) -> Option<Vec<u8>> {
        self.rx_buf.take()
    }
}

struct TapRxToken(Vec<u8>);
struct TapTxToken(RawFd);

impl phy::RxToken for TapRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl phy::TxToken for TapTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        unsafe { libc::write(self.0, buf.as_ptr().cast(), buf.len()) };
        result
    }
}

impl Device for TapDevice {
    type RxToken<'a> = TapRxToken;
    type TxToken<'a> = TapTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.consume_pending()?;
        Some((TapRxToken(frame), TapTxToken(self.fd)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TapTxToken(self.fd))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU;
        caps
    }
}

/// A bridged TCP connection between the sandbox and the real network.
struct TcpBridge {
    host_stream: Option<TcpStream>,
    connect_rx: Option<mpsc::Receiver<std::io::Result<TcpStream>>>,
    closed: bool,
}

impl TcpBridge {
    fn new(dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        // Start connecting to the host in a background thread (non-blocking)
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let addr = SocketAddrV4::new(dst_ip, dst_port);
            let result = TcpStream::connect_timeout(
                &std::net::SocketAddr::V4(addr),
                std::time::Duration::from_secs(10),
            );
            tx.send(result).ok();
        });
        TcpBridge {
            host_stream: None,
            connect_rx: Some(rx),
            closed: false,
        }
    }

    /// Check if the background connect has completed.
    fn poll_connect(&mut self) {
        if let Some(ref rx) = self.connect_rx {
            match rx.try_recv() {
                Ok(Ok(stream)) => {
                    stream.set_nonblocking(true).ok();
                    self.host_stream = Some(stream);
                    self.connect_rx = None;
                }
                Ok(Err(_)) => {
                    self.closed = true;
                    self.connect_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {} // still connecting
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.closed = true;
                    self.connect_rx = None;
                }
            }
        }
    }
}

/// Extract destination IP and port from a TCP SYN in an Ethernet frame.
fn extract_tcp_syn(frame: &[u8]) -> Option<(Ipv4Addr, u16)> {
    // Ethernet header: 14 bytes
    if frame.len() < 14 {
        return None;
    }
    // Check ethertype = IPv4 (0x0800)
    if frame[12] != 0x08 || frame[13] != 0x00 {
        return None;
    }
    let ip = &frame[14..];
    if ip.len() < 20 {
        return None;
    }
    // Check IPv4 and protocol = TCP (6)
    let version = ip[0] >> 4;
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let protocol = ip[9];
    if version != 4 || protocol != 6 {
        return None;
    }
    if ip.len() < ihl + 20 {
        return None;
    }
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let tcp = &ip[ihl..];
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    if syn && !ack {
        Some((dst_ip, dst_port))
    } else {
        None
    }
}

fn now() -> Instant {
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    Instant::from_millis(d.as_millis() as i64)
}

/// Run the proxy loop. Blocks until the child process exits.
pub fn run_proxy(tap_fd: RawFd, whitelist: &mut Whitelist, child_pid: i32) {
    let mut device = TapDevice::new(tap_fd);

    let config = Config::new(HardwareAddress::Ethernet(GATEWAY_MAC));
    let mut iface = Interface::new(config, &mut device, now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(GATEWAY_IP.into(), 24)).unwrap();
    });
    // Add a default route so smoltcp accepts packets to any IP
    iface
        .routes_mut()
        .add_default_ipv4_route(GATEWAY_IP)
        .unwrap();

    let mut sockets = SocketSet::new(vec![]);

    // DNS socket: UDP on port 53 (on the gateway IP)
    let dns_rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0u8; 8192]);
    let dns_tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0u8; 8192]);
    let dns_socket = udp::Socket::new(dns_rx, dns_tx);
    let dns_handle = sockets.add(dns_socket);
    sockets
        .get_mut::<udp::Socket>(dns_handle)
        .bind(53)
        .expect("failed to bind DNS socket");

    let mut tcp_bridges: HashMap<SocketHandle, TcpBridge> = HashMap::new();
    // Track which ports we already have smoltcp sockets listening on
    let mut listening_ports: HashMap<u16, SocketHandle> = HashMap::new();

    loop {
        // Check if child is still alive
        let mut status = 0i32;
        let ret = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
        if ret > 0 {
            // Child exited
            break;
        }

        // Read from TAP device
        device.poll_read();

        // Peek at the frame before smoltcp processes it.
        // If it's a TCP SYN to an allowed destination, pre-create a listening socket.
        if let Some(frame) = device.peek()
            && let Some((dst_ip, dst_port)) = extract_tcp_syn(frame)
            && whitelist.is_ip_allowed(dst_ip)
            && !listening_ports.contains_key(&dst_port)
        {
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65535]);
            let tcp_socket = tcp::Socket::new(rx_buf, tx_buf);
            let handle = sockets.add(tcp_socket);
            sockets
                .get_mut::<tcp::Socket>(handle)
                .listen(dst_port)
                .expect("failed to listen on TCP port");
            listening_ports.insert(dst_port, handle);
            tcp_bridges.insert(handle, TcpBridge::new(dst_ip, dst_port));
        }

        // Let smoltcp process the frame
        iface.poll(now(), &mut device, &mut sockets);

        // Handle DNS queries — collect queries first to avoid borrow conflict
        let mut dns_queries = Vec::new();
        {
            let dns_socket = sockets.get_mut::<udp::Socket>(dns_handle);
            while let Ok((data, meta)) = dns_socket.recv() {
                dns_queries.push((data.to_vec(), meta));
            }
        }
        for (data, meta) in dns_queries {
            handle_dns(
                &data,
                meta,
                whitelist,
                sockets.get_mut::<udp::Socket>(dns_handle),
            );
        }

        // Handle TCP bridges: poll host connections and bridge data
        let mut to_remove = Vec::new();
        for (&handle, bridge) in tcp_bridges.iter_mut() {
            // Poll background connect
            bridge.poll_connect();

            if bridge.closed {
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                sock.abort();
                to_remove.push(handle);
                continue;
            }

            if let Some(ref mut stream) = bridge.host_stream {
                let sock = sockets.get_mut::<tcp::Socket>(handle);

                // Sandbox → Host
                if sock.can_recv() {
                    match sock.recv(|data| {
                        let written = stream.write(data).unwrap_or(0);
                        (written, written)
                    }) {
                        Ok(0) | Err(_) => {
                            bridge.closed = true;
                        }
                        Ok(_) => {}
                    }
                }

                // Host → Sandbox
                if sock.can_send() {
                    let mut buf = [0u8; 4096];
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            sock.close();
                            bridge.closed = true;
                        }
                        Ok(n) => {
                            sock.send(|send_buf| {
                                let to_write = n.min(send_buf.len());
                                send_buf[..to_write].copy_from_slice(&buf[..to_write]);
                                (to_write, ())
                            })
                            .ok();
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            sock.close();
                            bridge.closed = true;
                        }
                    }
                }

                // If smoltcp socket is closed, tear down
                if !sock.is_open() {
                    bridge.closed = true;
                    to_remove.push(handle);
                }
            }
        }
        for handle in to_remove {
            tcp_bridges.remove(&handle);
            // Find and remove from listening_ports
            listening_ports.retain(|_, h| *h != handle);
            sockets.remove(handle);
        }

        // Brief sleep to avoid busy-looping
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn handle_dns(
    data: &[u8],
    meta: udp::UdpMetadata,
    whitelist: &mut Whitelist,
    dns_socket: &mut udp::Socket,
) {
    let domain = match dns::parse_query_domain(data) {
        Some(d) => d,
        None => return,
    };

    let reply_meta = udp::UdpMetadata {
        endpoint: meta.endpoint,
        local_address: meta.local_address,
        meta: smoltcp::phy::PacketMeta::default(),
    };

    if whitelist.is_domain_allowed(&domain) {
        if let Some(response) = dns::forward_query(data) {
            for ip in dns::extract_a_records(&response) {
                whitelist.add_resolved_ip(ip);
            }
            dns_socket.send_slice(&response, reply_meta).ok();
        }
    } else if let Some(response) = dns::build_nxdomain_response(data) {
        dns_socket.send_slice(&response, reply_meta).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet + IPv4 + TCP SYN frame.
    fn make_tcp_syn(dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet header (14 bytes)
        frame.extend_from_slice(&[0xff; 6]); // dst mac
        frame.extend_from_slice(&[0x00; 6]); // src mac
        frame.extend_from_slice(&[0x08, 0x00]); // ethertype = IPv4

        // IPv4 header (20 bytes)
        frame.push(0x45); // version=4, ihl=5
        frame.push(0x00); // DSCP/ECN
        let total_len: u16 = 40; // 20 IP + 20 TCP
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00; 4]); // ID, flags, frag offset
        frame.push(64); // TTL
        frame.push(6); // protocol = TCP
        frame.extend_from_slice(&[0x00, 0x00]); // checksum (skipped)
        frame.extend_from_slice(&[10, 0, 2, 15]); // src IP
        frame.extend_from_slice(&dst_ip); // dst IP

        // TCP header (20 bytes)
        frame.extend_from_slice(&12345u16.to_be_bytes()); // src port
        frame.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        frame.extend_from_slice(&[0x00; 4]); // seq number
        frame.extend_from_slice(&[0x00; 4]); // ack number
        frame.push(0x50); // data offset = 5 (20 bytes), no flags high nibble
        frame.push(0x02); // flags: SYN only
        frame.extend_from_slice(&[0xff, 0xff]); // window
        frame.extend_from_slice(&[0x00; 4]); // checksum + urgent

        frame
    }

    #[test]
    fn extract_syn_valid() {
        let frame = make_tcp_syn([93, 184, 216, 34], 443);
        let result = extract_tcp_syn(&frame);
        assert_eq!(result, Some((Ipv4Addr::new(93, 184, 216, 34), 443)));
    }

    #[test]
    fn extract_syn_different_port() {
        let frame = make_tcp_syn([1, 2, 3, 4], 8080);
        assert_eq!(
            extract_tcp_syn(&frame),
            Some((Ipv4Addr::new(1, 2, 3, 4), 8080))
        );
    }

    #[test]
    fn extract_syn_ignores_syn_ack() {
        let mut frame = make_tcp_syn([1, 2, 3, 4], 80);
        // Set ACK flag (byte 47 = offset 14+20+13 in the TCP header)
        frame[14 + 20 + 13] = 0x12; // SYN+ACK
        assert_eq!(extract_tcp_syn(&frame), None);
    }

    #[test]
    fn extract_syn_ignores_ack_only() {
        let mut frame = make_tcp_syn([1, 2, 3, 4], 80);
        frame[14 + 20 + 13] = 0x10; // ACK only, no SYN
        assert_eq!(extract_tcp_syn(&frame), None);
    }

    #[test]
    fn extract_syn_ignores_rst() {
        let mut frame = make_tcp_syn([1, 2, 3, 4], 80);
        frame[14 + 20 + 13] = 0x04; // RST
        assert_eq!(extract_tcp_syn(&frame), None);
    }

    #[test]
    fn extract_syn_ignores_udp() {
        let mut frame = make_tcp_syn([1, 2, 3, 4], 53);
        // Change protocol to UDP (17)
        frame[14 + 9] = 17;
        assert_eq!(extract_tcp_syn(&frame), None);
    }

    #[test]
    fn extract_syn_ignores_ipv6() {
        let mut frame = make_tcp_syn([1, 2, 3, 4], 80);
        // Change ethertype to IPv6
        frame[12] = 0x86;
        frame[13] = 0xdd;
        assert_eq!(extract_tcp_syn(&frame), None);
    }

    #[test]
    fn extract_syn_ignores_arp() {
        let frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src mac
            0x08, 0x06, // ethertype = ARP
            0x00, 0x01, // rest of ARP (doesn't matter)
        ];
        assert_eq!(extract_tcp_syn(&frame), None);
    }

    #[test]
    fn extract_syn_too_short() {
        assert_eq!(extract_tcp_syn(&[]), None);
        assert_eq!(extract_tcp_syn(&[0; 13]), None); // too short for ethernet
        assert_eq!(extract_tcp_syn(&[0; 14]), None); // ethernet but no IP

        // Ethernet + partial IP header
        let mut short = vec![0u8; 14 + 10];
        short[12] = 0x08;
        short[13] = 0x00;
        short[14] = 0x45;
        assert_eq!(extract_tcp_syn(&short), None);
    }

    #[test]
    fn extract_syn_with_ip_options() {
        // IHL=6 (24 bytes IP header — includes 4 bytes of options)
        let mut frame = Vec::new();
        // Ethernet
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);
        // IPv4 with IHL=6
        frame.push(0x46); // version=4, ihl=6
        frame.push(0x00);
        frame.extend_from_slice(&44u16.to_be_bytes()); // total_len = 24 IP + 20 TCP
        frame.extend_from_slice(&[0x00; 4]);
        frame.push(64); // TTL
        frame.push(6); // TCP
        frame.extend_from_slice(&[0x00, 0x00]); // checksum
        frame.extend_from_slice(&[10, 0, 2, 15]); // src
        frame.extend_from_slice(&[1, 2, 3, 4]); // dst
        frame.extend_from_slice(&[0x00; 4]); // IP options (4 bytes)
        // TCP header
        frame.extend_from_slice(&5000u16.to_be_bytes()); // src port
        frame.extend_from_slice(&443u16.to_be_bytes()); // dst port
        frame.extend_from_slice(&[0x00; 4]); // seq
        frame.extend_from_slice(&[0x00; 4]); // ack
        frame.push(0x50); // data offset
        frame.push(0x02); // SYN
        frame.extend_from_slice(&[0xff, 0xff]); // window
        frame.extend_from_slice(&[0x00; 4]); // checksum + urgent

        assert_eq!(
            extract_tcp_syn(&frame),
            Some((Ipv4Addr::new(1, 2, 3, 4), 443))
        );
    }
}
