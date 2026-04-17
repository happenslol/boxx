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
        // Send response FROM the DNS server IP the sandbox was trying to reach
        local_address: meta.local_address,
        meta: smoltcp::phy::PacketMeta::default(),
    };

    if whitelist.is_domain_allowed(&domain) {
        // Forward to real DNS
        if let Some(response) = dns::forward_query(data) {
            // Track resolved IPs
            for ip in dns::extract_a_records(&response) {
                whitelist.add_resolved_ip(ip);
            }
            dns_socket.send_slice(&response, reply_meta).ok();
        }
    } else {
        // Return NXDOMAIN
        if let Some(response) = dns::build_nxdomain_response(data) {
            dns_socket.send_slice(&response, reply_meta).ok();
        }
    }
}
