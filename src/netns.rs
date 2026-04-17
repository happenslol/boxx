use std::os::fd::RawFd;

// ioctl constants for TUN/TAP
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

// Netlink constants
const NETLINK_ROUTE: libc::c_int = 0;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_NEWLINK: u16 = 16;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;

const IFA_LOCAL: u16 = 2;
const IFA_ADDRESS: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;

const AF_INET: u8 = 2;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RTN_UNICAST: u8 = 1;

/// Result of setting up the sandbox network namespace.
pub struct SandboxNet {
    /// TAP device fd (readable/writable from host namespace).
    pub tap_fd: RawFd,
    /// PID of the child process (will exec bwrap).
    pub child_pid: i32,
    /// Write end of the ready pipe — write to unblock the child.
    pub ready_fd: RawFd,
}

/// Fork, create a network namespace with a TAP device, return the TAP fd to the parent.
/// The child calls `child_fn` after waiting for the ready signal.
pub fn setup_sandbox_netns_with_child<F>(child_fn: F) -> Result<SandboxNet, String>
where
    F: FnOnce(),
{
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err("socketpair failed".into());
    }
    let (sock_parent, sock_child) = (sv[0], sv[1]);

    let mut pipefd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
        return Err("pipe failed".into());
    }
    let (ready_read, ready_write) = (pipefd[0], pipefd[1]);

    // Capture uid/gid before fork (needed for uid_map/gid_map after unshare)
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err("fork failed".into()),
        0 => {
            // === CHILD ===
            unsafe { libc::close(sock_parent) };
            unsafe { libc::close(ready_write) };

            // Create new user + network namespaces together.
            // The user namespace grants capabilities needed for the network namespace.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                eprintln!("unshare(CLONE_NEWUSER|CLONE_NEWNET) failed");
                unsafe { libc::_exit(1) };
            }

            // Set up UID/GID mapping so we keep our identity
            std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
                .expect("failed to write uid_map");
            std::fs::write("/proc/self/setgroups", "deny\n").expect("failed to write setgroups");
            std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
                .expect("failed to write gid_map");

            let tap_fd = create_tap_device("tap0");
            if tap_fd < 0 {
                eprintln!("failed to create TAP device");
                unsafe { libc::_exit(1) };
            }

            if let Err(e) = configure_network() {
                eprintln!("failed to configure network: {e}");
                unsafe { libc::_exit(1) };
            }

            if !send_fd(sock_child, tap_fd) {
                eprintln!("failed to send TAP fd to parent");
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::close(sock_child) };

            // Wait for parent to signal ready
            let mut buf = [0u8; 1];
            unsafe { libc::read(ready_read, buf.as_mut_ptr().cast(), 1) };
            unsafe { libc::close(ready_read) };

            // Now exec bwrap (or whatever the caller wants)
            child_fn();

            // If child_fn returns, something went wrong
            unsafe { libc::_exit(1) };
        }
        _ => {
            // === PARENT ===
            unsafe { libc::close(sock_child) };
            unsafe { libc::close(ready_read) };

            let tap_fd = recv_fd(sock_parent);
            unsafe { libc::close(sock_parent) };
            if tap_fd < 0 {
                return Err("failed to receive TAP fd from child".into());
            }

            Ok(SandboxNet {
                tap_fd,
                child_pid: pid,
                ready_fd: ready_write,
            })
        }
    }
}

fn create_tap_device(name: &str) -> RawFd {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return -1;
    }

    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    let mut ifr = Ifreq {
        ifr_name: [0u8; 16],
        ifr_flags: IFF_TAP | IFF_NO_PI,
        _pad: [0u8; 22],
    };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) } != 0 {
        unsafe { libc::close(fd) };
        return -1;
    }

    fd
}

/// Configure the network inside the new namespace using netlink:
/// - Bring up lo
/// - Assign 10.0.2.15/24 to tap0
/// - Bring up tap0
/// - Add default route via 10.0.2.2
fn configure_network() -> Result<(), String> {
    let nl_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if nl_fd < 0 {
        return Err("netlink socket failed".into());
    }

    // Bind to netlink
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::bind(
            nl_fd,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    } != 0
    {
        unsafe { libc::close(nl_fd) };
        return Err("netlink bind failed".into());
    }

    // Get interface indices
    let lo_idx = get_ifindex(nl_fd, "lo")?;
    let tap_idx = get_ifindex(nl_fd, "tap0")?;

    // Bring up lo
    set_link_up(nl_fd, lo_idx)?;

    // Assign IP to tap0: 10.0.2.15/24
    add_address(nl_fd, tap_idx, [10, 0, 2, 15], 24)?;

    // Bring up tap0
    set_link_up(nl_fd, tap_idx)?;

    // Add default route via 10.0.2.2
    add_default_route(nl_fd, [10, 0, 2, 2], tap_idx)?;

    unsafe { libc::close(nl_fd) };
    Ok(())
}

fn get_ifindex(_nl_fd: RawFd, name: &str) -> Result<i32, String> {
    // Use ioctl SIOCGIFINDEX instead of netlink for simplicity
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err("socket for ifindex failed".into());
    }

    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; 16],
        ifr_ifindex: i32,
        _pad: [u8; 20],
    }

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    const SIOCGIFINDEX: libc::c_ulong = 0x8933;
    if unsafe { libc::ioctl(sock, SIOCGIFINDEX, &ifr) } != 0 {
        unsafe { libc::close(sock) };
        return Err(format!("SIOCGIFINDEX failed for {name}"));
    }
    unsafe { libc::close(sock) };
    Ok(ifr.ifr_ifindex)
}

fn netlink_send_and_ack(nl_fd: RawFd, msg: &[u8]) -> Result<(), String> {
    let sent = unsafe { libc::send(nl_fd, msg.as_ptr().cast(), msg.len(), 0) };
    if sent < 0 {
        return Err("netlink send failed".into());
    }

    // Read ACK
    let mut buf = [0u8; 4096];
    let len = unsafe { libc::recv(nl_fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if len < 0 {
        return Err("netlink recv failed".into());
    }

    // Check for error in the response
    if len >= 20 {
        let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if nlmsg_type == 2 {
            // NLMSG_ERROR
            let error = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if error != 0 {
                return Err(format!("netlink error: {error}"));
            }
        }
    }
    Ok(())
}

fn set_link_up(nl_fd: RawFd, ifindex: i32) -> Result<(), String> {
    // RTM_NEWLINK to bring interface up
    #[repr(C)]
    #[derive(Default)]
    struct NlMsgLink {
        nlmsg_len: u32,
        nlmsg_type: u16,
        nlmsg_flags: u16,
        nlmsg_seq: u32,
        nlmsg_pid: u32,
        ifi_family: u8,
        _pad: u8,
        ifi_type: u16,
        ifi_index: i32,
        ifi_flags: u32,
        ifi_change: u32,
    }

    let msg = NlMsgLink {
        nlmsg_len: std::mem::size_of::<NlMsgLink>() as u32,
        nlmsg_type: RTM_NEWLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
        ifi_family: 0,
        ifi_index: ifindex,
        ifi_flags: libc::IFF_UP as u32,
        ifi_change: libc::IFF_UP as u32,
        ..Default::default()
    };

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const msg).cast::<u8>(),
            std::mem::size_of::<NlMsgLink>(),
        )
    };
    netlink_send_and_ack(nl_fd, bytes)
}

fn add_address(nl_fd: RawFd, ifindex: i32, addr: [u8; 4], prefix_len: u8) -> Result<(), String> {
    // Build the netlink message manually with NLA attributes
    let mut buf = [0u8; 128];
    let mut pos = 0;

    // nlmsghdr (16 bytes)
    // ifaddrmsg (8 bytes)
    // NLA: IFA_LOCAL (8 bytes: 4 header + 4 data)
    // NLA: IFA_ADDRESS (8 bytes)
    let total_len: u32 = 16 + 8 + 8 + 8;

    // nlmsghdr
    buf[pos..pos + 4].copy_from_slice(&total_len.to_ne_bytes());
    pos += 4;
    buf[pos..pos + 2].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 2]
        .copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL).to_ne_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&2u32.to_ne_bytes()); // seq
    pos += 4;
    buf[pos..pos + 4].copy_from_slice(&0u32.to_ne_bytes()); // pid
    pos += 4;

    // ifaddrmsg
    buf[pos] = AF_INET;
    pos += 1;
    buf[pos] = prefix_len;
    pos += 1;
    buf[pos] = 0; // flags
    pos += 1;
    buf[pos] = RT_SCOPE_UNIVERSE;
    pos += 1;
    buf[pos..pos + 4].copy_from_slice(&(ifindex as u32).to_ne_bytes());
    pos += 4;

    // NLA: IFA_LOCAL
    buf[pos..pos + 2].copy_from_slice(&8u16.to_ne_bytes()); // nla_len
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&IFA_LOCAL.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&addr);
    pos += 4;

    // NLA: IFA_ADDRESS
    buf[pos..pos + 2].copy_from_slice(&8u16.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&IFA_ADDRESS.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&addr);

    netlink_send_and_ack(nl_fd, &buf[..total_len as usize])
}

fn add_default_route(nl_fd: RawFd, gateway: [u8; 4], oif: i32) -> Result<(), String> {
    let mut buf = [0u8; 128];
    let mut pos = 0;

    // nlmsghdr (16) + rtmsg (12) + NLA RTA_GATEWAY (8) + NLA RTA_OIF (8)
    let total_len: u32 = 16 + 12 + 8 + 8;

    // nlmsghdr
    buf[pos..pos + 4].copy_from_slice(&total_len.to_ne_bytes());
    pos += 4;
    buf[pos..pos + 2].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 2]
        .copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL).to_ne_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&3u32.to_ne_bytes()); // seq
    pos += 4;
    buf[pos..pos + 4].copy_from_slice(&0u32.to_ne_bytes()); // pid
    pos += 4;

    // rtmsg
    buf[pos] = AF_INET; // rtm_family
    pos += 1;
    buf[pos] = 0; // rtm_dst_len (0 = default route)
    pos += 1;
    buf[pos] = 0; // rtm_src_len
    pos += 1;
    buf[pos] = 0; // rtm_tos
    pos += 1;
    buf[pos] = RT_TABLE_MAIN;
    pos += 1;
    buf[pos] = RTPROT_BOOT;
    pos += 1;
    buf[pos] = RT_SCOPE_UNIVERSE;
    pos += 1;
    buf[pos] = RTN_UNICAST;
    pos += 1;
    buf[pos..pos + 4].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    pos += 4;

    // NLA: RTA_GATEWAY
    buf[pos..pos + 2].copy_from_slice(&8u16.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&RTA_GATEWAY.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&gateway);
    pos += 4;

    // NLA: RTA_OIF
    buf[pos..pos + 2].copy_from_slice(&8u16.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&RTA_OIF.to_ne_bytes());
    pos += 2;
    buf[pos..pos + 4].copy_from_slice(&(oif as u32).to_ne_bytes());

    netlink_send_and_ack(nl_fd, &buf[..total_len as usize])
}

/// Send a file descriptor over a Unix socket using SCM_RIGHTS.
fn send_fd(sock: RawFd, fd: RawFd) -> bool {
    let data = [0u8; 1];
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: 1,
    };

    // cmsg buffer: aligned, with space for one fd
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return false;
    }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }

    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    ret > 0
}

/// Receive a file descriptor from a Unix socket using SCM_RIGHTS.
fn recv_fd(sock: RawFd) -> RawFd {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: 1,
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space;

    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret <= 0 {
        return -1;
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return -1;
    }

    unsafe {
        if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
            let mut fd: RawFd = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut fd as *mut RawFd as *mut u8,
                std::mem::size_of::<RawFd>(),
            );
            fd
        } else {
            -1
        }
    }
}
