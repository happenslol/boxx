mod dns;
mod netns;
mod proxy;
mod whitelist;

use clap::Parser;
use std::process::Command;
use whitelist::{AllowEntry, Whitelist, parse_allow_entry};

/// Lightweight sandbox for running commands with filesystem and network isolation.
#[derive(Parser)]
#[command(name = "boxx")]
struct Cli {
    /// Allow network access to a domain, IP, or CIDR (can be repeated).
    #[arg(long = "allow", value_name = "DOMAIN|IP|CIDR")]
    allow: Vec<String>,

    /// Allow unrestricted network access (passthrough).
    #[arg(long = "allow-all")]
    allow_all: bool,

    /// Command to run inside the sandbox.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let allow_entries: Vec<AllowEntry> = cli.allow.iter().map(|s| parse_allow_entry(s)).collect();

    let home = std::env::var("HOME").expect("HOME not set");
    let tmp_dir = format!("/tmp/boxx-{:016x}", random_u64());
    std::fs::create_dir_all(&tmp_dir).expect("failed to create tmp dir");

    let exit_code = if cli.allow_all {
        run_passthrough(&home, &tmp_dir, &cli.command)
    } else if allow_entries.is_empty() {
        run_isolated(&home, &tmp_dir, &cli.command)
    } else {
        run_filtered(&home, &tmp_dir, &cli.command, allow_entries)
    };

    std::fs::remove_dir_all(&tmp_dir).ok();
    std::process::exit(exit_code);
}

/// Run with full network access (current behavior).
fn run_passthrough(home: &str, tmp_dir: &str, args: &[String]) -> i32 {
    let mut cmd = build_bwrap_cmd(home, tmp_dir, BwrapNetMode::Passthrough);
    cmd.args(args);
    exec_bwrap(cmd)
}

/// Run with no network access at all.
fn run_isolated(home: &str, tmp_dir: &str, args: &[String]) -> i32 {
    let mut cmd = build_bwrap_cmd(home, tmp_dir, BwrapNetMode::Isolated);
    cmd.args(args);
    exec_bwrap(cmd)
}

/// Run with filtered network through the proxy.
fn run_filtered(home: &str, tmp_dir: &str, args: &[String], entries: Vec<AllowEntry>) -> i32 {
    let mut whitelist = Whitelist::new(entries);

    // Write a resolv.conf that points DNS to our proxy gateway
    let resolv_path = format!("{tmp_dir}/resolv.conf");
    std::fs::write(&resolv_path, "nameserver 10.0.2.2\n").expect("failed to write resolv.conf");

    // Resolve the real path behind /etc/resolv.conf (follows symlinks)
    // so we can overlay the actual file, not the symlink.
    let resolv_target = std::fs::canonicalize("/etc/resolv.conf")
        .unwrap_or_else(|_| std::path::PathBuf::from("/etc/resolv.conf"));
    let resolv_target_str = resolv_target
        .to_str()
        .expect("resolv.conf path not utf-8")
        .to_string();

    // Clone values needed by the child closure
    let home_clone = home.to_string();
    let tmp_dir_clone = tmp_dir.to_string();
    let resolv_clone = resolv_path.clone();
    let args_clone = args.to_vec();

    let sandbox = netns::setup_sandbox_netns_with_child(move || {
        // This runs in the child process, inside the new user+net namespace.
        // Use Filtered mode: skip user/net unshare since we already did that.
        let mut cmd = build_bwrap_cmd(&home_clone, &tmp_dir_clone, BwrapNetMode::Filtered);

        // Override the real resolv.conf file (following symlinks)
        cmd.args(["--ro-bind", &resolv_clone, &resolv_target_str]);

        cmd.args(&args_clone);

        let err = exec_bwrap_replace(cmd);
        eprintln!("failed to exec bwrap: {err}");
    })
    .unwrap_or_else(|e| {
        eprintln!("failed to set up sandbox network: {e}");
        std::process::exit(1);
    });

    // Signal the child to start (TAP device is set up, proxy is about to run)
    unsafe {
        libc::write(sandbox.ready_fd, [1u8].as_ptr().cast(), 1);
        libc::close(sandbox.ready_fd);
    }

    // Run the proxy loop (blocks until child exits)
    proxy::run_proxy(sandbox.tap_fd, &mut whitelist, sandbox.child_pid);

    // Collect child exit status
    let mut status = 0i32;
    unsafe { libc::waitpid(sandbox.child_pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

enum BwrapNetMode {
    /// Full passthrough: --unshare-all --share-net
    Passthrough,
    /// Isolated: --unshare-all (network unshared by bwrap)
    Isolated,
    /// Filtered: already in user+net namespace, only unshare ipc/pid/uts/cgroup
    Filtered,
}

fn build_bwrap_cmd(home: &str, tmp_dir: &str, net_mode: BwrapNetMode) -> Command {
    let mut cmd = Command::new("bwrap");

    match net_mode {
        BwrapNetMode::Passthrough => {
            cmd.args(["--unshare-all", "--share-net"]);
        }
        BwrapNetMode::Isolated => {
            cmd.args(["--unshare-all"]);
        }
        BwrapNetMode::Filtered => {
            // Already in a user+net namespace; only unshare the rest
            cmd.args([
                "--unshare-ipc",
                "--unshare-pid",
                "--unshare-uts",
                "--unshare-cgroup",
            ]);
        }
    }

    // Basic filesystem setup
    cmd.args(["--dev", "/dev"]);
    cmd.args(["--proc", "/proc"]);

    // Per-sandbox tmp directory
    cmd.args(["--bind", tmp_dir, "/tmp"]);

    // System paths (read-only)
    for path in ["/nix/store", "/run", "/etc"] {
        if std::fs::metadata(path).is_ok() {
            cmd.args(["--ro-bind", path, path]);
        }
    }

    let cwd =
        std::env::current_dir().map(|c| c.canonicalize().expect("failed to canonicalize cwd"));

    // Home subset (read-only), skip if cwd is inside
    for dir in ["code", ".config", ".flake"] {
        let path = std::path::PathBuf::from(format!("{home}/{dir}"))
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(format!("{home}/{dir}")));
        if std::fs::metadata(&path).is_ok() {
            if let Ok(true) = cwd.as_ref().map(|c| c.starts_with(&path)) {
                continue;
            }
            let p = path.to_str().expect("path is not valid utf-8");
            cmd.args(["--ro-bind", p, p]);
        }
    }

    // Home subset (read-write)
    for dir in [".local", ".cache", ".pi"] {
        let path = format!("{home}/{dir}");
        if std::fs::metadata(&path).is_ok() {
            cmd.args(["--bind", &path, &path]);
        }
    }

    // Current working directory (read-write, overlays the ro-bind above)
    if let Ok(ref cwd) = cwd {
        let cwd = cwd.to_str().expect("cwd is not valid utf-8");
        cmd.args(["--bind", cwd, cwd]);
        cmd.args(["--chdir", cwd]);
    }

    cmd
}

fn exec_bwrap(mut cmd: Command) -> i32 {
    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("failed to exec bwrap: {e}");
        std::process::exit(1);
    });
    status.code().unwrap_or(1)
}

/// Replace the current process with bwrap (used in the child after fork).
fn exec_bwrap_replace(mut cmd: Command) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    // This only returns if exec fails
    cmd.exec()
}

fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut buf)
        .expect("failed to read /dev/urandom");
    u64::from_ne_bytes(buf)
}
