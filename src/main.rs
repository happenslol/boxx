mod config;
mod dns;
mod docker;
mod netns;
mod proxy;
mod whitelist;

use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use whitelist::{AllowEntry, Whitelist, parse_allow_entry};

/// Lightweight sandbox for running commands with filesystem and network isolation.
#[derive(Parser)]
#[command(name = "boxx")]
struct Cli {
    /// Allow network access to a domain, IP, or CIDR (can be repeated).
    #[arg(long = "allow", value_name = "DOMAIN|IP|CIDR")]
    allow: Vec<String>,

    /// Enable the network proxy. Without --proxy, the sandbox has
    /// full network access (default). With --proxy, all outbound
    /// traffic is blocked unless explicitly allowed via --allow
    /// entries or boxx.toml.
    #[arg(long = "proxy")]
    proxy: bool,

    /// Expose a filtered docker socket to the sandbox. Uses the rootless
    /// daemon at `$XDG_RUNTIME_DIR/docker.sock` (or `docker_socket` in
    /// boxx.toml). Only safe mutations are forwarded; container mounts
    /// are restricted to the current working directory and containers
    /// created by the sandbox are isolated from the host's via a label.
    #[arg(long = "allow-docker")]
    allow_docker: bool,

    /// Command to run inside the sandbox.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    let cli_entries: Vec<AllowEntry> = cli.allow.iter().map(|s| parse_allow_entry(s)).collect();

    // Snapshot which config files exist at startup. This set is the
    // only source the watcher reads from, and the only set we overlay
    // with /dev/null inside the sandbox — files the sandbox creates
    // mid-run are never loaded.
    let config_paths = config::existing_config_paths();
    let config = config::load(&config_paths);
    let config_entries = config.to_allow_entries();
    let all_entries: Vec<AllowEntry> = cli_entries.iter().cloned().chain(config_entries).collect();

    let home = std::env::var("HOME").expect("HOME not set");
    let tmp_dir = format!("/tmp/boxx-{:016x}", random_u64());
    std::fs::create_dir_all(&tmp_dir).expect("failed to create tmp dir");

    // Start the docker proxy (if requested) before anything that forks —
    // the socket file must exist for bwrap to bind-mount it, and the
    // proxy threads live in the parent only.
    let docker_sock = cli
        .allow_docker
        .then(|| setup_docker_proxy(&tmp_dir, config.docker_socket.clone()));
    let docker_sock_ref = docker_sock.as_deref();

    let exit_code = if cli.proxy {
        if !all_entries.is_empty() {
            run_filtered(
                &home,
                &tmp_dir,
                &cli.command,
                all_entries,
                cli_entries,
                config_paths,
                docker_sock_ref,
            )
        } else {
            // --proxy with no allow entries: all network blocked.
            run_isolated(
                &home,
                &tmp_dir,
                &cli.command,
                &config_paths,
                docker_sock_ref,
            )
        }
    } else {
        // Default: full network access, no proxy or filtering.
        run_passthrough(
            &home,
            &tmp_dir,
            &cli.command,
            &config_paths,
            docker_sock_ref,
        )
    };

    std::fs::remove_dir_all(&tmp_dir).ok();
    std::process::exit(exit_code);
}

/// Resolve the backend socket, start the proxy, return the host path of
/// the proxy's listening socket (to be bind-mounted into the sandbox).
fn setup_docker_proxy(tmp_dir: &str, configured_backend: Option<PathBuf>) -> PathBuf {
    let backend = configured_backend.unwrap_or_else(|| {
        let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| {
            eprintln!(
                "boxx: --allow-docker requires XDG_RUNTIME_DIR to be set, or `docker_socket` in boxx.toml"
            );
            std::process::exit(1);
        });
        PathBuf::from(runtime).join("docker.sock")
    });
    if !backend.exists() {
        eprintln!(
            "boxx: docker backend socket {} not found (is rootless dockerd running?)",
            backend.display()
        );
        std::process::exit(1);
    }
    let cwd = std::env::current_dir()
        .and_then(|p| p.canonicalize())
        .unwrap_or_else(|e| {
            eprintln!("boxx: failed to canonicalize cwd: {e}");
            std::process::exit(1);
        });
    let proxy_socket = PathBuf::from(format!("{tmp_dir}/docker.sock"));
    // Scope containers by the canonical cwd. Sandboxes that share a
    // directory (including successive invocations) share containers;
    // sandboxes in different directories are isolated from each other.
    let sandbox_id = cwd.to_string_lossy().into_owned();
    if let Err(e) = docker::spawn(docker::Options {
        proxy_socket: proxy_socket.clone(),
        backend_socket: backend,
        sandbox_id,
        cwd,
    }) {
        eprintln!("boxx: failed to start docker proxy: {e}");
        std::process::exit(1);
    }
    proxy_socket
}

/// Run with full network access (default).
fn run_passthrough(
    home: &str,
    tmp_dir: &str,
    args: &[String],
    masked: &[PathBuf],
    docker_sock: Option<&Path>,
) -> i32 {
    let mut cmd = build_bwrap_cmd(
        home,
        tmp_dir,
        BwrapNetMode::Passthrough,
        masked,
        docker_sock,
    );
    cmd.args(args);
    exec_bwrap(cmd)
}

/// Run with no network access at all (--proxy with no --allow entries).
fn run_isolated(
    home: &str,
    tmp_dir: &str,
    args: &[String],
    masked: &[PathBuf],
    docker_sock: Option<&Path>,
) -> i32 {
    let mut cmd = build_bwrap_cmd(home, tmp_dir, BwrapNetMode::Isolated, masked, docker_sock);
    cmd.args(args);
    exec_bwrap(cmd)
}

/// Run with filtered network through the proxy.
fn run_filtered(
    home: &str,
    tmp_dir: &str,
    args: &[String],
    entries: Vec<AllowEntry>,
    cli_entries: Vec<AllowEntry>,
    masked: Vec<PathBuf>,
    docker_sock: Option<&Path>,
) -> i32 {
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
    let masked_clone = masked.clone();
    let docker_sock_clone = docker_sock.map(PathBuf::from);

    let sandbox = netns::setup_sandbox_netns_with_child(move || {
        // This runs in the child process, inside the new user+net namespace.
        // Use Filtered mode: skip user/net unshare since we already did that.
        let mut cmd = build_bwrap_cmd(
            &home_clone,
            &tmp_dir_clone,
            BwrapNetMode::Filtered,
            &masked_clone,
            docker_sock_clone.as_deref(),
        );

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

    // Spawn config watcher (parent only — after fork). It pushes
    // fresh (cli + config) allow entries through the channel on change.
    let (reload_tx, reload_rx) = mpsc::channel();
    config::spawn_watcher(masked, reload_tx, cli_entries);

    // Run the proxy loop (blocks until child exits, returns its status)
    proxy::run_proxy(sandbox.tap_fd, &mut whitelist, sandbox.child_pid, reload_rx)
}

enum BwrapNetMode {
    /// Full passthrough: --unshare-all --share-net (default)
    Passthrough,
    /// Isolated: --unshare-all (--proxy with no allow entries)
    Isolated,
    /// Filtered: already in user+net namespace, only unshare ipc/pid/uts/cgroup
    Filtered,
}

fn build_bwrap_cmd(
    home: &str,
    tmp_dir: &str,
    net_mode: BwrapNetMode,
    masked: &[PathBuf],
    docker_sock: Option<&Path>,
) -> Command {
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
    for path in [
        "/nix/store",
        "/run",
        "/etc",
        "/bin",
        "/usr/bin",
        "/lib",
        "/lib64",
    ] {
        if std::fs::metadata(path).is_ok() {
            cmd.args(["--ro-bind", path, path]);
        }
    }

    // Per-user runtime directory (read-only)
    let uid = unsafe { libc::getuid() };
    let run_user = format!("/run/user/{uid}");
    if std::fs::metadata(&run_user).is_ok() {
        cmd.args(["--ro-bind", &run_user, &run_user]);
    }

    let cwd =
        std::env::current_dir().map(|c| c.canonicalize().expect("failed to canonicalize cwd"));

    // Home subset (read-only), skip if cwd is inside
    for dir in ["code", ".config", ".flake", ".supermaven", ".corepack"] {
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
    for dir in [
        ".local",
        ".cache",
        ".pi",
        ".pnpm",
        ".npm-packages",
        ".flake/config/pi",
        ".cargo/registry",
        ".cargo/git",
    ] {
        let path = format!("{home}/{dir}");
        if std::fs::metadata(&path).is_ok() {
            cmd.args(["--bind", &path, &path]);
        }
    }

    // Current working directory (read-write, overlays the ro-bind above)
    if let Ok(ref cwd) = cwd {
        let cwd_str = cwd.to_str().expect("cwd is not valid utf-8");
        cmd.args(["--bind", cwd_str, cwd_str]);
        cmd.args(["--chdir", cwd_str]);

        // If cwd is a git worktree, the main repo's `.git` directory lives
        // elsewhere on disk and git operations need read-write access to it
        // (refs, packed-refs, objects). Mount only `.git`, not the rest of
        // the main worktree, to keep sandbox access minimal.
        if let Some(common_git) = worktree_common_git_dir(cwd)
            && let Some(p) = common_git.to_str()
        {
            cmd.args(["--bind", p, p]);
        }
    }

    // Home files (read-only). Must come after the cwd bind above so that
    // when cwd == home the file ro-bind still overlays the rw bind.
    for file in [".gitconfig", ".zshrc"] {
        let path = format!("{home}/{file}");
        if std::fs::metadata(&path).is_ok() {
            cmd.args(["--ro-bind", &path, &path]);
        }
    }

    // Mask config files — sandbox sees an empty read-only file at each
    // path, regardless of the real contents on the host. Must come after
    // the parent directory binds above so the overlay sits on top.
    for path in masked {
        if let Some(p) = path.to_str() {
            cmd.args(["--ro-bind", "/dev/null", p]);
        }
    }

    // Overlay the filtering docker proxy socket at /run/docker.sock so
    // docker clients with default settings find it, and point the env
    // var at the same path for good measure.
    if let Some(sock) = docker_sock
        && let Some(p) = sock.to_str()
    {
        cmd.args(["--ro-bind", p, "/run/docker.sock"]);
        cmd.args(["--setenv", "DOCKER_HOST", "unix:///run/docker.sock"]);
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

/// If `cwd` is inside a git worktree, return the absolute path to the main
/// repository's `.git` directory. Returns `None` for regular checkouts (where
/// `.git` is itself the directory) or if the worktree metadata can't be read.
fn worktree_common_git_dir(cwd: &Path) -> Option<PathBuf> {
    let dot_git = cwd.join(".git");
    if !std::fs::metadata(&dot_git).ok()?.is_file() {
        return None;
    }
    let contents = std::fs::read_to_string(&dot_git).ok()?;
    let gitdir = contents.lines().find_map(|l| l.strip_prefix("gitdir:"))?;
    let worktree_gitdir = PathBuf::from(gitdir.trim());

    // The worktree's gitdir contains a `commondir` file pointing to the
    // main repo's `.git` directory (relative to the worktree gitdir, or
    // absolute).
    let commondir = std::fs::read_to_string(worktree_gitdir.join("commondir")).ok()?;
    let commondir = commondir.trim();
    let main_git = if Path::new(commondir).is_absolute() {
        PathBuf::from(commondir)
    } else {
        worktree_gitdir.join(commondir)
    };
    main_git.canonicalize().ok()
}

fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut buf)
        .expect("failed to read /dev/urandom");
    u64::from_ne_bytes(buf)
}
