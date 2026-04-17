use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: boxx <command> [args...]");
        std::process::exit(1);
    }

    let home = std::env::var("HOME").expect("HOME not set");
    let tmp_dir = format!("/tmp/boxx-{:016x}", random_u64());

    std::fs::create_dir_all(&tmp_dir).expect("failed to create tmp dir");

    let mut cmd = Command::new("bwrap");

    // Unshare all namespaces
    cmd.args(["--unshare-all", "--share-net"]);

    // Basic filesystem setup
    cmd.args(["--dev", "/dev"]);
    cmd.args(["--proc", "/proc"]);

    // Per-sandbox tmp directory
    cmd.args(["--bind", &tmp_dir, "/tmp"]);

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

    // The sandboxed command
    cmd.args(&args);

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("failed to exec bwrap: {e}");
        std::process::exit(1);
    });

    std::fs::remove_dir_all(&tmp_dir).ok();
    std::process::exit(status.code().unwrap_or(1));
}

fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut buf)
        .expect("failed to read /dev/urandom");
    u64::from_ne_bytes(buf)
}
