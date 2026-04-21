use std::path::{Path, PathBuf};
use std::process::Command;

fn boxx_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_boxx"))
}

/// Self-cleaning temp directory. Gives each test a fresh, isolated
/// cwd so config-file tests don't collide.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("boxx-test-{name}-{pid}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// boxx rooted in `dir` as both cwd and HOME, so the test can't see
/// the developer's real `~/.config/boxx/boxx.toml`.
fn boxx_in(dir: &Path) -> Command {
    let mut cmd = boxx_bin();
    cmd.current_dir(dir);
    cmd.env("HOME", dir);
    cmd
}

// -- Passthrough mode (--allow-all) --

#[test]
fn passthrough_runs_command() {
    let out = boxx_bin()
        .args(["--allow-all", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
}

#[test]
fn passthrough_preserves_exit_code() {
    let out = boxx_bin()
        .args(["--allow-all", "--", "sh", "-c", "exit 42"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(42));
}

// -- Isolated mode (no --allow flags) --

#[test]
fn isolated_runs_command() {
    let out = boxx_bin().args(["--", "echo", "sandbox"]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "sandbox");
}

#[test]
fn isolated_blocks_network() {
    // Run from a clean tempdir+HOME so no boxx.toml flips us into
    // filtered mode — we want to exercise actual isolated mode here.
    let dir = TempDir::new("isolated");
    let out = boxx_in(dir.path())
        .args([
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "2",
            "--max-time",
            "3",
            "https://example.com",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).is_empty());
}

// -- Filtered mode (--allow) --

#[test]
fn filtered_allows_whitelisted_domain() {
    let out = boxx_bin()
        .args([
            "--allow",
            "example.com",
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "https://example.com",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Example Domain"),
        "expected HTML from example.com, got: {stdout}"
    );
}

#[test]
fn filtered_blocks_non_whitelisted_domain() {
    let out = boxx_bin()
        .args([
            "--allow",
            "example.com",
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "2",
            "--max-time",
            "4",
            "https://google.com",
        ])
        .output()
        .unwrap();
    // curl should fail — DNS returns NXDOMAIN for google.com
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("<html"),
        "non-whitelisted domain should not return HTML, got: {stdout}"
    );
}

#[test]
fn filtered_allows_subdomain() {
    // Whitelisting "example.com" should also allow "www.example.com"
    let out = boxx_bin()
        .args([
            "--allow",
            "example.com",
            "--",
            "curl",
            "-s",
            "-L",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "https://www.example.com",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Example Domain"),
        "subdomain of whitelisted domain should work, got: {stdout}"
    );
}

#[test]
fn filtered_dns_resolves_only_allowed() {
    // Use nslookup/dig-like behavior: the sandbox can only resolve allowed domains
    let out = boxx_bin()
        .args([
            "--allow",
            "example.com",
            "--",
            "sh",
            "-c",
            "getent hosts example.com >/dev/null 2>&1 && echo ok || echo fail",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "ok");

    let out = boxx_bin()
        .args([
            "--allow",
            "example.com",
            "--",
            "sh",
            "-c",
            "getent hosts google.com >/dev/null 2>&1 && echo ok || echo fail",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "fail");
}

// -- Filesystem isolation still works --

#[test]
fn sandbox_has_isolated_tmp() {
    let out = boxx_bin()
        .args(["--allow-all", "--", "sh", "-c", "ls /tmp | wc -l"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // /tmp should be empty (fresh per-invocation)
    // Except in filtered mode where resolv.conf is written there
    assert_eq!(stdout.trim(), "0");
}

#[test]
fn sandbox_cannot_write_outside_cwd() {
    let out = boxx_bin()
        .args([
            "--allow-all",
            "--",
            "sh",
            "-c",
            "touch /etc/test_write 2>&1; echo $?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should fail — /etc is read-only
    assert_ne!(stdout.trim(), "0");
}

// -- Argument parsing edge cases --

#[test]
fn no_args_exits_with_error() {
    let out = boxx_bin().output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn only_flags_no_command_exits_with_error() {
    let out = boxx_bin()
        .args(["--allow", "example.com", "--"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

// -- Config file --

#[test]
fn config_file_masked_inside_sandbox() {
    let dir = TempDir::new("mask");
    let config_path = dir.path().join("boxx.toml");
    let original = "allow = [\"secret.example\"]\n";
    std::fs::write(&config_path, original).unwrap();

    // Read attempt: sandbox sees /dev/null-bound file, open fails.
    let out = boxx_in(dir.path())
        .args(["--allow-all", "--", "cat", "boxx.toml"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "reading masked config should fail, stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Write attempt: ro-bind blocks writes.
    let out = boxx_in(dir.path())
        .args([
            "--allow-all",
            "--",
            "sh",
            "-c",
            "echo pwned > boxx.toml",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "writing masked config should fail");

    // Host file must be untouched.
    let on_disk = std::fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        on_disk, original,
        "host config was modified despite the mask"
    );
}

#[test]
fn config_file_drives_allowlist() {
    let dir = TempDir::new("load");
    std::fs::write(
        dir.path().join("boxx.toml"),
        "allow = [\"example.com\"]\n",
    )
    .unwrap();

    // No --allow on the CLI — filtered mode is reached purely via the
    // config file's allowlist.
    let out = boxx_in(dir.path())
        .args([
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "https://example.com",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Example Domain"),
        "config-driven allowlist should permit example.com, got: {stdout}"
    );
}

#[test]
fn config_live_reload_applies() {
    let dir = TempDir::new("reload");
    let config_path = dir.path().join("boxx.toml");

    // Start with an entry that forces filtered mode but does not permit
    // example.com. The sandbox's first DNS query therefore returns
    // NXDOMAIN from our proxy.
    std::fs::write(&config_path, "allow = [\"placeholder.invalid\"]\n").unwrap();

    let child = boxx_in(dir.path())
        .args([
            "--",
            "sh",
            "-c",
            "getent hosts example.com >/dev/null 2>&1 && echo pre_ok || echo pre_fail; \
             sleep 3; \
             getent hosts example.com >/dev/null 2>&1 && echo post_ok || echo post_fail",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait long enough for the first getent to run, then rewrite the
    // config. The watcher should pick this up, reload the proxy's
    // whitelist, and the second getent (after the 3s sleep) should win.
    std::thread::sleep(std::time::Duration::from_millis(800));
    std::fs::write(&config_path, "allow = [\"example.com\"]\n").unwrap();

    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("pre_fail"),
        "expected pre_fail before reload, got: {stdout}"
    );
    assert!(
        stdout.contains("post_ok"),
        "expected post_ok after live reload, got: {stdout}"
    );
}

// -- Home files --

#[test]
fn gitconfig_is_mounted_readonly() {
    let dir = TempDir::new("git");
    let gitconfig = dir.path().join(".gitconfig");
    let original = "[user]\n\tname = Test User\n\temail = test@example.com\n";
    std::fs::write(&gitconfig, original).unwrap();

    // Sandbox sees the host's .gitconfig contents at $HOME/.gitconfig.
    let out = boxx_in(dir.path())
        .args([
            "--allow-all",
            "--",
            "sh",
            "-c",
            "cat \"$HOME/.gitconfig\"",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "reading .gitconfig failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), original);

    // ro-bind means writes must fail.
    let out = boxx_in(dir.path())
        .args([
            "--allow-all",
            "--",
            "sh",
            "-c",
            "echo hacked > \"$HOME/.gitconfig\"",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "write to .gitconfig should fail");

    // And the host file is untouched.
    let on_disk = std::fs::read_to_string(&gitconfig).unwrap();
    assert_eq!(on_disk, original);
}

#[test]
fn missing_gitconfig_is_skipped() {
    // No .gitconfig in the test HOME — boxx should launch cleanly anyway.
    let dir = TempDir::new("nogit");
    let out = boxx_in(dir.path())
        .args(["--allow-all", "--", "echo", "ok"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

#[test]
fn command_without_separator() {
    // Command without -- should still work (first non-flag arg starts command)
    let out = boxx_bin().args(["echo", "hi"]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
}
