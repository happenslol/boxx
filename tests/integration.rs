use std::process::Command;

fn boxx_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_boxx"))
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
    // curl should fail because there's no network at all
    let out = boxx_bin()
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

#[test]
fn command_without_separator() {
    // Command without -- should still work (first non-flag arg starts command)
    let out = boxx_bin().args(["echo", "hi"]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");
}
