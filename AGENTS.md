# AGENTS.md - boxx

## Overview

**boxx** is a lightweight, secure sandboxing tool for Linux. It wraps [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) to create isolated environments for running untrusted or sensitive commands.

The tool provides filesystem isolation by creating a minimal container with:
- Read-only access to system paths (`/nix/store`, `/run`, `/etc`)
- Read-only access to `~/code` directory
- Read-write access only to the current working directory
- A fresh, per-invocation `/tmp` directory
- Network access preserved for convenience

## Architecture

```
┌─────────────┐
│  boxx cmd   │  <-- User invokes with command to sandbox
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  bubblewrap │  <-- Unshares namespaces, sets up filesystem
│   (bwrap)   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Sandboxed │  <-- Command runs in isolated environment
│   Command   │
└─────────────┘
```

### Filesystem Layout (Inside Sandbox)

| Path | Access | Notes |
|------|--------|-------|
| `/dev` | Read-write | Device files from host |
| `/proc` | Read-only | Process filesystem |
| `/tmp` | Read-write | Clean per-invocation directory |
| `/nix/store` | Read-only | Nix store (read-only bind mount) |
| `/run` | Read-only | Runtime directory |
| `/etc` | Read-only | System configuration |
| `~/code` | Read-only | User's code directory (if exists) |
| `~/.config` | Read-only | User's config directory (if exists) |
| CWD | Read-write | Current directory (overlay on ~/code if applicable) |

## Development Setup

This project uses **Nix** for reproducible development environments.

```bash
# Enter development shell (handles Rust toolchain automatically)
nix develop

# Or with direnv (automatic when cd-ing into directory)
direnv allow
```

The Nix flake provides:
- Rust toolchain (via `fenix` - latest stable)
- `rustfmt`, `clippy` for code quality
- `cargo` for building
- `bwrap` (bubblewrap) - the underlying sandboxing tool

## Building & Running

```bash
# Build
cargo build --release

# Run (from repo root)
cargo run -- ls -la

# Install
cargo install --path .

# Use
boxx <command> [args...]
```

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | Main application code - argument parsing, bwrap invocation |
| `Cargo.toml` | Rust package manifest |
| `flake.nix` | Nix development environment and build configuration |
| `.envrc` | direnv configuration for automatic Nix shell entry |

## Security Model

- Uses all Linux namespaces (`--unshare-all`) except network (`--share-net`)
- Filesystem is mostly read-only to prevent sandbox escape via file writes
- Current working directory is writable for practical file operations
- Temporary directory is per-invocation to prevent cross-execution data leakage
- Random temp directory names prevent predictable path attacks

## Code Style & Linting

The Nix build requires `cargo clippy --all-targets -- --deny warnings` to pass with no warnings.

```bash
# Run linting
cargo clippy --all-targets -- --deny warnings

# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

## Adding Features

Common modifications:

### Adding new bind mounts
In `src/main.rs`, add new paths to the `cmd.args()` chain:

```rust
for path in ["/nix/store", "/run", "/etc", "/new/path"] {
    if std::fs::metadata(path).is_ok() {
        cmd.args(["--ro-bind", path, path]);
    }
}
```

### Modifying namespace sharing
Change `--share-net` to control network access:
- `--share-net` = network access allowed
- Omit = network isolated

### Adding writeable directories
Add bind mounts without `ro-` prefix:
```rust
cmd.args(["--bind", source, dest]);
```

## Testing

Since the tool runs commands in a sandbox, integration testing requires:
1. A Linux system with bubblewrap installed
2. Test commands that don't require elevated privileges

```bash
# Basic test - check sandbox filesystem isolation
boxx ls /

# Test network access
boxx curl https://example.com

# Test that writes are isolated to CWD only
boxx bash -c "touch /tmp/write_test && ls /tmp"
```

## Dependencies

- **Runtime**: `bwrap` (bubblewrap) must be installed on the system
- **Build**: Standard Rust toolchain (provided by Nix)

## Important Considerations

1. **Not a full security boundary**: Network is shared, so networked attacks are possible. This is for filesystem isolation primarily.

2. **Requires bwrap installed**: The tool execs `bwrap` binary directly - it must be in PATH.

3. **NixOS assumption**: Paths like `/nix/store` are hardcoded. On non-NixOS systems, modify the bind mounts in `main.rs`.

4. **Root not required**: bwrap works unprivileged on modern Linux kernels with user namespaces enabled.

5. **Temp cleanup**: On abnormal exit (kill -9, etc.), `/tmp/boxx-*` directories may be left behind.
