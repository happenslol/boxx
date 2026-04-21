use notify::{RecursiveMode, Watcher};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use crate::whitelist::{AllowEntry, parse_allow_entry};

const CONFIG_FILENAME: &str = "boxx.toml";

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Config {
    pub fn to_allow_entries(&self) -> Vec<AllowEntry> {
        self.allow.iter().map(|s| parse_allow_entry(s)).collect()
    }

    fn parse(contents: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(contents)
    }
}

/// Candidate config paths, in the order they are merged.
/// Allowlists are additive across files.
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(CONFIG_FILENAME)];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(format!(
            "{home}/.config/boxx/{CONFIG_FILENAME}"
        )));
    }
    paths
}

/// Canonicalized config paths that exist at startup. This is the
/// authoritative set used for both sandbox masking and live-reload
/// watching — files created after startup are intentionally ignored
/// so the sandbox cannot materialize a config mid-run.
pub fn existing_config_paths() -> Vec<PathBuf> {
    candidate_paths()
        .into_iter()
        .filter_map(|p| std::fs::canonicalize(&p).ok())
        .collect()
}

/// Load and merge configs from the given paths. Parse errors are
/// logged and the file is skipped. Missing files are skipped silently.
pub fn load(paths: &[PathBuf]) -> Config {
    let mut merged = Config::default();
    for path in paths {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match Config::parse(&contents) {
            Ok(cfg) => merged.allow.extend(cfg.allow),
            Err(e) => eprintln!("boxx: failed to parse {}: {}", path.display(), e),
        }
    }
    merged
}

/// Spawn a thread that watches each given config file via `notify` and
/// sends fresh (cli + config) allow entries through `tx` whenever a file
/// changes. The thread exits when the receiver is dropped or on its own
/// when no paths are given.
pub fn spawn_watcher(
    paths: Vec<PathBuf>,
    tx: mpsc::Sender<Vec<AllowEntry>>,
    cli_entries: Vec<AllowEntry>,
) {
    if paths.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let (notify_tx, notify_rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = match notify::recommended_watcher(notify_tx) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("boxx: failed to create file watcher: {e}");
                return;
            }
        };

        for path in &paths {
            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                eprintln!("boxx: failed to watch {}: {}", path.display(), e);
            }
        }

        loop {
            match notify_rx.recv() {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => continue,
                Err(_) => return,
            }

            // Coalesce burst events (editors emit several per save).
            while notify_rx.recv_timeout(Duration::from_millis(100)).is_ok() {}

            // Atomic-rename saves replace the inode; re-add each watch
            // so we follow the new file. If a path is now gone the
            // re-watch fails silently and we stop tracking it.
            for path in &paths {
                let _ = watcher.unwatch(path);
                let _ = watcher.watch(path, RecursiveMode::NonRecursive);
            }

            let config = load(&paths);
            let mut entries = cli_entries.clone();
            entries.extend(config.to_allow_entries());
            if tx.send(entries).is_err() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_config() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.allow.is_empty());
    }

    #[test]
    fn parse_allow_list() {
        let cfg = Config::parse(r#"allow = ["example.com", "10.0.0.0/8", "::1"]"#).unwrap();
        assert_eq!(cfg.allow, vec!["example.com", "10.0.0.0/8", "::1"]);
    }

    #[test]
    fn parse_missing_allow_is_empty() {
        let cfg = Config::parse("# just a comment\n").unwrap();
        assert!(cfg.allow.is_empty());
    }

    #[test]
    fn parse_invalid_toml_errors() {
        assert!(Config::parse("allow = not-valid").is_err());
    }

    #[test]
    fn to_allow_entries_mixed() {
        let cfg = Config {
            allow: vec!["example.com".into(), "1.2.3.4".into(), "10.0.0.0/8".into()],
        };
        let entries = cfg.to_allow_entries();
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0], AllowEntry::Domain(_)));
        assert!(matches!(entries[1], AllowEntry::Ip(_)));
        assert!(matches!(entries[2], AllowEntry::Cidr(_, _)));
    }
}
