use notify::{RecursiveMode, Watcher};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsStr;
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
/// Earlier entries take no precedence — allowlists are additive.
pub fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(CONFIG_FILENAME)];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(format!(
            "{home}/.config/boxx/{CONFIG_FILENAME}"
        )));
    }
    paths
}

/// Read and merge all existing config files. Missing files are ignored,
/// parse errors are logged and the file is skipped.
pub fn load_merged() -> Config {
    let mut merged = Config::default();
    for path in config_paths() {
        let contents = match std::fs::read_to_string(&path) {
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

/// Spawn a thread that watches config files via `notify` and sends fresh
/// (cli + config) allow entries through `tx` whenever a file changes.
/// The thread exits when the receiver is dropped.
pub fn spawn_watcher(tx: mpsc::Sender<Vec<AllowEntry>>, cli_entries: Vec<AllowEntry>) {
    std::thread::spawn(move || {
        let (notify_tx, notify_rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = match notify::recommended_watcher(notify_tx) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("boxx: failed to create file watcher: {e}");
                return;
            }
        };

        // Watch each distinct parent directory that exists. Watching the
        // parent (not the file) lets us catch creation of a file that did
        // not exist at startup, and survives editor atomic-rename saves.
        let mut watched: HashSet<PathBuf> = HashSet::new();
        for path in config_paths() {
            let parent = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            if watched.contains(&parent) || !parent.exists() {
                continue;
            }
            if let Err(e) = watcher.watch(&parent, RecursiveMode::NonRecursive) {
                eprintln!("boxx: failed to watch {}: {}", parent.display(), e);
                continue;
            }
            watched.insert(parent);
        }

        if watched.is_empty() {
            return;
        }

        loop {
            let event = match notify_rx.recv() {
                Ok(Ok(evt)) => evt,
                Ok(Err(_)) => continue,
                Err(_) => return,
            };

            let touches_config = event
                .paths
                .iter()
                .any(|p| p.file_name() == Some(OsStr::new(CONFIG_FILENAME)));
            if !touches_config {
                continue;
            }

            // Editors often emit several events per save (create temp,
            // rename, chmod). Drain anything that arrives within 100ms
            // before reloading to coalesce them.
            while notify_rx.recv_timeout(Duration::from_millis(100)).is_ok() {}

            let config = load_merged();
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
