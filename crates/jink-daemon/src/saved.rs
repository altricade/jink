//! What the daemon keeps between runs: the strategy, whether to start by
//! itself, and the settings, as JSON in its own folder.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::protocol::SettingsWire;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saved {
    /// The strategy's id (checked against the catalog when loaded).
    pub strategy: String,
    pub start_at_boot: bool,
    /// As text: entries that a later jink no longer accepts are dropped
    /// when loaded, not fatal.
    #[serde(default)]
    pub settings: SettingsWire,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("cannot read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("{path} is damaged: {source}")]
    Damaged {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl Saved {
    /// What a fresh install starts with: off until the user starts it.
    #[must_use]
    pub fn new(strategy: &str) -> Self {
        Self {
            strategy: strategy.to_owned(),
            start_at_boot: false,
            settings: SettingsWire::default(),
        }
    }

    /// The state saved at `path`, or `None` if nothing was saved yet.
    ///
    /// # Errors
    /// If the file cannot be read or is not a saved state.
    pub fn load(path: &Path) -> Result<Option<Self>, LoadError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(LoadError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| LoadError::Damaged {
                path: path.to_path_buf(),
                source,
            })
    }

    /// Saves to `path`: written next to it first, then renamed over it, so
    /// a crash or power loss leaves either the old state or the new one.
    ///
    /// # Errors
    /// If the file cannot be written.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, text)?;
        std::fs::rename(&temporary, path)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{LoadError, Saved};
    use crate::protocol::IpListWire;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jink-saved-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn saved_state_reads_back() {
        let dir = scratch("roundtrip");
        let path = dir.join("state.json");
        assert!(Saved::load(&path).unwrap().is_none());
        let mut saved = Saved::new("alt");
        saved.settings.my_sites.push("youtube.com".into());
        saved.settings.ip_list = IpListWire::BuiltIn;
        saved.save(&path).unwrap();
        assert_eq!(Saved::load(&path).unwrap(), Some(saved.clone()));
        // Saving again replaces it, and leaves no temporary file.
        saved.start_at_boot = true;
        saved.save(&path).unwrap();
        assert_eq!(Saved::load(&path).unwrap(), Some(saved));
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(files.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_reported() {
        let dir = scratch("damaged");
        let path = dir.join("state.json");
        std::fs::write(&path, "{\"strategy\": ").unwrap();
        assert!(matches!(Saved::load(&path), Err(LoadError::Damaged { .. })));
        std::fs::write(
            &path,
            r#"{"strategy":"alt","start_at_boot":true,"extra":1}"#,
        )
        .unwrap();
        assert!(matches!(Saved::load(&path), Err(LoadError::Damaged { .. })));
        // Settings may be missing: they are the defaults.
        std::fs::write(&path, r#"{"strategy":"alt","start_at_boot":false}"#).unwrap();
        assert_eq!(
            Saved::load(&path).unwrap().map(|s| s.start_at_boot),
            Some(false)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
