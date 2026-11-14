//! Loading a strategy from a zapret-discord-youtube folder: the `.bat` file
//! with `bin/` and `lists/` next to it, as the bundle ships.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use jink_core::config::Config;
use jink_core::config::bat::{BatError, winws_args};
use jink_core::config::winws::{ConfigError, FileSource, parse};

/// `service.bat`'s game filter: when on, the IP-list rules also cover ports
/// 1024-65535 (`%GameFilterTCP%`/`%GameFilterUDP%`); when off, the placeholder
/// port 12, which nothing uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum GameFilter {
    Off,
    On,
}

impl GameFilter {
    const fn ports(self) -> &'static str {
        match self {
            Self::Off => "12",
            Self::On => "1024-65535",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LoadError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Bat(#[from] BatError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// Reads list and payload files from disk. The `*-user.txt` lists are
/// created by `service.bat` on first run; if they are missing, they get the
/// same placeholder content it would write.
struct DiskFiles;

impl FileSource for DiskFiles {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(path).or_else(|e| {
            let name = Path::new(path).file_name().and_then(|n| n.to_str());
            let placeholder = match name {
                Some("list-general-user.txt" | "list-exclude-user.txt") => "domain.example.abc\r\n",
                Some("ipset-exclude-user.txt") => "203.0.113.113/32\r\n",
                _ => return Err(e),
            };
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(placeholder.as_bytes().to_vec())
            } else {
                Err(e)
            }
        })
    }
}

pub(crate) fn load(bat: &Path, game_filter: GameFilter) -> Result<Config, LoadError> {
    let text = std::fs::read_to_string(bat).map_err(|source| LoadError::Read {
        path: bat.to_path_buf(),
        source,
    })?;
    let base = bat
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let bin = format!("{}/bin/", base.display());
    let lists = format!("{}/lists/", base.display());
    let vars = HashMap::from([
        ("BIN", bin.as_str()),
        ("LISTS", lists.as_str()),
        ("GameFilterTCP", game_filter.ports()),
        ("GameFilterUDP", game_filter.ports()),
    ]);
    let args = winws_args(&text, &vars)?;
    Ok(parse(&args, &DiskFiles)?)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{GameFilter, load};

    /// A throwaway copy of the bundle layout: `general.bat`, `bin/`, `lists/`
    /// (without the `*-user.txt` lists, as before `service.bat` first runs).
    fn bundle_copy() -> PathBuf {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../jink-core/tests/fixtures");
        let dir = std::env::temp_dir().join(format!("jink-cli-test-{}", std::process::id()));
        let (bin, lists) = (dir.join("bin"), dir.join("lists"));
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&lists).unwrap();
        for entry in std::fs::read_dir(&fixtures).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "bin") {
                std::fs::copy(&path, bin.join(path.file_name().unwrap())).unwrap();
            }
        }
        for entry in std::fs::read_dir(fixtures.join("lists")).unwrap() {
            let path = entry.unwrap().path();
            std::fs::copy(&path, lists.join(path.file_name().unwrap())).unwrap();
        }
        std::fs::copy(
            fixtures.join("strategies/general.bat"),
            dir.join("general.bat"),
        )
        .unwrap();
        dir
    }

    #[test]
    fn loads_a_strategy_from_its_folder() {
        let dir = bundle_copy();
        let config = load(&dir.join("general.bat"), GameFilter::Off).unwrap();
        assert_eq!(config.rules.len(), 9);
        let on = load(&dir.join("general.bat"), GameFilter::On).unwrap();
        assert!(on.rules[7].matcher.tcp_ports.contains(27015));
        assert!(load(&dir.join("missing.bat"), GameFilter::Off).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
