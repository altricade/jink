//! Shared helpers: loading the bundle's strategy files from the fixtures.

use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

use jink_core::config::Config;
use jink_core::config::bat::winws_args;
use jink_core::config::winws::{FileSource, parse};

pub(crate) fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Resolves `bin/…` and `lists/…` paths to the fixtures. The `*-user.txt`
/// lists get the placeholder content `service.bat` creates on first run.
pub(crate) struct Bundle;

impl FileSource for Bundle {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        let placeholder = match path {
            "lists/list-general-user.txt" => {
                Some("# Never leave this file empty\r\ndomain.example.abc\r\n")
            }
            "lists/list-exclude-user.txt" => Some("domain.example.abc\r\n"),
            "lists/ipset-exclude-user.txt" => Some("203.0.113.113/32\r\n"),
            _ => None,
        };
        if let Some(text) = placeholder {
            return Ok(text.as_bytes().to_vec());
        }
        let rel = path
            .strip_prefix("bin/")
            .map(PathBuf::from)
            .or_else(|| {
                path.strip_prefix("lists/")
                    .map(|p| PathBuf::from("lists").join(p))
            })
            .ok_or_else(|| std::io::Error::other(format!("outside bin/ and lists/: {path}")))?;
        std::fs::read(fixtures().join(rel))
    }
}

/// Like [`Bundle`], but with the full IP list `service.bat` can switch on
/// (`ipset-all.txt.backup`) instead of the shipped one-address placeholder.
pub(crate) struct FullIpset;

impl FileSource for FullIpset {
    fn read(&self, path: &str) -> std::io::Result<Vec<u8>> {
        match path {
            "lists/ipset-all.txt" => Bundle.read("lists/ipset-all-full.txt"),
            other => Bundle.read(other),
        }
    }
}

/// A strategy with its lists; `full_ipset` swaps in the full IP list.
pub(crate) fn load_with(
    file: &str,
    game_filter: &str,
    full_ipset: bool,
) -> Result<Config, Box<dyn Error>> {
    let text = std::fs::read_to_string(fixtures().join("strategies").join(file))?;
    let vars = HashMap::from([
        ("BIN", "bin/"),
        ("LISTS", "lists/"),
        ("GameFilterTCP", game_filter),
        ("GameFilterUDP", game_filter),
    ]);
    let args = winws_args(&text, &vars)?;
    let files: &dyn FileSource = if full_ipset { &FullIpset } else { &Bundle };
    Ok(parse(&args, files)?)
}
