//! `jink ctl`: the control channel from the terminal, for testing and for
//! people who prefer it to the app. It prints the daemon's JSON replies.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};

use crate::CliError;

#[derive(Debug, Subcommand)]
pub(crate) enum Ctl {
    /// Whether desync runs, on which network, with which strategy.
    Status,
    /// The built-in strategies and how much of each runs here.
    Strategies,
    /// Start desync, with a strategy id (`jink ctl strategies`) or the last one.
    Start { strategy: Option<String> },
    /// Stop desync.
    Stop,
    /// Show the settings (own and excluded sites and IPs, gaming, IP list).
    Settings,
    /// Replace the settings with those in a JSON file (as `settings` shows).
    SetSettings { file: PathBuf },
    /// Whether desync starts by itself when the computer starts.
    Boot { state: OnOff },
    /// Try every strategy and keep the one that gets through best (about
    /// two minutes; `watch` shows the progress, `status` the result).
    Find,
    /// Stop finding, leaving desync as it was.
    CancelFind,
    /// Follow the status as it changes (Ctrl+C to stop).
    Watch,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum OnOff {
    On,
    Off,
}

pub(crate) fn run(command: &Ctl) -> Result<(), CliError> {
    let request = match command {
        Ctl::Status => json!({"cmd": "status"}),
        Ctl::Strategies => json!({"cmd": "strategies"}),
        Ctl::Start { strategy } => json!({"cmd": "start", "strategy": strategy}),
        Ctl::Stop => json!({"cmd": "stop"}),
        Ctl::Settings => json!({"cmd": "settings"}),
        Ctl::SetSettings { file } => {
            let text = std::fs::read_to_string(file)?;
            let settings: Value =
                serde_json::from_str(&text).map_err(|e| CliError::Json(e.to_string()))?;
            json!({"cmd": "update_settings", "settings": settings})
        }
        Ctl::Boot { state } => {
            json!({"cmd": "set_start_at_boot", "on": matches!(state, OnOff::On)})
        }
        Ctl::Find => json!({"cmd": "find"}),
        Ctl::CancelFind => json!({"cmd": "cancel_find"}),
        Ctl::Watch => json!({"cmd": "watch"}),
    };
    let mut stream = connect().map_err(CliError::NoDaemon)?;
    let mut line = serde_json::to_vec(&request).map_err(|e| CliError::Json(e.to_string()))?;
    line.push(b'\n');
    stream.write_all(&line)?;
    let replies = BufReader::new(stream).lines();
    let mut out = std::io::stdout().lock();
    for reply in replies {
        let reply: Value =
            serde_json::from_str(&reply?).map_err(|e| CliError::Json(e.to_string()))?;
        let text =
            serde_json::to_string_pretty(&reply).map_err(|e| CliError::Json(e.to_string()))?;
        writeln!(out, "{text}")?;
        out.flush()?;
        if reply.get("type") == Some(&json!("error")) {
            return Err(CliError::Refused);
        }
        if !matches!(command, Ctl::Watch) {
            break;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn connect() -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(jink_daemon::SOCKET)
}

/// The pipe, opened for reading and writing its data only: the daemon lets
/// users do no more (see `jink_daemon::PIPE`).
#[cfg(windows)]
fn connect() -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES`.
    const ACCESS: u32 = 0x0012_019b;
    std::fs::OpenOptions::new()
        .access_mode(ACCESS)
        .open(jink_daemon::PIPE)
}
