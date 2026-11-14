//! `jink`: check and run zapret-discord-youtube strategies.
//!
//! - `jink check <strategy.bat>` (any OS) shows what jink will do with it.
//! - `jink run <strategy.bat>` runs it: on Windows (as Administrator) with
//!   WinDivert, `WinDivert64.sys` next to `jink.exe`; on macOS (with sudo)
//!   through a utun interface.
//! - `jink service install|uninstall|status` (macOS) runs it at every
//!   startup instead.

#[cfg(any(windows, target_os = "macos", test))]
mod entropy;
mod report;
#[cfg(target_os = "macos")]
mod service;
mod strategy;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use jink_core::config::platform::Platform;

use crate::strategy::{GameFilter, LoadError};

#[derive(Debug, Parser)]
#[command(
    name = "jink",
    version,
    about = "DPI desync engine for zapret-discord-youtube strategies"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load a strategy and show what jink will do with it.
    Check(StrategyArgs),
    /// Run a strategy (Windows: as Administrator; macOS: with sudo).
    Run {
        #[command(flatten)]
        strategy: StrategyArgs,
        /// Start even if some rules use techniques jink cannot perform yet;
        /// those rules then pass traffic unchanged.
        #[arg(long)]
        allow_partial: bool,
    },
    /// Run jink as a service: at every startup, without a terminal.
    #[cfg(target_os = "macos")]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[cfg(target_os = "macos")]
#[derive(Debug, Subcommand)]
enum ServiceAction {
    /// Install a strategy as the service and start it (with sudo). It
    /// replaces the strategy installed before.
    Install {
        #[command(flatten)]
        strategy: StrategyArgs,
        /// As for `run`.
        #[arg(long)]
        allow_partial: bool,
    },
    /// Stop and remove the service (with sudo).
    Uninstall,
    /// Show whether the service is installed and running.
    Status,
}

#[derive(Debug, Args)]
struct StrategyArgs {
    /// A `general*.bat` file inside a zapret-discord-youtube folder (with its
    /// `bin` and `lists` folders next to it).
    strategy: PathBuf,
    /// service.bat's game filter: extend the IP-list rules to ports 1024-65535.
    #[arg(long, value_enum, default_value_t = GameFilter::Off)]
    game_filter: GameFilter,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error("cannot write output: {0}")]
    Output(#[from] std::io::Error),
    #[cfg(any(windows, target_os = "macos"))]
    #[error(
        "this strategy uses techniques jink cannot perform here (see `jink check`); \
         pass --allow-partial to run it anyway"
    )]
    Partial,
    #[cfg(windows)]
    #[error(transparent)]
    Filter(#[from] jink_windivert::filter::FilterError),
    #[cfg(any(windows, target_os = "macos"))]
    #[error("cannot seed the random generator: {0}")]
    Entropy(getrandom::Error),
    #[cfg(windows)]
    #[error(transparent)]
    Capture(#[from] jink_windivert::RunError),
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    Tunnel(#[from] jink_macos::RunError),
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    Service(#[from] jink_macos::service::ServiceError),
    #[cfg(target_os = "macos")]
    #[error("the strategy must be a .bat file")]
    NotAFile,
    #[cfg(not(any(windows, target_os = "macos")))]
    #[error("`jink run` needs Windows or macOS; `jink check` works here")]
    RunUnsupported,
}

const fn this_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::MacOs
    }
}

fn check(args: &StrategyArgs) -> Result<(), CliError> {
    let config = strategy::load(&args.strategy, args.game_filter)?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "Strategy: {}", args.strategy.display())?;
    for line in report::describe(&config, this_platform()) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

#[cfg(windows)]
fn run(args: &StrategyArgs, allow_partial: bool) -> Result<(), CliError> {
    use std::collections::HashSet;

    use jink_core::engine::PacketEngine;
    use jink_windivert::Event;
    use jink_windivert::filter::{FilterOptions, build};

    let config = strategy::load(&args.strategy, args.game_filter)?;
    let partial = config
        .rules
        .iter()
        .any(|r| !jink_core::desync::unimplemented(r).is_empty());
    if partial && !allow_partial {
        return Err(CliError::Partial);
    }
    let filter = build(&config.capture, FilterOptions::default())?;
    let rules = config.rules.len();
    let entropy = entropy::OsSeeded::new().map_err(CliError::Entropy)?;
    let mut engine = PacketEngine::new(config, Box::new(entropy));
    {
        let mut out = std::io::stdout().lock();
        writeln!(
            out,
            "jink: running {} ({rules} rules). Press Ctrl+C to stop.",
            args.strategy.display()
        )?;
    }
    // Report each distinct problem once, not once per packet. A failed write
    // to stderr cannot be reported anywhere, so it is ignored.
    let mut seen = HashSet::new();
    let mut on_event = |event: Event| {
        let message = match event {
            Event::PlanFailed(e) => format!("rule not applied: {e}"),
            Event::SendFailed(e) => format!("send failed: {e}"),
        };
        if seen.insert(message.clone()) {
            let _ = writeln!(std::io::stderr().lock(), "jink: {message}");
        }
    };
    jink_windivert::run(&mut engine, &filter, &mut on_event)?;
    Ok(())
}

/// The engine for a strategy, and how many of its rules pass traffic
/// unchanged; refused if there are any, unless `allow_partial`.
#[cfg(target_os = "macos")]
fn macos_engine(
    args: &StrategyArgs,
    allow_partial: bool,
) -> Result<(jink_core::engine::stream::StreamEngine, usize), CliError> {
    let config = strategy::load(&args.strategy, args.game_filter)?;
    let entropy = Box::new(entropy::OsSeeded::new().map_err(CliError::Entropy)?);
    let (engine, unsupported) = jink_core::engine::stream::StreamEngine::partial(config, entropy);
    if !unsupported.is_empty() && !allow_partial {
        return Err(CliError::Partial);
    }
    Ok((engine, unsupported.len()))
}

#[cfg(target_os = "macos")]
fn run(args: &StrategyArgs, allow_partial: bool) -> Result<(), CliError> {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use jink_macos::Event;

    let (engine, skipped) = macos_engine(args, allow_partial)?;
    // Report the state each time it changes, and each distinct problem once,
    // not once per connection. A failed write to the terminal cannot be
    // reported anywhere, so it is ignored.
    let state = Mutex::new(String::new());
    let seen = Mutex::new(HashSet::new());
    let summary = jink_macos::run(engine, move |event| {
        let new_state = match event {
            Event::Started { tun } => {
                let _ = writeln!(
                    std::io::stdout().lock(),
                    "jink: started on {tun} ({skipped} rules pass traffic unchanged). \
                     Press Ctrl+C to stop."
                );
                return;
            }
            Event::Online { uplink, ipv6 } => {
                let ipv6 = if ipv6 {
                    "; IPv6 is turned away, so apps use IPv4"
                } else {
                    ""
                };
                format!(
                    "online: all IPv4 traffic goes through jink and leaves through {uplink}{ipv6}"
                )
            }
            Event::Offline => "no network; waiting for one".to_owned(),
            Event::Unavailable(e) => format!("traffic bypasses jink: {e}"),
            Event::RoutesLeft(errors) => {
                report_once(&seen, format!("could not delete routes: {errors:?}"), "");
                return;
            }
            Event::Relay { server, error } => {
                report_once(
                    &seen,
                    error.to_string(),
                    &format!(" (first seen with {server})"),
                );
                return;
            }
            Event::Desync { server, error } => {
                report_once(
                    &seen,
                    error.to_string(),
                    &format!(" (first seen with {server})"),
                );
                return;
            }
            Event::StateFile(e) => {
                report_once(
                    &seen,
                    format!("cannot record routes for cleanup after a crash: {e}"),
                    "",
                );
                return;
            }
            Event::CaptureEnded(e) => {
                report_once(&seen, format!("handshake capture stopped: {e}"), "");
                return;
            }
            Event::Foreign(source) => {
                report_once(
                    &seen,
                    format!("dropped a connection from {source}, which did not come through jink"),
                    "",
                );
                return;
            }
        };
        let changed = state.lock().is_ok_and(|mut last| {
            let changed = *last != new_state;
            last.clone_from(&new_state);
            changed
        });
        if changed {
            let _ = writeln!(std::io::stdout().lock(), "jink: {new_state}");
        }
    })?;
    writeln!(
        std::io::stdout().lock(),
        "jink: stopped; routes restored. TCP: {} connected ({} desynced), {} failed. \
         UDP: {} flows ({} datagrams after decoys), {} failed.",
        summary.tcp_connected,
        summary.tcp_desynced,
        summary.tcp_failed,
        summary.udp_flows,
        summary.udp_decoyed,
        summary.udp_failed
    )?;
    Ok(())
}

/// Prints `kind` (with `example`) unless it was printed before.
#[cfg(target_os = "macos")]
fn report_once(
    seen: &std::sync::Mutex<std::collections::HashSet<String>>,
    kind: String,
    example: &str,
) {
    let line = format!("jink: {kind}{example}");
    if seen.lock().is_ok_and(|mut s| s.insert(kind)) {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run(args: &StrategyArgs, allow_partial: bool) -> Result<(), CliError> {
    let _ = (args, allow_partial);
    Err(CliError::RunUnsupported)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Check(args) => check(args),
        Command::Run {
            strategy,
            allow_partial,
        } => run(strategy, *allow_partial),
        #[cfg(target_os = "macos")]
        Command::Service { action } => match action {
            ServiceAction::Install {
                strategy,
                allow_partial,
            } => service::install(strategy, *allow_partial),
            ServiceAction::Uninstall => service::uninstall(),
            ServiceAction::Status => service::status(),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Nothing else can be done if stderr itself is unwritable.
            let _ = writeln!(std::io::stderr().lock(), "jink: {e}");
            ExitCode::FAILURE
        }
    }
}
