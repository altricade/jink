//! `jink`: check and run zapret-discord-youtube strategies.
//!
//! - `jink check <strategy.bat>` (any OS) shows what jink will do with it.
//! - `jink run <strategy.bat>` runs it: on Windows (as Administrator) with
//!   WinDivert, `WinDivert64.sys` next to `jink.exe`; on macOS (with sudo)
//!   through a utun interface (TCP desync; UDP decoys not yet).

#[cfg(any(windows, target_os = "macos", test))]
mod entropy;
mod report;
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

#[cfg(target_os = "macos")]
fn run(args: &StrategyArgs, allow_partial: bool) -> Result<(), CliError> {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use jink_core::engine::stream::StreamEngine;
    use jink_macos::Event;

    let config = strategy::load(&args.strategy, args.game_filter)?;
    let entropy = Box::new(entropy::OsSeeded::new().map_err(CliError::Entropy)?);
    let (engine, unsupported) = StreamEngine::partial(config, entropy);
    if !unsupported.is_empty() && !allow_partial {
        return Err(CliError::Partial);
    }
    // Report each distinct problem once, not once per connection. A failed
    // write to the terminal cannot be reported anywhere, so it is ignored.
    let seen = Mutex::new(HashSet::new());
    let skipped = unsupported.len();
    let summary = jink_macos::run(engine, move |event| {
        // (kind of problem, example): each kind is reported once.
        let (kind, example) = match event {
            Event::Ready { tun, uplink } => {
                let _ = writeln!(
                    std::io::stdout().lock(),
                    "jink: all IPv4 traffic now goes through {tun} and leaves through {uplink}.\n\
                     jink: TCP desync is active ({skipped} rules pass traffic unchanged); \
                     UDP decoys are not sent yet.\n\
                     jink: press Ctrl+C to stop."
                );
                return;
            }
            Event::Relay { server, error } => {
                (error.to_string(), format!(" (first seen with {server})"))
            }
            Event::Desync { server, error } => {
                (error.to_string(), format!(" (first seen with {server})"))
            }
            Event::CaptureEnded(e) => (format!("handshake capture stopped: {e}"), String::new()),
            Event::Foreign(source) => (
                format!("dropped a connection from {source}, which did not come through jink"),
                String::new(),
            ),
        };
        let first = seen.lock().is_ok_and(|mut s| s.insert(kind.clone()));
        if first {
            let _ = writeln!(std::io::stderr().lock(), "jink: {kind}{example}");
        }
    })?;
    writeln!(
        std::io::stdout().lock(),
        "jink: stopped; routes restored. TCP: {} connected ({} desynced), {} failed. \
         UDP: {} flows, {} failed.",
        summary.tcp_connected,
        summary.tcp_desynced,
        summary.tcp_failed,
        summary.udp_flows,
        summary.udp_failed
    )?;
    Ok(())
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
