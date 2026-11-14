//! `jink service` on macOS: a strategy installed as a launchd daemon, so jink
//! runs at every startup without a terminal.

use std::io::Write;
use std::path::{Path, PathBuf};

use jink_macos::service::{self, Install, Status};

use crate::{CliError, StrategyArgs, macos_engine, strategy};

/// The strategy's folder inside the service's.
const STRATEGY: &str = "strategy";

/// Checks the strategy as `jink run` would, then installs and starts it.
pub(crate) fn install(args: &StrategyArgs, allow_partial: bool) -> Result<(), CliError> {
    let (_, skipped) = macos_engine(args, allow_partial)?;
    let files: Vec<(PathBuf, PathBuf)> = strategy::files(&args.strategy)?
        .into_iter()
        .map(|(from, to)| (from, Path::new(STRATEGY).join(to)))
        .collect();
    let bat = args
        .strategy
        .file_name()
        .map(|name| Path::new(service::HOME).join(STRATEGY).join(name))
        .ok_or(CliError::NotAFile)?;
    let mut run = vec![
        "run".to_owned(),
        bat.display().to_string(),
        "--game-filter".to_owned(),
        args.game_filter.arg().to_owned(),
    ];
    if allow_partial {
        run.push("--allow-partial".to_owned());
    }
    service::install(&Install { files, args: run })?;
    writeln!(
        std::io::stdout().lock(),
        "jink: installed {} as a service ({skipped} rules pass traffic unchanged). \
         It runs now and at every startup.\n\
         jink: its output goes to {}. Remove it with: sudo \"{}\" service uninstall",
        args.strategy.display(),
        service::LOG,
        Path::new(service::HOME).join("jink").display()
    )?;
    Ok(())
}

pub(crate) fn uninstall() -> Result<(), CliError> {
    let line = if service::uninstall()? {
        "the service is stopped and removed"
    } else {
        "the service is not installed"
    };
    writeln!(std::io::stdout().lock(), "jink: {line}.")?;
    Ok(())
}

pub(crate) fn status() -> Result<(), CliError> {
    let strategy = installed_strategy().unwrap_or_else(|| "an unknown strategy".to_owned());
    let line = match service::status()? {
        Status::NotInstalled => "not installed".to_owned(),
        Status::NotLoaded => {
            format!("installed ({strategy}), not loaded: it starts at the next startup")
        }
        Status::Running { pid } => format!("running {strategy} (process {pid})"),
        Status::Stopped { last_exit } => format!(
            "installed ({strategy}) but stopped (last exit: {}); see {}",
            last_exit.as_deref().unwrap_or("unknown"),
            service::LOG
        ),
    };
    writeln!(std::io::stdout().lock(), "jink service: {line}")?;
    Ok(())
}

/// The name of the installed strategy's `.bat` file.
fn installed_strategy() -> Option<String> {
    std::fs::read_dir(Path::new(service::HOME).join(STRATEGY))
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("bat"))
        })
        .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
}
