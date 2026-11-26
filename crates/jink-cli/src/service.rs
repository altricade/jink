//! `jink service` on macOS: the jink daemon installed as a launchd service,
//! so it runs at every startup and the apps (or `jink ctl`) can control it
//! without a terminal or a password.

use std::io::Write;
use std::path::Path;

use jink_macos::service::{self, Install, Status};

use crate::CliError;

/// Installs the daemon and starts it.
pub(crate) fn install() -> Result<(), CliError> {
    service::install(&Install {
        files: Vec::new(),
        args: vec!["daemon".to_owned()],
    })?;
    writeln!(
        std::io::stdout().lock(),
        "jink: the service is installed and runs now and at every startup.\n\
         jink: control it with `jink ctl` (for example `jink ctl start`); \
         its log is {}.\n\
         jink: remove it with: sudo \"{}\" service uninstall",
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
    let line = match service::status()? {
        Status::NotInstalled => "not installed".to_owned(),
        Status::NotLoaded => "installed, not loaded: it starts at the next startup".to_owned(),
        Status::Running { pid } => {
            format!("running (process {pid}); `jink ctl status` shows what it does")
        }
        Status::Stopped { last_exit } => format!(
            "installed but stopped (last exit: {}); see {}",
            last_exit.as_deref().unwrap_or("unknown"),
            service::LOG
        ),
    };
    writeln!(std::io::stdout().lock(), "jink service: {line}")?;
    Ok(())
}
