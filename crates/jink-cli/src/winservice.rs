//! `jink service` on Windows: the jink daemon installed as a Windows
//! service, so it runs at every startup and the apps (or `jink ctl`) can
//! control it without Administrator.

use std::io::Write;

use jink_daemon::service::{self, Status};

use crate::CliError;

/// Installs the service and starts it.
pub(crate) fn install() -> Result<(), CliError> {
    service::install()?;
    let log = jink_daemon::home()?.join("jink.log");
    writeln!(
        std::io::stdout().lock(),
        "jink: the service is installed and runs now and at every startup, \
         from this jink.exe (do not move it).\n\
         jink: control it with `jink ctl` (for example `jink ctl start`); \
         its log is {}.\n\
         jink: remove it with `jink service uninstall` (as Administrator).",
        log.display()
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
        Status::Running { pid } => format!(
            "running{}; `jink ctl status` shows what it does",
            pid.map_or_else(String::new, |p| format!(" (process {p})"))
        ),
        Status::Stopped { state } => format!(
            "installed but not running ({state}); see {}",
            jink_daemon::home()?.join("jink.log").display()
        ),
    };
    writeln!(std::io::stdout().lock(), "jink service: {line}")?;
    Ok(())
}
