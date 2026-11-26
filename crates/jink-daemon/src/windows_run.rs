//! The daemon on Windows: a Windows service (the service manager starts it
//! at every startup and stops it on request or at shutdown), its control
//! pipe, its state and log in `%ProgramData%\jink`. Started from a terminal
//! instead, it runs there until Ctrl+C, for testing.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use interprocess::os::windows::named_pipe::PipeListenerOptions;
use interprocess::os::windows::named_pipe::pipe_mode;
use interprocess::os::windows::named_pipe::tokio::PipeListener;
use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use tokio::sync::oneshot;
use widestring::U16CString;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::daemon::{Setup, spawn};
use crate::probe::Prober;
use crate::server;
use crate::windows::Windows;

/// The service's name.
pub const SERVICE: &str = "jink";
/// The control pipe.
pub const PIPE: &str = r"\\.\pipe\jink";
/// The state file and the log, inside the daemon's folder.
const STATE: &str = "state.json";
const LOG: &str = "jink.log";
/// A log larger than this at start is moved to `jink.log.old`.
const LOG_LIMIT: u64 = 1024 * 1024;
/// Who may use the pipe: the system and administrators fully; signed-in
/// users may read and write it, but not create instances of it (which
/// would let them stand in for the daemon); network users never (remote
/// clients are refused as well). `0x12019b` is `FILE_GENERIC_READ` plus
/// writing data, extended attributes and attributes, without
/// `FILE_CREATE_PIPE_INSTANCE`; clients ask for exactly that.
const PIPE_ACCESS: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)(D;;GA;;;NU)";
/// Windows' answer when the process was not started by the service manager.
const NOT_A_SERVICE: i32 = 1063;
/// How long the service manager is told stopping may take.
const STOP_HINT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("the jink daemon is already running")]
    AlreadyRunning,
    #[error("the daemon needs Administrator: run it from an Administrator terminal")]
    NotAdministrator,
    #[error("%ProgramData% is not set")]
    NoProgramData,
    #[error("cannot set up the control pipe {PIPE}: {0}")]
    Pipe(io::Error),
    #[error("cannot create the daemon's folder {path}: {source}")]
    Folder { path: String, source: io::Error },
    #[error("cannot start the async runtime: {0}")]
    Runtime(io::Error),
    #[error("cannot set up the certificate checks for finding strategies: {0}")]
    Checks(rustls::Error),
    #[error("the service manager refused: {0}")]
    Service(windows_service::Error),
}

/// The daemon's folder: `%ProgramData%\jink`.
///
/// # Errors
/// If `%ProgramData%` is not set.
pub fn home() -> Result<PathBuf, DaemonError> {
    std::env::var_os("ProgramData")
        .map(|data| PathBuf::from(data).join("jink"))
        .ok_or(DaemonError::NoProgramData)
}

/// Runs the daemon: as the service when the service manager started this
/// process, otherwise in this terminal until Ctrl+C.
///
/// # Errors
/// If it cannot set up, or the control pipe fails.
pub fn run() -> Result<(), DaemonError> {
    match service_dispatcher::start(SERVICE, service_main) {
        Ok(()) => Ok(()),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_A_SERVICE) => {
            let log = Log::Terminal;
            runtime()?.block_on(serve(&home()?, log, async {
                // Without Ctrl+C handling, Ctrl+C still ends the process.
                let _ = tokio::signal::ctrl_c().await;
            }))
        }
        Err(e) => Err(DaemonError::Service(e)),
    }
}

/// Called by the service manager on a thread of its own; returns when the
/// service has stopped.
extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let ended = as_service();
    if let Err(e) = &ended {
        // Before the log file is open, or the log itself failed: the
        // service manager's exit code is all that is left.
        Log::Terminal.line(&e.to_string());
    }
}

fn as_service() -> Result<(), DaemonError> {
    let home = home()?;
    let (stop, stopped) = oneshot::channel();
    let mut stop = Some(stop);
    let status = service_control_handler::register(SERVICE, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(stop) = stop.take() {
                // The daemon already ended: nothing to stop.
                let _ = stop.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(DaemonError::Service)?;
    let report = |state, exit: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: if exit == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(exit)
            },
            checkpoint: 0,
            wait_hint: if state == ServiceState::StopPending {
                STOP_HINT
            } else {
                Duration::ZERO
            },
            process_id: None,
        })
    };
    report(ServiceState::Running, 0).map_err(DaemonError::Service)?;
    let ended = Log::file(&home).and_then(|log| {
        runtime()?.block_on(serve(&home, log, async {
            // A dropped sender (the handler is gone) stops the daemon too.
            let _ = stopped.await;
        }))
    });
    // Too late to tell anyone if the service manager does not listen.
    let _ = report(ServiceState::StopPending, 0);
    let _ = report(ServiceState::Stopped, u32::from(ended.is_err()));
    ended
}

fn runtime() -> Result<tokio::runtime::Runtime, DaemonError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)
}

async fn serve(home: &Path, log: Log, until: impl Future<Output = ()>) -> Result<(), DaemonError> {
    std::fs::create_dir_all(home).map_err(|source| match source.kind() {
        io::ErrorKind::PermissionDenied => DaemonError::NotAdministrator,
        _ => DaemonError::Folder {
            path: home.display().to_string(),
            source,
        },
    })?;
    let listener = listen()?;
    let probe = Prober::system().map_err(DaemonError::Checks)?;
    let log = std::sync::Arc::new(log);
    let (handle, task) = spawn(Setup {
        backend: Windows,
        probe,
        saved_at: home.join(STATE),
        log: Box::new({
            let log = log.clone();
            move |line| log.line(line)
        }),
    });
    log.line("started");
    tokio::pin!(until);
    let ended = loop {
        tokio::select! {
            () = &mut until => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(stream) => {
                    let handle = handle.clone();
                    tokio::spawn(async move {
                        let (read, write) = tokio::io::split(stream);
                        // An app that goes away mid-request is no news.
                        let _ = server::connection(read, write, &handle).await;
                    });
                }
                Err(e) => break Err(DaemonError::Pipe(e)),
            },
        }
    };
    handle.shut_down().await;
    if let Err(e) = task.await {
        log.line(&format!("the daemon's task failed: {e}"));
    }
    log.line("stopped");
    ended
}

/// The control pipe, open to signed-in users. Creating its first instance
/// fails if another process has the pipe (a daemon already running).
fn listen() -> Result<PipeListener<pipe_mode::Bytes, pipe_mode::Bytes>, DaemonError> {
    let access =
        U16CString::from_str(PIPE_ACCESS).map_err(|e| DaemonError::Pipe(io::Error::other(e)))?;
    let descriptor = SecurityDescriptor::deserialize(&access).map_err(DaemonError::Pipe)?;
    PipeListenerOptions::new()
        .path(PIPE)
        .security_descriptor(Some(descriptor))
        .create_tokio_duplex::<pipe_mode::Bytes>()
        .map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => DaemonError::AlreadyRunning,
            _ => DaemonError::Pipe(e),
        })
}

/// Where the daemon's log lines go.
#[derive(Debug)]
enum Log {
    /// Its terminal (started by hand).
    Terminal,
    /// `jink.log` in its folder (as the service, which has no terminal).
    File(Mutex<File>),
}

impl Log {
    fn file(home: &Path) -> Result<Self, DaemonError> {
        let folder = |source| DaemonError::Folder {
            path: home.display().to_string(),
            source,
        };
        std::fs::create_dir_all(home).map_err(folder)?;
        let path = home.join(LOG);
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_LIMIT) {
            let mut old = OsString::from(path.as_os_str());
            old.push(".old");
            std::fs::rename(&path, old).map_err(folder)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(folder)?;
        Ok(Self::File(Mutex::new(file)))
    }

    /// A log that cannot be written cannot report that either.
    fn line(&self, line: &str) {
        match self {
            Self::Terminal => {
                let _ = writeln!(io::stderr().lock(), "jink: {line}");
            }
            Self::File(file) => {
                if let Ok(mut file) = file.lock() {
                    let _ = writeln!(file, "jink: {line}");
                }
            }
        }
    }
}
