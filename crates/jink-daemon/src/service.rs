//! The daemon as a Windows service: installed to start at every startup and
//! to restart if it crashes, run by the system account, from where the
//! installing `jink.exe` is (the installer puts it in Program Files).

use std::ffi::OsString;
use std::io;
use std::time::{Duration, Instant};

use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::windows_run::{SERVICE, home};

const DESCRIPTION: &str =
    "jink: unblocks YouTube and Discord. Runs the engine the jink app controls.";
/// How long a stop may take before it is given up on.
const STOP_LIMIT: Duration = Duration::from_secs(20);
/// Windows' answer when no service has that name.
const NO_SUCH_SERVICE: i32 = 1060;
/// Windows' answer when a service to stop is not running.
const NOT_RUNNING: i32 = 1062;
/// Windows' answer when access is denied.
const ACCESS_DENIED: i32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("installing or removing the service needs Administrator")]
    NotAdministrator,
    #[error("cannot find jink's own executable: {0}")]
    Executable(io::Error),
    #[error("the service did not stop within {} s", STOP_LIMIT.as_secs())]
    StopTimedOut,
    #[error("cannot remove the daemon's folder: {0}")]
    Folder(io::Error),
    #[error(transparent)]
    Home(#[from] crate::windows_run::DaemonError),
    #[error("the service manager refused: {0}")]
    Manager(windows_service::Error),
}

impl From<windows_service::Error> for ServiceError {
    fn from(error: windows_service::Error) -> Self {
        match &error {
            windows_service::Error::Winapi(e) if e.raw_os_error() == Some(ACCESS_DENIED) => {
                Self::NotAdministrator
            }
            _ => Self::Manager(error),
        }
    }
}

/// Where the service stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    NotInstalled,
    Running {
        pid: Option<u32>,
    },
    /// Installed and not running (stopped, or on its way).
    Stopped {
        state: String,
    },
}

/// Installs the service to run this `jink.exe daemon` and starts it; an
/// installed service is stopped and pointed here first (a new version
/// replaces the old).
///
/// # Errors
/// Without Administrator, or if the service manager refuses.
pub fn install() -> Result<(), ServiceError> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE),
        display_name: OsString::from("jink"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().map_err(ServiceError::Executable)?,
        launch_arguments: vec![OsString::from("daemon")],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let service = match manager.open_service(SERVICE, access) {
        Ok(service) => {
            stop(&service)?;
            service.change_config(&info)?;
            service
        }
        Err(e) if os_error(&e) == Some(NO_SUCH_SERVICE) => manager.create_service(&info, access)?,
        Err(e) => return Err(e.into()),
    };
    service.set_description(DESCRIPTION)?;
    // Back after 5 s if it crashes, every time (the count resets daily).
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_hours(24)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    service.start::<&str>(&[])?;
    Ok(())
}

/// Stops and removes the service and its folder (settings and log); `false`
/// if it was not installed.
///
/// # Errors
/// Without Administrator, or if the service manager refuses.
pub fn uninstall() -> Result<bool, ServiceError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match manager.open_service(SERVICE, access) {
        Ok(service) => service,
        Err(e) if os_error(&e) == Some(NO_SUCH_SERVICE) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    stop(&service)?;
    service.delete()?;
    match std::fs::remove_dir_all(home()?) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(ServiceError::Folder(e)),
        _ => Ok(true),
    }
}

/// Whether the service is installed and running.
///
/// # Errors
/// If the service manager refuses.
pub fn status() -> Result<Status, ServiceError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(SERVICE, ServiceAccess::QUERY_STATUS) {
        Ok(service) => service,
        Err(e) if os_error(&e) == Some(NO_SUCH_SERVICE) => return Ok(Status::NotInstalled),
        Err(e) => return Err(e.into()),
    };
    let status = service.query_status()?;
    Ok(match status.current_state {
        ServiceState::Running => Status::Running {
            pid: status.process_id,
        },
        state => Status::Stopped {
            state: format!("{state:?}"),
        },
    })
}

/// Stops the service and waits until it has.
fn stop(service: &Service) -> Result<(), ServiceError> {
    match service.stop() {
        Err(e) if os_error(&e) == Some(NOT_RUNNING) => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let began = Instant::now();
    while service.query_status()?.current_state != ServiceState::Stopped {
        if began.elapsed() > STOP_LIMIT {
            return Err(ServiceError::StopTimedOut);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

fn os_error(error: &windows_service::Error) -> Option<i32> {
    match error {
        windows_service::Error::Winapi(e) => e.raw_os_error(),
        _ => None,
    }
}
