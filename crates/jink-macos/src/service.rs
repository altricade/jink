//! Running jink as a launchd daemon: started at boot (before anyone logs
//! in), restarted if it crashes, stopped with the system.
//!
//! The daemon runs as root, so everything it runs and reads is copied into a
//! root-owned folder: a root daemon must not run a binary its user could
//! replace, and macOS keeps root daemons out of `~/Downloads` and the like.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The daemon's launchd label.
pub const LABEL: &str = "jink";
/// The folder the daemon runs from.
pub const HOME: &str = "/Library/Application Support/jink";
/// The daemon's launchd definition.
pub const PLIST: &str = "/Library/LaunchDaemons/jink.plist";
/// Where the daemon's output goes.
pub const LOG: &str = "/Library/Logs/jink.log";
/// The jink binary inside [`HOME`].
const BINARY: &str = "jink";
const LAUNCHCTL: &str = "/bin/launchctl";

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("installing or removing the service needs root: run jink with sudo")]
    NotRoot,
    #[error("cannot find jink's own binary: {0}")]
    OwnBinary(io::Error),
    #[error("cannot copy {path}: {source}")]
    Copy { path: PathBuf, source: io::Error },
    #[error("cannot write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("cannot run launchctl: {0}")]
    Launchctl(io::Error),
    #[error("launchctl could not start the service: {0}")]
    Bootstrap(String),
}

/// What to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// Files to copy: the source, and the path inside [`HOME`].
    pub files: Vec<(PathBuf, PathBuf)>,
    /// The daemon's arguments to jink (`run`, the strategy inside [`HOME`],
    /// options).
    pub args: Vec<String>,
}

/// The service as launchd sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    NotInstalled,
    /// Installed but not loaded (launchd will load it at the next boot).
    NotLoaded,
    Running {
        pid: u32,
    },
    /// Loaded, not running: it exited (and was not restarted).
    Stopped {
        last_exit: Option<String>,
    },
}

/// Installs the daemon and starts it, replacing an installed one.
///
/// # Errors
/// If not root, or a file cannot be copied or written (the service installed
/// before, if any, is then left as it was), or launchd refuses it.
pub fn install(spec: &Install) -> Result<(), ServiceError> {
    let own = std::env::current_exe().map_err(ServiceError::OwnBinary)?;
    let home = Path::new(HOME);
    // Everything is copied next to the old folder first, so a failure leaves
    // the installed service alone.
    let staging = home.with_extension("new");
    remove(&staging, |p| fs::remove_dir_all(p))?;
    fs::create_dir_all(&staging).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => ServiceError::NotRoot,
        _ => ServiceError::Write {
            path: staging.clone(),
            source: e,
        },
    })?;
    let copies = std::iter::once((own, PathBuf::from(BINARY), 0o755)).chain(
        spec.files
            .iter()
            .map(|(from, to)| (from.clone(), to.clone(), 0o644)),
    );
    for (from, to, mode) in copies {
        copy(&from, &staging.join(to), mode)?;
    }
    let definition = plist(&home.join(BINARY), &spec.args);

    stop();
    let replace = |path: &Path, source| ServiceError::Write {
        path: path.to_path_buf(),
        source,
    };
    match fs::remove_dir_all(home) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(replace(home, e)),
        _ => {}
    }
    fs::rename(&staging, home).map_err(|e| replace(home, e))?;
    write_file(Path::new(PLIST), definition.as_bytes(), 0o644)?;
    let output = Command::new(LAUNCHCTL)
        .args(["bootstrap", "system", PLIST])
        .output()
        .map_err(ServiceError::Launchctl)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ServiceError::Bootstrap(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

/// Stops and removes the daemon, its folder and its log, returning whether
/// there was anything to remove.
///
/// # Errors
/// If not root, or a file cannot be removed.
pub fn uninstall() -> Result<bool, ServiceError> {
    stop();
    let plist = remove(Path::new(PLIST), |p| fs::remove_file(p))?;
    let log = remove(Path::new(LOG), |p| fs::remove_file(p))?;
    let home = remove(Path::new(HOME), |p| fs::remove_dir_all(p))?;
    Ok(plist || log || home)
}

/// The service's state.
///
/// # Errors
/// If launchctl cannot be run.
pub fn status() -> Result<Status, ServiceError> {
    if !Path::new(PLIST).exists() {
        return Ok(Status::NotInstalled);
    }
    let output = Command::new(LAUNCHCTL)
        .args(["print", &format!("system/{LABEL}")])
        .output()
        .map_err(ServiceError::Launchctl)?;
    if !output.status.success() {
        return Ok(Status::NotLoaded);
    }
    Ok(parse_print(&String::from_utf8_lossy(&output.stdout)))
}

/// Unloads the daemon if it is loaded: launchd stops it with SIGTERM, and
/// jink restores the routes. Not being loaded is not an error.
fn stop() {
    // The only failure that matters, a daemon that stays loaded, makes the
    // bootstrap that follows fail, which is reported.
    let _ = Command::new(LAUNCHCTL)
        .args(["bootout", &format!("system/{LABEL}")])
        .output();
}

fn copy(from: &Path, to: &Path, mode: u32) -> Result<(), ServiceError> {
    let failed = |source| ServiceError::Copy {
        path: from.to_path_buf(),
        source,
    };
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).map_err(failed)?;
    }
    fs::copy(from, to).map_err(failed)?;
    // Not the source's mode: nothing the daemon runs or reads may be
    // writable by anyone but root.
    fs::set_permissions(to, fs::Permissions::from_mode(mode)).map_err(failed)
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), ServiceError> {
    let failed = |source: io::Error| match source.kind() {
        io::ErrorKind::PermissionDenied => ServiceError::NotRoot,
        _ => ServiceError::Write {
            path: path.to_path_buf(),
            source,
        },
    };
    fs::write(path, contents).map_err(failed)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(failed)
}

/// Removes `path` with `how`, returning whether it was there.
fn remove(path: &Path, how: impl FnOnce(&Path) -> io::Result<()>) -> Result<bool, ServiceError> {
    match how(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Err(ServiceError::NotRoot),
        Err(e) => Err(ServiceError::Write {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// The launchd definition: run at load (boot), and again whenever jink
/// exits with an error or crashes, but not after a clean stop.
fn plist(binary: &Path, args: &[String]) -> String {
    let arguments: String = std::iter::once(binary.display().to_string())
        .chain(args.iter().cloned())
        .map(|a| format!("\n        <string>{}</string>", escape(&a)))
        .collect::<Vec<_>>()
        .concat();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>{arguments}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        label = escape(LABEL),
        log = escape(LOG),
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The state from `launchctl print system/<label>` output.
fn parse_print(output: &str) -> Status {
    let field = |name: &str| {
        output.lines().find_map(|line| {
            let (key, value) = line.trim().split_once(" = ")?;
            (key == name).then(|| value.trim().to_owned())
        })
    };
    let pid = field("pid").and_then(|p| p.parse().ok());
    match (field("state").as_deref(), pid) {
        (Some("running"), Some(pid)) => Status::Running { pid },
        _ => Status::Stopped {
            last_exit: field("last exit code"),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Status, parse_print, plist};

    #[test]
    fn definition_runs_jink_at_boot_and_after_crashes() {
        let args = [
            "run",
            "/Library/Application Support/jink/strategy/general (ALT).bat",
        ]
        .map(String::from);
        let text = plist(Path::new("/Library/Application Support/jink/jink"), &args);
        assert!(text.contains(
            "<array>\n        <string>/Library/Application Support/jink/jink</string>\n        \
             <string>run</string>\n        \
             <string>/Library/Application Support/jink/strategy/general (ALT).bat</string>\n    \
             </array>"
        ));
        assert!(text.contains("<key>Label</key>\n    <string>jink</string>"));
        assert!(text.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(text.contains("<key>SuccessfulExit</key>\n        <false/>"));
        assert!(
            text.contains(
                "<key>StandardErrorPath</key>\n    <string>/Library/Logs/jink.log</string>"
            )
        );
    }

    #[test]
    fn arguments_are_escaped() {
        let text = plist(Path::new("/j"), &["a<b>&c".to_owned()]);
        assert!(text.contains("<string>a&lt;b&gt;&amp;c</string>"));
    }

    #[test]
    fn launchctl_print_gives_the_state() {
        let running = "system/jink = {\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/jink.plist\n\
                       \tstate = running\n\n\tprogram = /Library/Application Support/jink/jink\n\
                       \tpid = 4242\n\tlast exit code = (never exited)\n}\n";
        assert_eq!(parse_print(running), Status::Running { pid: 4242 });
        let stopped = "system/jink = {\n\tstate = not running\n\tlast exit code = 1\n}\n";
        assert_eq!(
            parse_print(stopped),
            Status::Stopped {
                last_exit: Some("1".into())
            }
        );
        assert_eq!(parse_print(""), Status::Stopped { last_exit: None });
        // Fields are matched by their whole name.
        let similar = "\tpid file = 9\n\tstate = running\n\tpid = 7\n";
        assert_eq!(parse_print(similar), Status::Running { pid: 7 });
    }
}
