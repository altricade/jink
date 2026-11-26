//! TCP timestamps, which Windows leaves off. A fake that fools with them
//! (`--dpi-desync-fooling=ts`) needs the connection to use them, so zapret
//! turns them on before every run (`service.bat`, `tcp_enable`); jink does
//! the same when its strategy fools with them.

use std::io;
use std::process::Command;

/// Turns TCP timestamps on for the whole system (needs Administrator). The
/// setting stays after jink stops, as with zapret.
///
/// # Errors
/// If `netsh` cannot be run or refuses.
pub fn enable_tcp_timestamps() -> io::Result<()> {
    let output = Command::new("netsh")
        .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ))
    }
}
