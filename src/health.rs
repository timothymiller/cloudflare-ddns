//! Liveness file for container health checks.
//!
//! The release image is `FROM scratch`, so a Docker `HEALTHCHECK` cannot run
//! curl or a shell. Instead the update loop writes a deadline (Unix seconds) to
//! a small file before each sleep, each update cycle and each domain or WAF list
//! within a cycle, and `--health` exits 0
//! only while that deadline is still in the future. A loop that hangs or dies
//! stops refreshing the file and the container turns unhealthy.
//!
//! Failed updates do not make the container unhealthy: restarting it cannot fix
//! a Cloudflare outage or a bad token, and failures are already reported through
//! notifications and heartbeats.

use crate::pp::{self, PP};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Slack for one unit of work: IP detection, or the Cloudflare API calls for
/// one domain or WAF list. Each request is bounded by its timeout and the loop
/// refreshes the deadline between units, so a cycle over many domains never
/// has to fit in this budget. Generous on purpose: a false "unhealthy" is
/// worse than a late one.
const CYCLE_BUDGET: Duration = Duration::from_secs(600);

static WRITE_WARNED: AtomicBool = AtomicBool::new(false);

/// Health file location: `HEALTH_FILE`, else `cloudflare-ddns.health` in the
/// system temp directory (`/tmp` in the container image).
pub fn path() -> PathBuf {
    match std::env::var("HEALTH_FILE") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
        _ => std::env::temp_dir().join("cloudflare-ddns.health"),
    }
}

/// Records that the loop is alive and will check in again within `wait`
/// plus one update cycle. Write failures (e.g. a read-only root filesystem)
/// are reported once and otherwise ignored.
pub fn mark_alive(wait: Duration, timeouts: Duration, ppfmt: &PP) {
    let deadline = unix_now() + wait + CYCLE_BUDGET + timeouts;
    if let Err(e) = write_deadline(&path(), deadline) {
        if !WRITE_WARNED.swap(true, Ordering::Relaxed) {
            ppfmt.warningf(
                pp::EMOJI_WARNING,
                &format!("Could not write health file (--health will report unhealthy): {e}"),
            );
        }
    }
}

/// Refreshes the deadline from inside an update cycle, between units of work.
/// Silent on failure: the loop-level `mark_alive` already warned once.
pub fn mark_progress(timeouts: Duration) {
    let _ = write_deadline(&path(), unix_now() + CYCLE_BUDGET + timeouts);
}

/// Runs the `--health` check. Returns the process exit code.
pub fn run_check() -> i32 {
    let path = path();
    match check(&path, unix_now()) {
        Ok(()) => {
            println!("healthy");
            0
        }
        Err(e) => {
            eprintln!("unhealthy: {e}");
            1
        }
    }
}

fn check(path: &Path, now: Duration) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "cannot read {} ({e}); the updater has not started or is not running with --repeat",
            path.display()
        )
    })?;
    let deadline: u64 = content
        .trim()
        .parse()
        .map_err(|_| format!("malformed health file {}", path.display()))?;
    let overdue = now.as_secs().saturating_sub(deadline);
    if overdue > 0 {
        return Err(format!("update loop is {overdue}s overdue"));
    }
    Ok(())
}

/// Writes atomically so `--health` never reads a half-written file.
fn write_deadline(path: &Path, deadline: Duration) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, deadline.as_secs().to_string())?;
    std::fs::rename(&tmp, path)
}

fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_before_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h");
        write_deadline(&path, Duration::from_secs(1000)).unwrap();
        assert!(check(&path, Duration::from_secs(999)).is_ok());
        assert!(check(&path, Duration::from_secs(1000)).is_ok());
    }

    #[test]
    fn unhealthy_after_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h");
        write_deadline(&path, Duration::from_secs(1000)).unwrap();
        let err = check(&path, Duration::from_secs(1030)).unwrap_err();
        assert!(err.contains("30s overdue"), "{err}");
    }

    #[test]
    fn unhealthy_when_missing_or_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h");
        assert!(check(&path, Duration::ZERO).is_err());
        std::fs::write(&path, "not a number").unwrap();
        assert!(check(&path, Duration::ZERO)
            .unwrap_err()
            .contains("malformed"));
    }

    #[test]
    fn write_replaces_previous_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h");
        write_deadline(&path, Duration::from_secs(10)).unwrap();
        write_deadline(&path, Duration::from_secs(5000)).unwrap();
        assert!(check(&path, Duration::from_secs(100)).is_ok());
        assert!(!path.with_extension("tmp").exists());
    }
}
