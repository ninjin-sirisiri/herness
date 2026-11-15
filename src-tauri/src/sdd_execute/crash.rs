//! Test-only crash injection at the durable H4 boundaries.
//!
//! The H4 lifecycle acceptance test must prove what a real process does when it
//! dies at a specific durable boundary: before the host commit, after the commit
//! exists but before its result is recorded, after the result is recorded but
//! before the H4 snapshot stores the Task completion, and before the
//! compatibility ledger replaces its destination. A dropped `SIGKILL` cannot
//! name such a boundary, so this module offers four explicit points.
//!
//! # Production isolation
//!
//! The only way to arm this module is [`arm`], and the only caller is the
//! explicit windowless H4 lifecycle launcher
//! ([`crate::lifecycle::h4`]). The launcher accepts the point only together with
//! `--h4-lifecycle-test`; a flag on its own is rejected by the launch parser. No
//! environment variable is read here, and no production path ever arms it. The
//! injection sites call [`hit`], which reads one process-global atomic that
//! stays zero for the whole normal desktop process, so a production run performs
//! exactly one relaxed load per boundary and never exits for a test.
//!
//! # The exit
//!
//! [`hit`] prints one `H4_LIFECYCLE_CRASH:` line with the point and pid, flushes
//! stdout, and exits with [`CRASH_EXIT_CODE`]. It intentionally does not run a
//! destructor, a quit hook, or a graceful stop: the point exists to observe the
//! durable state a crash leaves behind.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

/// Stable process exit code of an injected crash.
pub const CRASH_EXIT_CODE: i32 = 70;

/// One durable boundary the test can crash at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    /// The commit intent is durable and no Git process has run.
    BeforeHostCommit,
    /// The real Git commit exists and the H4 journal result is not recorded.
    AfterHostCommit,
    /// The commit result is recorded and the H4 completion snapshot is not.
    BeforeDbResult,
    /// The ledger intent is durable and the destination is not replaced.
    BeforeProgressReplace,
}

impl CrashPoint {
    /// Every point, in lifecycle order.
    pub const ALL: [Self; 4] = [
        Self::BeforeHostCommit,
        Self::AfterHostCommit,
        Self::BeforeDbResult,
        Self::BeforeProgressReplace,
    ];

    /// Stable label used by the flag, the printed line, and the report.
    pub const fn label(self) -> &'static str {
        match self {
            Self::BeforeHostCommit => "before-host-commit",
            Self::AfterHostCommit => "after-host-commit",
            Self::BeforeDbResult => "before-db-result",
            Self::BeforeProgressReplace => "before-progress-replace",
        }
    }

    /// Parses one stable label.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|point| point.label() == value)
    }

    const fn code(self) -> u8 {
        match self {
            Self::BeforeHostCommit => 1,
            Self::AfterHostCommit => 2,
            Self::BeforeDbResult => 3,
            Self::BeforeProgressReplace => 4,
        }
    }
}

static ARMED: AtomicU8 = AtomicU8::new(0);

/// Arms exactly one crash point for this process.
///
/// Only the explicit H4 lifecycle launcher calls this. Production code never
/// does, so [`hit`] is a no-op there.
#[doc(hidden)]
pub fn arm(point: CrashPoint) {
    ARMED.store(point.code(), Ordering::SeqCst);
}

/// Whether the named point is armed.
pub fn is_armed(point: CrashPoint) -> bool {
    ARMED.load(Ordering::SeqCst) == point.code()
}

/// Crashes the process when the named point is armed.
///
/// The check is one atomic load in every normal run. The print and exit happen
/// only for the explicitly armed test process.
pub fn hit(point: CrashPoint) {
    if !is_armed(point) {
        return;
    }
    let mut stdout = std::io::stdout();
    let _ = writeln!(
        stdout,
        "H4_LIFECYCLE_CRASH: point={} pid={}",
        point.label(),
        std::process::id()
    );
    let _ = stdout.flush();
    std::process::exit(CRASH_EXIT_CODE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_round_trips() {
        for point in CrashPoint::ALL {
            assert_eq!(CrashPoint::parse(point.label()), Some(point));
        }
        assert_eq!(CrashPoint::parse("not-a-boundary"), None);
    }

    #[test]
    fn an_unarmed_point_does_nothing() {
        // This test never arms a point, so the call returns normally.
        for point in CrashPoint::ALL {
            assert!(!is_armed(point));
            hit(point);
        }
    }
}
