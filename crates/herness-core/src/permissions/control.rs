//! Host-owned run stop and deadline control.
//!
//! [`RunControl`] is a cheap, shared handle. The host keeps one per run and
//! every component that can start a side effect reads the same snapshot. The
//! adapter never derives stop or deadline state from model text, and a handle
//! cannot be widened by a tool request.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::contracts::request::{StopDeadlineControl, StopReason};

const NOT_STOPPED: u8 = 0;
const USER_REQUEST: u8 = 1;
const APPLICATION_QUIT: u8 = 2;
const POLICY: u8 = 3;

fn reason_code(reason: StopReason) -> u8 {
    match reason {
        StopReason::UserRequest => USER_REQUEST,
        StopReason::ApplicationQuit => APPLICATION_QUIT,
        StopReason::Policy => POLICY,
    }
}

fn reason_from_code(code: u8) -> Option<StopReason> {
    match code {
        USER_REQUEST => Some(StopReason::UserRequest),
        APPLICATION_QUIT => Some(StopReason::ApplicationQuit),
        POLICY => Some(StopReason::Policy),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct RunControlInner {
    stop: AtomicU8,
    deadline: Mutex<Option<Instant>>,
}

/// Shared stop/deadline state for one run.
///
/// Cloning a handle shares the state; it is not a snapshot. Reads are
/// instantaneous and safe from a blocking tool thread.
#[derive(Debug, Clone, Default)]
pub struct RunControl {
    inner: Arc<RunControlInner>,
}

impl RunControl {
    /// Creates an unstopped control with no deadline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a stop request. The first reason wins; later requests do not
    /// overwrite it.
    pub fn request_stop(&self, reason: StopReason) {
        let _ = self.inner.stop.compare_exchange(
            NOT_STOPPED,
            reason_code(reason),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// Clears a prior stop request. This is only for an explicit human resume;
    /// it never clears a deadline.
    pub fn reset_stop(&self) {
        self.inner.stop.store(NOT_STOPPED, Ordering::SeqCst);
    }

    /// Sets or clears the absolute run deadline.
    pub fn set_deadline(&self, deadline: Option<Instant>) {
        *self
            .inner
            .deadline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = deadline;
    }

    /// Returns the absolute run deadline, if one is set.
    pub fn deadline(&self) -> Option<Instant> {
        *self
            .inner
            .deadline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns the requested stop reason, if any.
    pub fn stop_reason(&self) -> Option<StopReason> {
        reason_from_code(self.inner.stop.load(Ordering::SeqCst))
    }

    /// Whether a stop was requested.
    pub fn is_stopped(&self) -> bool {
        self.stop_reason().is_some()
    }

    /// Whether the deadline has been reached.
    pub fn is_deadline_reached(&self) -> bool {
        self.deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Whether a side effect may start under the current control state.
    pub fn permits_side_effect(&self) -> bool {
        !self.is_stopped() && !self.is_deadline_reached()
    }

    /// Remaining time before the deadline, or `None` when no deadline is set.
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Immutable snapshot for one check.
    pub fn snapshot(&self) -> StopDeadlineControl {
        let stopped = self.stop_reason();
        let deadline_reached = self.is_deadline_reached();
        match (stopped, deadline_reached) {
            (Some(reason), _) => StopDeadlineControl::stopped(reason),
            (None, true) => StopDeadlineControl::deadline(),
            (None, false) => StopDeadlineControl::proceed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_stop_reason_wins_and_is_shared_between_clones() {
        let control = RunControl::new();
        let clone = control.clone();
        assert!(control.permits_side_effect());
        clone.request_stop(StopReason::UserRequest);
        control.request_stop(StopReason::ApplicationQuit);
        assert_eq!(control.stop_reason(), Some(StopReason::UserRequest));
        assert_eq!(
            control.snapshot(),
            StopDeadlineControl::stopped(StopReason::UserRequest)
        );
        assert!(!control.permits_side_effect());
        control.reset_stop();
        assert!(control.permits_side_effect());
    }

    #[test]
    fn deadlines_are_absolute_and_clearable() {
        let control = RunControl::new();
        control.set_deadline(Some(Instant::now() + Duration::from_secs(60)));
        assert!(!control.is_deadline_reached());
        assert_eq!(control.snapshot(), StopDeadlineControl::proceed());
        control.set_deadline(Some(Instant::now() - Duration::from_millis(1)));
        assert!(control.is_deadline_reached());
        assert_eq!(control.snapshot(), StopDeadlineControl::deadline());
        control.set_deadline(None);
        assert!(!control.is_deadline_reached());
    }
}
