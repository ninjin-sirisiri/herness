//! Bounded wrapper around a permission evaluator.
//!
//! The evaluator call runs on a worker thread. The tool thread waits only until
//! the earlier of the configured evaluation timeout and the run deadline, and
//! aborts the wait as soon as the run is stopped. A late answer is discarded and
//! never reaches a side effect.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::contracts::errors::{CoreError, EvaluationFailureKind};
use crate::permissions::control::RunControl;
use crate::permissions::{EvaluatorAvailability, PermissionDecision};
use crate::ports::evaluator::{
    EvaluationRequest, PermissionEvaluatorPort, SharedPermissionEvaluator,
};

/// Upper bound for one permission evaluation when the run has no earlier
/// deadline.
pub const DEFAULT_EVALUATION_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the wait loop re-checks stop/deadline while the evaluator runs.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// An evaluator wrapper that cannot wait past the run's control state.
#[derive(Clone, Debug)]
pub struct BoundedPermissionEvaluator {
    evaluator: Option<SharedPermissionEvaluator>,
    control: RunControl,
    timeout: Duration,
}

impl BoundedPermissionEvaluator {
    /// Wraps the host-selected evaluator (if any) with run control.
    pub fn new(evaluator: Option<SharedPermissionEvaluator>, control: RunControl) -> Self {
        Self {
            evaluator,
            control,
            timeout: DEFAULT_EVALUATION_TIMEOUT,
        }
    }

    /// Replaces the default 60 second evaluation timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Absolute deadline for this evaluation: the earlier of the run deadline
    /// and the evaluation timeout.
    fn wait_deadline(&self) -> Instant {
        let timeout_deadline = Instant::now() + self.timeout;
        match self.control.deadline() {
            Some(run_deadline) => run_deadline.min(timeout_deadline),
            None => timeout_deadline,
        }
    }
}

fn evaluation_timeout() -> CoreError {
    CoreError::PermissionEvaluationFailed {
        failure: EvaluationFailureKind::Timeout,
    }
}

impl PermissionEvaluatorPort for BoundedPermissionEvaluator {
    fn availability(&self) -> EvaluatorAvailability {
        self.evaluator
            .as_ref()
            .map_or(EvaluatorAvailability::Unavailable, |evaluator| {
                evaluator.availability()
            })
    }

    fn evaluate(&mut self, request: &EvaluationRequest) -> Result<PermissionDecision, CoreError> {
        let Some(evaluator) = self.evaluator.clone() else {
            return Err(CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            });
        };
        if !self.control.permits_side_effect() {
            return Err(evaluation_timeout());
        }
        let deadline = self.wait_deadline();
        let request = request.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("herness-permission-evaluator".to_owned())
            .spawn(move || {
                let mut evaluator = evaluator;
                let _ = tx.send(evaluator.evaluate(&request));
            })
            .map_err(|_| CoreError::PermissionEvaluationFailed {
                failure: EvaluationFailureKind::Unavailable,
            })?;
        loop {
            if !self.control.permits_side_effect() {
                return Err(evaluation_timeout());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(evaluation_timeout());
            }
            let wait = (deadline - now).min(POLL_INTERVAL);
            match rx.recv_timeout(wait) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(CoreError::PermissionEvaluationFailed {
                        failure: EvaluationFailureKind::InvalidResponse,
                    });
                }
            }
        }
    }
}
