//! Minimal desktop quit hook for H2 supervision records.
//!
//! Task 16 composes the real supervision store and UI. This module provides the
//! callable seam it can use from the existing quit worker: after H1 coordinated
//! stops have run, mark every active supervision record with the quit/recovery
//! reason and never claim a stop that H1 did not confirm.
//!
//! The function takes a plain [`Store`] and an explicit stop-fact map. It has no
//! Tauri window or application handle dependency, so it is testable without a
//! window. It never starts a run, sends a request, or auto-resumes.

use std::collections::BTreeMap;

use herness_core::{ProjectId, RunId, Timestamp};
use herness_store::Store;
use herness_supervision::recovery::{QuitSupervisionReport, mark_active_supervision_for_quit};
use herness_supervision::{ClockPort, SupervisionError};

struct FixedClock(Timestamp);

impl ClockPort for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// Marks every active supervision record of one project for quit.
///
/// `stop_facts` maps a run to whether H1 confirmed its coordinated stop. A run
/// absent from the map is treated as unconfirmed, so an incomplete H1 report
/// cannot make supervision look cleanly stopped.
pub fn mark_supervision_for_quit(
    store: &mut Store,
    project: ProjectId,
    stop_facts: &BTreeMap<RunId, bool>,
    now: Timestamp,
) -> Result<QuitSupervisionReport, String> {
    let records = store
        .supervision_records_for_project(&project)
        .map_err(|error| error.to_string())?;
    mark_active_supervision_for_quit(store, &FixedClock(now), records, stop_facts)
        .map_err(supervision_error)
}

fn supervision_error(error: SupervisionError) -> String {
    // Sanitized: SupervisionError never carries credentials or provider text.
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use herness_core::ProjectId;

    #[test]
    fn hook_is_callable_without_a_tauri_window() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let config =
            herness_store::StoreConfig::new(temp.path().join("app-data")).expect("store config");
        let mut store = Store::open(config).expect("store");
        let report = mark_supervision_for_quit(
            &mut store,
            ProjectId::new(),
            &BTreeMap::new(),
            Timestamp::from_unix_millis(1_700_000_000_000),
        )
        .expect("quit hook");
        assert!(report.marks().is_empty());
        assert_eq!(report.failed(), 0);
    }
}
