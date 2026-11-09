//! Desktop H3 HTML sync adapters.
//!
//! Task 14 adds the Common SDD policy bridge. The observer, coordinator,
//! worker, renderer, publication, and UI commands remain later tasks; nothing
//! in this module writes a file, creates HTML, calls a model, or sends an
//! external request.

pub mod observer;
pub mod policy;

pub use observer::{
    ProjectFilesystemWatcher, WatchAdapterError, WatchNotice, external_editor_change,
    native_saved_change, shell_change, signal_from_absolute,
};

pub use policy::{
    CandidateCheck, CandidateDecision, CandidateStage, ConnectedPolicyBridge, HtmlPolicyBridge,
    PackProbe, PolicyBootstrap, PolicyBridgeError, PolicyFinding,
};
