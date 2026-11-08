//! Desktop host adapters and Tauri shell for herness.
//!
//! The Keychain credential adapter is independent of Tauri and testable on its
//! own. Task 11 adds the single host composition, the trusted command guard, the
//! minimal main window, and the embedded static UI.

pub mod app;
pub mod commands;
pub mod credentials;
pub mod guard;
pub mod host;
pub mod lifecycle;
pub mod login;
pub mod real_check;
