//! Desktop filesystem watcher adapter for the H3 observer.
//!
//! `notify` is pinned here, not in `herness-html-sync`: the contract crate
//! receives plain [`ChangeSignal`] values and has no operating-system watcher
//! dependency. The adapter only reports paths that stay inside the canonical
//! project root; the observer still ignores every path outside its caller-
//! supplied Target and dependency set.
//!
//! The adapter never reads, writes, authors, or sends. It reports watcher
//! failure explicitly; the host continues periodic reconciliation and calls
//! `ProjectObserver::recover_watcher` after a successful restart.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::Sender;

use herness_core::AbsolutePath;
use herness_html_sync::{ChangeSignal, ChangeSource};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// One notice delivered to the host observer loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchNotice {
    /// A project-relative change signal.
    Signal(ChangeSignal),
    /// The operating-system watcher reported an error. No actor or reason is
    /// inferred.
    Failure,
}

/// Why the desktop watcher could not be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchAdapterError {
    /// The project root was missing, not a directory, or not canonical.
    InvalidRoot {
        /// Sanitized detail.
        detail: String,
    },
    /// The operating-system watcher could not be created or subscribed.
    WatchFailed {
        /// Sanitized detail.
        detail: String,
    },
}

impl fmt::Display for WatchAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot { detail } => write!(f, "invalid project root: {detail}"),
            Self::WatchFailed { detail } => write!(f, "filesystem watcher unavailable: {detail}"),
        }
    }
}

impl std::error::Error for WatchAdapterError {}

/// One recursive filesystem watcher for an open project.
pub struct ProjectFilesystemWatcher {
    root: PathBuf,
    sender: Sender<WatchNotice>,
    watcher: Option<RecommendedWatcher>,
}

impl ProjectFilesystemWatcher {
    /// Starts watching one canonical project root.
    ///
    /// Notices are sent to `sender`. A failed watcher creation or subscription
    /// is returned here; later operating-system errors arrive as
    /// [`WatchNotice::Failure`].
    pub fn start(
        project_root: impl AsRef<Path>,
        sender: Sender<WatchNotice>,
    ) -> Result<Self, WatchAdapterError> {
        let root = canonical_project_root(project_root.as_ref())?;
        let mut adapter = Self {
            root,
            sender,
            watcher: None,
        };
        adapter.install()?;
        Ok(adapter)
    }

    /// Canonical project root being watched.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether a watcher is currently installed.
    pub const fn is_watching(&self) -> bool {
        self.watcher.is_some()
    }

    /// Recreates the watcher after an operating-system failure.
    ///
    /// On success the host must perform one recovery reconciliation before it
    /// treats events as authoritative again.
    pub fn restart(&mut self) -> Result<(), WatchAdapterError> {
        self.watcher = None;
        self.install()
    }

    /// Stops the watcher explicitly.
    pub fn stop(&mut self) {
        self.watcher = None;
    }

    fn install(&mut self) -> Result<(), WatchAdapterError> {
        let root = self.root.clone();
        let sender = self.sender.clone();
        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<Event>| match result {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Access(_)) {
                        return;
                    }
                    for path in event.paths {
                        if let Some(signal) =
                            signal_from_absolute(&root, &path, ChangeSource::FilesystemWatcher)
                        {
                            let _ = sender.send(WatchNotice::Signal(signal));
                        }
                    }
                }
                Err(_) => {
                    let _ = sender.send(WatchNotice::Failure);
                }
            },
            Config::default(),
        )
        .map_err(|error| WatchAdapterError::WatchFailed {
            detail: error.to_string(),
        })?;
        watcher
            .watch(&self.root, RecursiveMode::Recursive)
            .map_err(|error| WatchAdapterError::WatchFailed {
                detail: error.to_string(),
            })?;
        self.watcher = Some(watcher);
        Ok(())
    }
}

/// Converts one absolute host path into a project-relative change signal.
///
/// Returns `None` for paths outside the root and for non-UTF-8 or escaping
/// components. No external actor is inferred; `source` only records how the
/// host learned about the path.
pub fn signal_from_absolute(
    project_root: &Path,
    path: &Path,
    source: ChangeSource,
) -> Option<ChangeSignal> {
    let relative = path.strip_prefix(project_root).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_str()?.to_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let joined = parts.join("/");
    ChangeSignal::new(joined, source).ok()
}

/// Converts one H1 persisted file-change path into a native-saved signal.
pub fn native_saved_change(project_root: &Path, path: &AbsolutePath) -> Option<ChangeSignal> {
    signal_from_absolute(
        project_root,
        Path::new(path.as_str()),
        ChangeSource::NativeSaved,
    )
}

/// Converts one shell observation path into a shell signal.
pub fn shell_change(project_root: &Path, path: &AbsolutePath) -> Option<ChangeSignal> {
    signal_from_absolute(project_root, Path::new(path.as_str()), ChangeSource::Shell)
}

/// Converts one external-editor observation path into an external-editor signal.
pub fn external_editor_change(project_root: &Path, path: &AbsolutePath) -> Option<ChangeSignal> {
    signal_from_absolute(
        project_root,
        Path::new(path.as_str()),
        ChangeSource::ExternalEditor,
    )
}

fn canonical_project_root(root: &Path) -> Result<PathBuf, WatchAdapterError> {
    if !root.is_absolute() {
        return Err(WatchAdapterError::InvalidRoot {
            detail: "the project root must be an absolute path".to_owned(),
        });
    }
    let canonical =
        std::fs::canonicalize(root).map_err(|error| WatchAdapterError::InvalidRoot {
            detail: error.to_string(),
        })?;
    if !canonical.is_dir() {
        return Err(WatchAdapterError::InvalidRoot {
            detail: "the project root must be a directory".to_owned(),
        });
    }
    Ok(canonical)
}
