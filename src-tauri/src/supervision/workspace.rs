//! Bounded real workspace reader for H2 target manifests.
//!
//! The reader walks the opened project without a shell. It skips VCS and build
//! directories and refuses paths that escape the project root. When the walk
//! exceeds its bound, the caller turns the snapshot into an explicit
//! unknown-coverage manifest instead of claiming a complete scope.

use std::path::{Component, Path, PathBuf};

use herness_supervision::SupervisionError;
use herness_supervision::freshness::{InputOrigin, WorkspaceInput, WorkspaceSnapshotPort};

const DEFAULT_MAX_INPUTS: usize = 50_000;
const MAX_DEPTH: usize = 32;

const SKIPPED_DIRECTORIES: &[&str] = &[".git", "target", "node_modules", ".DS_Store"];

/// Project-root reader used by the runtime snapshot port.
#[derive(Debug, Clone)]
pub struct ProjectWorkspace {
    root: PathBuf,
    max_inputs: usize,
}

impl ProjectWorkspace {
    /// Creates a reader over one canonical project root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_inputs: DEFAULT_MAX_INPUTS,
        }
    }

    /// Replaces the maximum number of enumerated input files.
    pub const fn with_max_inputs(mut self, max_inputs: usize) -> Self {
        self.max_inputs = max_inputs;
        self
    }

    /// Canonical project root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, path: &str) -> Result<Option<PathBuf>, SupervisionError> {
        let relative = Path::new(path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "workspace.path".to_owned(),
                detail: "paths must be project-relative and must not escape the project".to_owned(),
            });
        }
        let joined = self.root.join(relative);
        let Ok(canonical) = std::fs::canonicalize(&joined) else {
            return Ok(None);
        };
        let Ok(root) = std::fs::canonicalize(&self.root) else {
            return Ok(None);
        };
        if !canonical.starts_with(&root) {
            return Err(SupervisionError::EvidenceContractViolation {
                field: "workspace.path".to_owned(),
                detail: "the path resolves outside the project".to_owned(),
            });
        }
        Ok(canonical.is_file().then_some(canonical))
    }

    fn walk(&self) -> Result<Vec<WorkspaceInput>, SupervisionError> {
        let mut inputs = Vec::new();
        let mut stack = vec![(self.root.clone(), 0usize)];
        while let Some((directory, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                return Err(SupervisionError::EvidenceContractViolation {
                    field: "workspace.depth".to_owned(),
                    detail: "the project directory tree is deeper than the bound".to_owned(),
                });
            }
            let entries = std::fs::read_dir(&directory).map_err(|error| {
                SupervisionError::EvidenceContractViolation {
                    field: "workspace.readDir".to_owned(),
                    detail: format!("could not enumerate a project directory: {error}"),
                }
            })?;
            for entry in entries {
                let entry = entry.map_err(|error| SupervisionError::EvidenceContractViolation {
                    field: "workspace.readDir".to_owned(),
                    detail: format!("could not read a project entry: {error}"),
                })?;
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    if SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                        continue;
                    }
                    stack.push((path, depth + 1));
                    continue;
                }
                if !file_type.is_file() {
                    // Symlinks and special files are not followed. The target
                    // root itself is canonical; following links could escape it.
                    continue;
                }
                if SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                    continue;
                }
                let Some(relative) = path.strip_prefix(&self.root).ok() else {
                    continue;
                };
                let Some(relative) = relative.to_str() else {
                    continue;
                };
                inputs.push(WorkspaceInput::new(relative, InputOrigin::Tracked)?);
                if inputs.len() > self.max_inputs {
                    return Err(SupervisionError::EvidenceContractViolation {
                        field: "workspace.inputs".to_owned(),
                        detail: "the project has more inputs than the bounded manifest allows"
                            .to_owned(),
                    });
                }
            }
        }
        inputs.sort_by(|left, right| left.path().cmp(right.path()));
        Ok(inputs)
    }
}

impl WorkspaceSnapshotPort for ProjectWorkspace {
    fn head(&self) -> Result<Option<String>, SupervisionError> {
        // HEAD is descriptive only; content digests decide applicability.
        let head = self.root.join(".git").join("HEAD");
        let Ok(contents) = std::fs::read_to_string(head) else {
            return Ok(None);
        };
        let contents = contents.trim();
        if let Some(reference) = contents.strip_prefix("ref: ") {
            let path = self.root.join(".git").join(reference);
            if let Ok(value) = std::fs::read_to_string(path) {
                let value = value.trim();
                if !value.is_empty() {
                    return Ok(Some(value.to_owned()));
                }
            }
            return Ok(None);
        }
        if contents.is_empty() {
            Ok(None)
        } else {
            Ok(Some(contents.to_owned()))
        }
    }

    fn inputs(&self) -> Result<Vec<WorkspaceInput>, SupervisionError> {
        self.walk()
    }

    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, SupervisionError> {
        match self.resolve(path)? {
            Some(path) => std::fs::read(path).map(Some).map_err(|error| {
                SupervisionError::EvidenceContractViolation {
                    field: "workspace.read".to_owned(),
                    detail: format!("could not read a project input: {error}"),
                }
            }),
            None => Ok(None),
        }
    }
}
