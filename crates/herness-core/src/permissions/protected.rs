//! Protected host-boundary paths.
//!
//! The protected boundary is the set of absolute paths where host policy,
//! permission configuration, or other host-owned control data lives. Structured
//! file tools must not write or edit those paths, even when a broad allow rule
//! matches. The check precedes deny/ask evaluation and evaluator calls.
//!
//! Shell commands cannot be classified reliably. This boundary is therefore not
//! an OS sandbox and does not claim that an approved shell cannot modify these
//! paths; see the shell-rule documentation in [`super::rules`].

use crate::contracts::errors::CoreError;
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::permissions::rules::{normalize_absolute, operation_file_path};
use crate::tools::ToolName;

/// Absolute host paths that structured write/edit operations must not touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectedBoundary {
    paths: Vec<AbsolutePath>,
}

impl ProtectedBoundary {
    /// Creates a boundary from absolute paths.
    ///
    /// Paths are lexically normalized. A path and every descendant are
    /// protected, so a policy directory protects all files inside it.
    pub fn new(paths: Vec<AbsolutePath>) -> Result<Self, CoreError> {
        let paths = paths
            .into_iter()
            .map(|path| {
                normalize_absolute(path.as_path()).ok_or_else(|| CoreError::InvalidPath {
                    path: path.to_string(),
                    violation: crate::contracts::errors::PathViolation::NotAbsolute,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { paths })
    }

    /// Configured protected paths.
    pub fn paths(&self) -> &[AbsolutePath] {
        &self.paths
    }

    /// Whether no path is protected.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Returns the protected path that a write or edit would touch.
    ///
    /// Read and search operations are not denied: they do not modify the
    /// boundary. Bash returns `None` because its effects cannot be classified
    /// here; that is not a safety guarantee.
    pub fn violated_by(&self, operation: &FrozenOperation) -> Option<AbsolutePath> {
        if !matches!(operation.tool(), ToolName::Write | ToolName::Edit) {
            return None;
        }
        let target = operation_file_path(operation)?;
        self.paths
            .iter()
            .find(|protected| {
                target.as_path() == protected.as_path()
                    || target.as_path().starts_with(protected.as_path())
            })
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::ids::{OperationId, ProjectId, RunId};
    use crate::permissions::{PermissionMode, PolicyVersion};
    use crate::tools::{NonEmptyText, Rationale, ToolArguments, WriteArgs};

    fn write(path: &str) -> FrozenOperation {
        let project = ProjectId::new();
        FrozenOperation::new(
            OperationId::new(project),
            RunId::new(project),
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new(path).expect("path"),
                content: "x".to_owned(),
                rationale: Rationale::new("test").expect("rationale"),
            }),
            AbsolutePath::new("/tmp/project").expect("absolute"),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .expect("operation")
    }

    #[test]
    fn protected_paths_match_at_component_boundaries() {
        let boundary = ProtectedBoundary::new(vec![
            AbsolutePath::new("/tmp/project/.herness").expect("absolute"),
        ])
        .expect("boundary");
        assert!(
            boundary
                .violated_by(&write(".herness/policy.json"))
                .is_some()
        );
        assert!(
            boundary
                .violated_by(&write("/tmp/project/.herness"))
                .is_some()
        );
        assert!(
            boundary
                .violated_by(&write(".herness-other/policy.json"))
                .is_none()
        );
        assert!(boundary.violated_by(&write("notes.txt")).is_none());
    }
}
