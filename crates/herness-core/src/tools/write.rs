//! `write`: create-only file creation planning.
//!
//! `write` never overwrites an existing path. Changing an existing file
//! requires `edit` with its version and exact-text guard. This makes an
//! unnoticed clobber impossible: a file the model did not read cannot be
//! replaced by `write`.

use crate::contracts::errors::FileFailure;
use crate::contracts::path::AbsolutePath;
use crate::tools::FileVersion;
use crate::tools::arguments::WriteArgs;
use crate::tools::diff::{FileDiff, line_diff};
use crate::tools::files::hash_bytes;
use crate::tools::path::{ProjectRoot, ResolvedPath};

/// A validated, not-yet-applied file creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePlan {
    path: ResolvedPath,
    content: String,
    version: FileVersion,
    diff: FileDiff,
}

impl WritePlan {
    /// Resolved target that must not exist.
    pub const fn path(&self) -> &ResolvedPath {
        &self.path
    }

    /// Full new file content.
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Planned content hash.
    pub const fn version(&self) -> &FileVersion {
        &self.version
    }

    /// Deterministic textual diff from an empty file.
    pub const fn diff(&self) -> &FileDiff {
        &self.diff
    }
}

/// Resolves and plans a `write` that creates a new file.
pub fn plan(
    root: &ProjectRoot,
    cwd: &AbsolutePath,
    args: &WriteArgs,
) -> Result<WritePlan, FileFailure> {
    let path = root.creatable_file(cwd, args.path.as_str())?;
    let version = hash_bytes(args.content.as_bytes());
    let diff = line_diff("", &args.content, &path.relative_display());
    Ok(WritePlan {
        path,
        content: args.content.clone(),
        version,
        diff,
    })
}
