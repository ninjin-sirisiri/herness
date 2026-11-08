//! `edit`: exact-text replacement of an existing file.

use crate::contracts::errors::FileFailure;
use crate::contracts::path::AbsolutePath;
use crate::tools::FileVersion;
use crate::tools::arguments::EditArgs;
use crate::tools::diff::{FileDiff, line_diff};
use crate::tools::files::hash_bytes;
use crate::tools::path::{ProjectRoot, ResolvedPath};

/// A validated, not-yet-applied edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditPlan {
    path: ResolvedPath,
    before_version: FileVersion,
    before_content: String,
    after_content: String,
    after_version: FileVersion,
    diff: FileDiff,
}

impl EditPlan {
    /// Resolved existing target.
    pub const fn path(&self) -> &ResolvedPath {
        &self.path
    }

    /// Version observed before the edit.
    pub const fn before_version(&self) -> &FileVersion {
        &self.before_version
    }

    /// Content observed before the edit.
    pub fn before_content(&self) -> &str {
        &self.before_content
    }

    /// Full content after applying the replacement.
    pub fn after_content(&self) -> &str {
        &self.after_content
    }

    /// Planned content hash after the edit.
    pub const fn after_version(&self) -> &FileVersion {
        &self.after_version
    }

    /// Deterministic textual diff.
    pub const fn diff(&self) -> &FileDiff {
        &self.diff
    }
}

/// Resolves and plans an `edit` against the file's current contents.
///
/// `oldText` must occur exactly once. When `expectedVersion` is supplied it
/// must equal the current content hash; when it is absent the exact-text guard
/// still prevents applying a stale replacement to content that no longer
/// contains the expected text.
pub fn plan(
    root: &ProjectRoot,
    cwd: &AbsolutePath,
    args: &EditArgs,
) -> Result<EditPlan, FileFailure> {
    let path = root.existing_file(cwd, args.path.as_str())?;
    let bytes = std::fs::read(path.absolute()).map_err(|error| FileFailure::Io {
        path: path.relative_display(),
        error_kind: format!("{:?}", error.kind()),
    })?;
    let before_content =
        String::from_utf8(bytes.clone()).map_err(|_| FileFailure::InvalidUtf8 {
            path: path.relative_display(),
        })?;
    let before_version = hash_bytes(&bytes);

    if let Some(expected) = &args.expected_version
        && expected != &before_version
    {
        return Err(FileFailure::VersionConflict {
            path: path.relative_display(),
            expected: expected.clone(),
            actual: before_version,
        });
    }

    if args.old_text.is_empty() {
        return Err(FileFailure::EditTextEmpty);
    }
    let occurrences = before_content.match_indices(&args.old_text).count();
    match occurrences {
        0 => {
            return Err(FileFailure::EditTextNotFound {
                path: path.relative_display(),
            });
        }
        1 => {}
        other => {
            return Err(FileFailure::EditTextNotUnique {
                path: path.relative_display(),
                occurrences: u64::try_from(other).unwrap_or(u64::MAX),
            });
        }
    }

    let after_content = before_content.replacen(&args.old_text, &args.new_text, 1);
    if after_content == before_content {
        return Err(FileFailure::NoChange {
            path: path.relative_display(),
        });
    }
    let after_version = hash_bytes(after_content.as_bytes());
    let diff = line_diff(&before_content, &after_content, &path.relative_display());

    Ok(EditPlan {
        path,
        before_version,
        before_content,
        after_content,
        after_version,
        diff,
    })
}
