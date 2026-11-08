//! `read`: bounded UTF-8 line reads inside the project root.

use std::fs;

use serde::Serialize;

use crate::contracts::errors::FileFailure;
use crate::contracts::path::AbsolutePath;
use crate::tools::FileVersion;
use crate::tools::arguments::ReadArgs;
use crate::tools::files::hash_bytes;
use crate::tools::path::ProjectRoot;

/// Lines returned when the caller does not ask for a limit.
pub const DEFAULT_READ_LIMIT: u64 = 2_000;
/// Hard upper bound on lines returned in one read.
pub const MAX_READ_LIMIT: u64 = 10_000;

/// Result of a successful `read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadOutput {
    path: AbsolutePath,
    version: FileVersion,
    text: String,
    start_line: u64,
    end_line: Option<u64>,
    total_lines: u64,
    truncated: bool,
}

impl ReadOutput {
    /// Absolute path that was read.
    pub const fn path(&self) -> &AbsolutePath {
        &self.path
    }

    /// Content version observed by the read.
    pub const fn version(&self) -> &FileVersion {
        &self.version
    }

    /// UTF-8 text for the requested line range. Lines are joined with `\n`
    /// and do not include a synthetic trailing newline.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// One-based line number of the first returned line.
    pub const fn start_line(&self) -> u64 {
        self.start_line
    }

    /// One-based line number of the last returned line, when any line was
    /// returned.
    pub const fn end_line(&self) -> Option<u64> {
        self.end_line
    }

    /// Total lines in the file.
    pub const fn total_lines(&self) -> u64 {
        self.total_lines
    }

    /// Whether more lines remain after `end_line`.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Reads a UTF-8 file with one-based offset and bounded line limit.
pub fn read(
    root: &ProjectRoot,
    cwd: &AbsolutePath,
    args: &ReadArgs,
) -> Result<ReadOutput, FileFailure> {
    let resolved = root.existing_file(cwd, args.path.as_str())?;
    let bytes = fs::read(resolved.absolute()).map_err(|error| FileFailure::Io {
        path: resolved.relative_display(),
        error_kind: format!("{:?}", error.kind()),
    })?;
    let text = String::from_utf8(bytes.clone()).map_err(|_| FileFailure::InvalidUtf8 {
        path: resolved.relative_display(),
    })?;
    let version = hash_bytes(&bytes);

    let lines: Vec<&str> = text.lines().collect();
    let total_lines = u64::try_from(lines.len()).unwrap_or(u64::MAX);
    let offset = args.offset.unwrap_or(1);
    let limit = args.limit.unwrap_or(DEFAULT_READ_LIMIT).min(MAX_READ_LIMIT);

    let start_index = usize::try_from(offset.saturating_sub(1))
        .unwrap_or(usize::MAX)
        .min(lines.len());
    let take = usize::try_from(limit).unwrap_or(usize::MAX);
    let end_index = start_index.saturating_add(take).min(lines.len());
    let selected = &lines[start_index..end_index];
    let returned = u64::try_from(selected.len()).unwrap_or(u64::MAX);

    Ok(ReadOutput {
        path: resolved.absolute_value()?,
        version,
        text: selected.join("\n"),
        start_line: offset,
        end_line: (returned > 0).then(|| offset.saturating_add(returned - 1)),
        total_lines,
        truncated: end_index < lines.len(),
    })
}
