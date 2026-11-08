//! `search`: deterministic literal text search inside the project root.
//!
//! Matching is a case-sensitive literal substring match per UTF-8 line. An
//! optional glob filters project-relative paths: `*` matches any sequence
//! except `/`, `**` matches any sequence including `/`, `?` matches one
//! character except `/`, and every other character is literal.
//!
//! Traversal is depth-first with directory entries sorted by file name. Symlinks
//! are never followed, non-regular files are skipped, files larger than
//! [`MAX_SEARCH_FILE_BYTES`] are skipped, and non-UTF-8 files are skipped. No
//! external search binary is required.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::contracts::errors::FileFailure;
use crate::contracts::path::AbsolutePath;
use crate::tools::arguments::SearchArgs;
use crate::tools::path::ProjectRoot;

/// Matches returned when the caller does not ask for a limit.
pub const DEFAULT_SEARCH_RESULTS: u32 = 100;
/// Hard upper bound on returned matches.
pub const MAX_SEARCH_RESULTS: u32 = 1_000;
/// Largest file searched, in bytes.
pub const MAX_SEARCH_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Hard upper bound on files read in one search, regardless of matches.
pub const MAX_SEARCH_FILES: u64 = 20_000;
/// Maximum characters kept in one match preview.
pub const MAX_PREVIEW_CHARS: usize = 500;

/// One matching line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchMatch {
    path: AbsolutePath,
    line: u64,
    column: u64,
    preview: String,
}

impl SearchMatch {
    /// Absolute path of the matching file.
    pub const fn path(&self) -> &AbsolutePath {
        &self.path
    }

    /// One-based line number.
    pub const fn line(&self) -> u64 {
        self.line
    }

    /// One-based Unicode-scalar column of the first match in the line.
    pub const fn column(&self) -> u64 {
        self.column
    }

    /// Bounded text of the matching line.
    pub fn preview(&self) -> &str {
        &self.preview
    }
}

/// Result of a successful `search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchOutput {
    matches: Vec<SearchMatch>,
    truncated: bool,
    files_scanned: u64,
}

impl SearchOutput {
    /// Matches in deterministic traversal order.
    pub fn matches(&self) -> &[SearchMatch] {
        &self.matches
    }

    /// Whether a result or scan bound stopped the search early.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Number of regular UTF-8 files actually scanned.
    pub const fn files_scanned(&self) -> u64 {
        self.files_scanned
    }
}

/// Searches project files for a literal query.
pub fn search(
    root: &ProjectRoot,
    cwd: &AbsolutePath,
    args: &SearchArgs,
) -> Result<SearchOutput, FileFailure> {
    let scope = match &args.path {
        Some(path) => root.existing_file_or_directory(cwd, path.as_str())?,
        None => root.existing_file_or_directory(cwd, cwd.as_str())?,
    };
    let limit = args
        .max_results
        .unwrap_or(DEFAULT_SEARCH_RESULTS)
        .min(MAX_SEARCH_RESULTS);
    let query = args.query.as_str();
    let glob = args.glob.as_ref().map(|glob| glob.as_str().to_owned());

    let mut searcher = Searcher {
        root,
        query,
        glob: glob.as_deref(),
        limit,
        matches: Vec::new(),
        truncated: false,
        files_scanned: 0,
    };

    let metadata = fs::metadata(scope.real()).map_err(|error| FileFailure::Io {
        path: scope.relative_display(),
        error_kind: format!("{:?}", error.kind()),
    })?;
    if metadata.is_dir() {
        searcher.walk(scope.real())?;
    } else {
        searcher.file(scope.real())?;
    }

    Ok(SearchOutput {
        matches: searcher.matches,
        truncated: searcher.truncated,
        files_scanned: searcher.files_scanned,
    })
}

struct Searcher<'a> {
    root: &'a ProjectRoot,
    query: &'a str,
    glob: Option<&'a str>,
    limit: u32,
    matches: Vec<SearchMatch>,
    truncated: bool,
    files_scanned: u64,
}

impl Searcher<'_> {
    fn walk(&mut self, directory: &Path) -> Result<(), FileFailure> {
        // `sorted_entries` filters symlinks and fixes the traversal order per
        // directory; recursion preserves that deterministic depth-first order.
        for path in sorted_entries(directory)? {
            if self.truncated
                || self.matches.len() >= usize::try_from(self.limit).unwrap_or(usize::MAX)
            {
                self.truncated = true;
                return Ok(());
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(FileFailure::Io {
                        path: path.to_string_lossy().into_owned(),
                        error_kind: format!("{:?}", error.kind()),
                    });
                }
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                self.walk(&path)?;
            } else if metadata.is_file() {
                self.file(&path)?;
            }
        }
        Ok(())
    }

    fn file(&mut self, path: &Path) -> Result<(), FileFailure> {
        if self.files_scanned >= MAX_SEARCH_FILES {
            self.truncated = true;
            return Ok(());
        }
        let relative = path.strip_prefix(self.root.as_path()).map_err(|_| {
            FileFailure::PathOutsideProject {
                path: path.to_string_lossy().into_owned(),
            }
        })?;
        if path.to_str().is_none() {
            // Result paths are UTF-8 contract values; skip names that cannot be
            // represented without lossy rewriting.
            return Ok(());
        }
        let relative_display = display_path(relative);
        if let Some(glob) = self.glob
            && !glob_matches(glob, &relative_display)
        {
            return Ok(());
        }

        let metadata = fs::symlink_metadata(path).map_err(|error| FileFailure::Io {
            path: relative_display.clone(),
            error_kind: format!("{:?}", error.kind()),
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Ok(());
        }
        if metadata.len() > MAX_SEARCH_FILE_BYTES {
            return Ok(());
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(()),
        };
        let Ok(text) = String::from_utf8(bytes) else {
            return Ok(());
        };
        self.files_scanned = self.files_scanned.saturating_add(1);
        let absolute = AbsolutePath::new(path.to_string_lossy().into_owned()).map_err(|_| {
            FileFailure::Io {
                path: relative_display.clone(),
                error_kind: "path is not valid UTF-8".to_owned(),
            }
        })?;
        let limit = usize::try_from(self.limit).unwrap_or(usize::MAX);

        for (index, line) in text.lines().enumerate() {
            let Some(byte_index) = line.find(self.query) else {
                continue;
            };
            if self.matches.len() >= limit {
                self.truncated = true;
                return Ok(());
            }
            let column = u64::try_from(line[..byte_index].chars().count()).unwrap_or(u64::MAX) + 1;
            let line_number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
            self.matches.push(SearchMatch {
                path: absolute.clone(),
                line: line_number,
                column,
                preview: preview(line),
            });
        }
        Ok(())
    }
}

fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>, FileFailure> {
    let entries = fs::read_dir(directory).map_err(|error| FileFailure::Io {
        path: directory.to_string_lossy().into_owned(),
        error_kind: format!("{:?}", error.kind()),
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        let is_symlink = entry
            .file_type()
            .map(|file_type| file_type.is_symlink())
            .unwrap_or(true);
        if is_symlink {
            continue;
        }
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

fn display_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn preview(line: &str) -> String {
    let mut preview: String = line.chars().take(MAX_PREVIEW_CHARS).collect();
    if line.chars().count() > MAX_PREVIEW_CHARS {
        preview.push('…');
    }
    preview
}

/// Glob matching over a `/`-separated project-relative path.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let path: Vec<char> = path.chars().collect();
    glob_match(&pattern, &path)
}

fn glob_match(pattern: &[char], path: &[char]) -> bool {
    match pattern.first() {
        None => path.is_empty(),
        Some('*') => {
            if pattern.get(1) == Some(&'*') {
                glob_match(&pattern[2..], path)
                    || (!path.is_empty() && glob_match(pattern, &path[1..]))
            } else {
                glob_match(&pattern[1..], path)
                    || (!path.is_empty() && path[0] != '/' && glob_match(pattern, &path[1..]))
            }
        }
        Some('?') => !path.is_empty() && path[0] != '/' && glob_match(&pattern[1..], &path[1..]),
        Some(character) => {
            !path.is_empty() && path[0] == *character && glob_match(&pattern[1..], &path[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_uses_component_aware_star_and_question_mark() {
        assert!(glob_matches("*.rs", "main.rs"));
        assert!(!glob_matches("*.rs", "src/main.rs"));
        assert!(glob_matches("**/*.rs", "src/main.rs"));
        assert!(glob_matches("src/*", "src/main.rs"));
        assert!(!glob_matches("src/*", "src/nested/main.rs"));
        assert!(glob_matches("src/**", "src/nested/main.rs"));
        assert!(glob_matches("ma?n.rs", "main.rs"));
        assert!(!glob_matches("ma?n.rs", "ma/n.rs"));
    }
}
