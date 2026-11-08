//! Lexical and real-path resolution inside one trusted project root.
//!
//! Every native file tool resolves its target through [`ProjectRoot`]. The
//! resolver:
//!
//! 1. resolves relative arguments against the frozen working directory;
//! 2. folds `.` and `..` lexically and requires the result to stay under the
//!    canonical project root;
//! 3. canonicalizes the existing prefix and requires the real path to stay
//!    under the root;
//! 4. refuses any symlink component below the root, including a symlinked
//!    target file and a symlinked parent of a not-yet-created file.
//!
//! This is a trusted-project boundary, not an OS sandbox. It assumes the
//! project directory itself and the host process are not adversarial.

use std::fs;
use std::path::{Path, PathBuf};

use crate::contracts::errors::{ArgumentViolation, CoreError, FileFailure, PathViolation};
use crate::contracts::path::AbsolutePath;
use crate::permissions::rules::normalize_absolute;

/// Canonical root of the project a run was opened for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRoot {
    root: PathBuf,
}

impl ProjectRoot {
    /// Canonicalizes and validates an existing project directory.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, CoreError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(CoreError::InvalidPath {
                path: path.to_string_lossy().into_owned(),
                violation: PathViolation::Empty,
            });
        }
        let root = fs::canonicalize(path).map_err(|error| CoreError::InvalidValue {
            field: "projectRoot".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: format!("cannot canonicalize project root: {}", error.kind()),
            },
        })?;
        let metadata = fs::metadata(&root).map_err(|error| CoreError::InvalidValue {
            field: "projectRoot".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: format!("cannot read project root: {}", error.kind()),
            },
        })?;
        if !metadata.is_dir() {
            return Err(CoreError::InvalidValue {
                field: "projectRoot".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "project root is not a directory".to_owned(),
                },
            });
        }
        Ok(Self { root })
    }

    /// Canonical project directory.
    pub fn as_path(&self) -> &Path {
        &self.root
    }

    /// Resolves a read or edit target that must already be a regular file.
    pub fn existing_file(
        &self,
        cwd: &AbsolutePath,
        raw: &str,
    ) -> Result<ResolvedPath, FileFailure> {
        let resolved = self.resolve(cwd, raw)?;
        let metadata = match fs::symlink_metadata(resolved.absolute.as_path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(FileFailure::NotFound {
                    path: resolved.relative_display(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                return Err(FileFailure::NotAFile {
                    path: resolved.relative_display(),
                });
            }
            Err(error) => return Err(io_failure(resolved.absolute.as_path(), &error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(FileFailure::SymlinkNotAllowed {
                path: resolved.relative_display(),
            });
        }
        if !metadata.is_file() {
            return Err(FileFailure::NotAFile {
                path: resolved.relative_display(),
            });
        }
        Ok(resolved)
    }

    /// Resolves a write target that must not exist and whose parent must be a
    /// real directory below the root.
    pub fn creatable_file(
        &self,
        cwd: &AbsolutePath,
        raw: &str,
    ) -> Result<ResolvedPath, FileFailure> {
        let resolved = self.resolve(cwd, raw)?;
        let Some(parent) = resolved.absolute.as_path().parent() else {
            return Err(FileFailure::PathOutsideProject {
                path: resolved.relative_display(),
            });
        };
        let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                FileFailure::ParentMissing {
                    path: parent.to_string_lossy().into_owned(),
                }
            } else {
                io_failure(parent, &error)
            }
        })?;
        if parent_metadata.file_type().is_symlink() {
            return Err(FileFailure::SymlinkNotAllowed {
                path: parent.to_string_lossy().into_owned(),
            });
        }
        if !parent_metadata.is_dir() {
            return Err(FileFailure::ParentNotDirectory {
                path: parent.to_string_lossy().into_owned(),
            });
        }

        match fs::symlink_metadata(resolved.absolute.as_path()) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(FileFailure::SymlinkNotAllowed {
                        path: resolved.relative_display(),
                    });
                }
                Err(FileFailure::AlreadyExists {
                    path: resolved.relative_display(),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(resolved),
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                Err(FileFailure::ParentNotDirectory {
                    path: parent.to_string_lossy().into_owned(),
                })
            }
            Err(error) => Err(io_failure(resolved.absolute.as_path(), &error)),
        }
    }

    /// Resolves a search scope that must already exist as a file or directory.
    pub fn existing_file_or_directory(
        &self,
        cwd: &AbsolutePath,
        raw: &str,
    ) -> Result<ResolvedPath, FileFailure> {
        let resolved = self.resolve(cwd, raw)?;
        let metadata = match fs::symlink_metadata(resolved.absolute.as_path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(FileFailure::NotFound {
                    path: resolved.relative_display(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                return Err(FileFailure::NotAFile {
                    path: resolved.relative_display(),
                });
            }
            Err(error) => return Err(io_failure(resolved.absolute.as_path(), &error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(FileFailure::SymlinkNotAllowed {
                path: resolved.relative_display(),
            });
        }
        if !(metadata.is_file() || metadata.is_dir()) {
            return Err(FileFailure::NotAFile {
                path: resolved.relative_display(),
            });
        }
        Ok(resolved)
    }

    fn resolve(&self, cwd: &AbsolutePath, raw: &str) -> Result<ResolvedPath, FileFailure> {
        let raw_path = Path::new(raw);
        if raw.is_empty() || raw.contains('\0') {
            return Err(FileFailure::Io {
                path: raw.to_owned(),
                error_kind: "invalid path".to_owned(),
            });
        }

        let joined = if raw_path.is_absolute() {
            raw_path.to_path_buf()
        } else {
            let real_cwd = fs::canonicalize(cwd.as_path())
                .map_err(|error| io_failure(cwd.as_path(), &error))?;
            if !real_cwd.starts_with(&self.root) {
                return Err(FileFailure::PathOutsideProject {
                    path: cwd.to_string(),
                });
            }
            real_cwd.join(raw_path)
        };

        let normalized = normalize_absolute(&joined).ok_or_else(|| FileFailure::Io {
            path: cwd.to_string(),
            error_kind: "working directory is not an absolute UTF-8 path".to_owned(),
        })?;
        if !normalized.as_path().starts_with(&self.root) {
            return Err(FileFailure::PathOutsideProject {
                path: normalized.to_string(),
            });
        }

        let relative = normalized
            .as_path()
            .strip_prefix(&self.root)
            .map_err(|_| FileFailure::PathOutsideProject {
                path: normalized.to_string(),
            })?
            .to_path_buf();

        self.reject_symlink_components(&relative)?;

        let real = canonicalize_nearest_existing(normalized.as_path());
        if !real.starts_with(&self.root) {
            return Err(FileFailure::PathOutsideProject {
                path: real.to_string_lossy().into_owned(),
            });
        }

        Ok(ResolvedPath {
            absolute: normalized.as_path().to_path_buf(),
            real,
            relative,
        })
    }

    /// Refuses a symlink at any component below the canonical root, whether it
    /// exists or is the not-yet-created tail of the path.
    fn reject_symlink_components(&self, relative: &Path) -> Result<(), FileFailure> {
        let mut current = self.root.clone();
        for component in relative.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(FileFailure::SymlinkNotAllowed {
                        path: current.to_string_lossy().into_owned(),
                    });
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(io_failure(&current, &error)),
            }
        }
        Ok(())
    }
}

/// A path resolved and validated against the project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    absolute: PathBuf,
    real: PathBuf,
    relative: PathBuf,
}

impl ResolvedPath {
    /// Lexically normalized absolute path inside the project root.
    pub fn absolute(&self) -> &Path {
        &self.absolute
    }

    /// Real path with existing symlinks resolved. Always inside the root.
    pub fn real(&self) -> &Path {
        &self.real
    }

    /// Path relative to the project root.
    pub fn relative(&self) -> &Path {
        &self.relative
    }

    /// Project-relative display path using `/` separators.
    pub fn relative_display(&self) -> String {
        self.relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Key that serializes writers to the same file in this process.
    pub fn lock_key(&self) -> PathBuf {
        // The parent is real and the final component is the requested file
        // name. Using the real parent makes hard links and differently written
        // but equivalent parent paths agree.
        let parent = self
            .real
            .parent()
            .map_or_else(|| self.real.clone(), Path::to_path_buf);
        let name = self.absolute.file_name().map_or_else(
            || self.absolute.clone().into_os_string(),
            |name| name.to_owned(),
        );
        parent.join(name)
    }

    /// Absolute path as a validated core value.
    pub fn absolute_value(&self) -> Result<AbsolutePath, FileFailure> {
        AbsolutePath::new(self.absolute.to_string_lossy().into_owned()).map_err(|_| {
            FileFailure::Io {
                path: self.absolute.to_string_lossy().into_owned(),
                error_kind: "path is not valid UTF-8".to_owned(),
            }
        })
    }
}

/// Canonicalizes the deepest existing ancestor and appends missing components.
///
/// A dangling symlink cannot be canonicalized; it stays as a missing tail and
/// is rejected separately by the symlink-component walk.
fn canonicalize_nearest_existing(path: &Path) -> PathBuf {
    let mut current = path;
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(current) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return resolved;
            }
            Err(_) => match current.parent() {
                Some(parent) => {
                    if let Some(name) = current.file_name() {
                        missing.push(name.to_os_string());
                    }
                    current = parent;
                }
                None => return path.to_path_buf(),
            },
        }
    }
}

fn io_failure(path: &Path, error: &std::io::Error) -> FileFailure {
    FileFailure::Io {
        path: path.to_string_lossy().into_owned(),
        error_kind: format!("{:?}", error.kind()),
    }
}
