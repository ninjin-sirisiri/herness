//! Explicit application-data root for the host-owned SQLite database.
//!
//! There is intentionally no `Default` implementation: the host must supply a
//! private application-data directory (for example
//! `~/Library/Application Support/herness`). The resolved database path never
//! defaults to a project directory, and a root inside the project is rejected
//! before any file is created.

use std::path::{Component, Path, PathBuf};

use herness_core::CheckpointFormatVersion;

use crate::error::{ConfigViolation, StoreError};

/// File name of the SQLite database inside the application-data root.
pub const DATABASE_FILE_NAME: &str = "herness.sqlite3";

/// Checkpoint format versions this build accepts unless configured otherwise.
///
/// The checkpoint body stays opaque; this list only prevents silently reading a
/// format the host does not understand.
fn default_checkpoint_formats() -> Vec<CheckpointFormatVersion> {
    vec![CheckpointFormatVersion::new(1).expect("checkpoint format version 1 is non-zero")]
}

/// Configuration for opening the host-owned store.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    app_data_root: PathBuf,
    checkpoint_formats: Vec<CheckpointFormatVersion>,
}

impl StoreConfig {
    /// Creates a configuration rooted at an explicit absolute directory.
    pub fn new(app_data_root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let app_data_root = app_data_root.into();
        if app_data_root.as_os_str().is_empty() {
            return Err(StoreError::InvalidConfig {
                violation: ConfigViolation::EmptyPath,
            });
        }
        if !app_data_root.is_absolute() {
            return Err(StoreError::InvalidConfig {
                violation: ConfigViolation::NotAbsolute,
            });
        }
        if app_data_root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(StoreError::InvalidConfig {
                violation: ConfigViolation::ParentComponent,
            });
        }

        Ok(Self {
            app_data_root,
            checkpoint_formats: default_checkpoint_formats(),
        })
    }

    /// Adds a checkpoint format version that may be read and written.
    #[must_use]
    pub fn accept_checkpoint_format(mut self, version: CheckpointFormatVersion) -> Self {
        if !self.checkpoint_formats.contains(&version) {
            self.checkpoint_formats.push(version);
        }
        self
    }

    /// Explicit private application-data root.
    pub fn app_data_root(&self) -> &Path {
        &self.app_data_root
    }

    /// Resolved database path inside the application-data root.
    pub fn database_path(&self) -> PathBuf {
        self.app_data_root.join(DATABASE_FILE_NAME)
    }

    /// Checkpoint format versions accepted on commit and on load.
    pub fn checkpoint_formats(&self) -> &[CheckpointFormatVersion] {
        &self.checkpoint_formats
    }

    /// Rejects an application-data root that is the project or inside it.
    ///
    /// The comparison canonicalizes both paths as far as they exist, so a
    /// symlinked project directory cannot hide the database inside the project.
    pub fn ensure_outside_project(&self, project_root: &Path) -> Result<(), StoreError> {
        if !project_root.is_absolute() {
            return Err(StoreError::InvalidConfig {
                violation: ConfigViolation::NotAbsolute,
            });
        }

        let project = normalized_absolute(project_root);
        let app_data = normalized_absolute(&self.app_data_root);
        if app_data == project || app_data.starts_with(&project) {
            return Err(StoreError::InvalidConfig {
                violation: ConfigViolation::InsideProject,
            });
        }
        Ok(())
    }

    pub(crate) fn accepts_checkpoint_format(&self, version: CheckpointFormatVersion) -> bool {
        self.checkpoint_formats.contains(&version)
    }
}

/// Canonicalizes an existing path, or canonicalizes the nearest existing
/// ancestor and appends the remaining components.
fn normalized_absolute(path: &Path) -> PathBuf {
    let mut current = path;
    let mut missing = Vec::new();
    loop {
        match current.canonicalize() {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn relative_and_parent_roots_are_rejected() {
        assert!(matches!(
            StoreConfig::new("relative/app-data"),
            Err(StoreError::InvalidConfig {
                violation: ConfigViolation::NotAbsolute
            })
        ));
        assert!(matches!(
            StoreConfig::new("/tmp/herness/../app-data"),
            Err(StoreError::InvalidConfig {
                violation: ConfigViolation::ParentComponent
            })
        ));
        assert!(matches!(
            StoreConfig::new(""),
            Err(StoreError::InvalidConfig {
                violation: ConfigViolation::EmptyPath
            })
        ));
    }

    #[test]
    fn database_path_stays_under_the_explicit_app_data_root() {
        let temp = tempfile::tempdir().unwrap();
        let app_data = temp.path().join("app-data");
        let config = StoreConfig::new(&app_data).unwrap();

        assert_eq!(config.app_data_root(), app_data);
        assert_eq!(config.database_path(), app_data.join(DATABASE_FILE_NAME));
    }

    #[test]
    fn app_data_inside_the_project_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();

        let inside = StoreConfig::new(project.join("app-data")).unwrap();
        assert!(matches!(
            inside.ensure_outside_project(&project),
            Err(StoreError::InvalidConfig {
                violation: ConfigViolation::InsideProject
            })
        ));

        let equal = StoreConfig::new(&project).unwrap();
        assert!(matches!(
            equal.ensure_outside_project(&project),
            Err(StoreError::InvalidConfig {
                violation: ConfigViolation::InsideProject
            })
        ));

        let sibling = StoreConfig::new(temp.path().join("app-data")).unwrap();
        assert!(sibling.ensure_outside_project(&project).is_ok());
        assert!(!sibling.database_path().starts_with(&project));
        assert!(sibling.database_path().starts_with(sibling.app_data_root()));
        assert_ne!(sibling.database_path(), Path::new("herness.sqlite3"));
    }

    #[test]
    fn checkpoint_formats_are_explicit_and_deduplicated() {
        let config = StoreConfig::new("/tmp/herness-config-test").unwrap();
        assert_eq!(
            config.checkpoint_formats(),
            &[CheckpointFormatVersion::new(1).unwrap()]
        );

        let version = CheckpointFormatVersion::new(2).unwrap();
        let config = config
            .accept_checkpoint_format(version)
            .accept_checkpoint_format(version);
        assert_eq!(
            config.checkpoint_formats(),
            &[
                CheckpointFormatVersion::new(1).unwrap(),
                CheckpointFormatVersion::new(2).unwrap()
            ]
        );
    }
}
