//! Detection of the external tools H1 needs without relying on the ambient
//! Finder PATH.
//!
//! The host supplies explicit executable paths and search directories. An
//! explicit path list is authoritative: detection does not silently substitute
//! another executable or another validator. Missing, non-executable, and
//! version-insufficient tools produce structured capability deficiencies.
//! Nothing is installed or modified.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::path::AbsolutePath;

/// Python version required by the SDD validator in H1.
pub const MINIMUM_PYTHON_VERSION: PythonVersion = PythonVersion::new(3, 11, 0);

/// A Python `major.minor.patch` version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PythonVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PythonVersion {
    /// Creates a version value.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Major component.
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Minor component.
    pub const fn minor(self) -> u16 {
        self.minor
    }

    /// Patch component.
    pub const fn patch(self) -> u16 {
        self.patch
    }

    /// Parses the first `Python X.Y[.Z]` banner in `text`.
    pub fn from_banner(text: &str) -> Option<Self> {
        let start = text.find("Python ")? + "Python ".len();
        let token = text[start..]
            .split_whitespace()
            .next()?
            .trim_end_matches(['\r', '\n']);
        let mut parts = token.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if parts.next().is_some() {
            return None;
        }
        Some(Self::new(major, minor, patch))
    }
}

impl fmt::Display for PythonVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for PythonVersion {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_banner(&format!("Python {value}")).ok_or_else(|| CoreError::InvalidValue {
            field: "pythonVersion".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: "expected major.minor[.patch]".to_owned(),
            },
        })
    }
}

impl Serialize for PythonVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PythonVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// External tool required by H1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRequirement {
    /// Git executable.
    Git,
    /// Python 3.11 or newer.
    Python,
    /// The user's SDD HTML validator, executed with Python 3.11 or newer.
    HtmlDocsValidator,
}

impl ToolRequirement {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Python => "python",
            Self::HtmlDocsValidator => "html_docs_validator",
        }
    }
}

/// Result of detecting one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ToolAvailability {
    /// The tool is usable.
    Available,
    /// No configured or searched path existed.
    Missing,
    /// A candidate existed but was not an executable regular file.
    NotExecutable {
        /// Rejected path.
        path: String,
    },
    /// A candidate existed but was not a regular file.
    NotAFile {
        /// Rejected path.
        path: String,
    },
    /// The executable exists but is older than the required version.
    InsufficientVersion {
        /// Required minimum.
        minimum: PythonVersion,
        /// Version actually found.
        found: PythonVersion,
    },
    /// The validator script exists but no usable Python interpreter was found.
    InterpreterMissing,
    /// The executable could not be probed.
    ProbeFailed {
        /// Sanitized failure detail. No command output is carried.
        detail: String,
    },
    /// The filesystem rejected the probe.
    Io {
        /// Path involved.
        path: String,
        /// Sanitized error kind.
        error_kind: String,
    },
}

impl ToolAvailability {
    /// Whether the tool is usable.
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Detection result for a single executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolDetection {
    /// Which tool was requested.
    pub tool: ToolRequirement,
    /// Explicit paths configured by the host, in order.
    pub configured_paths: Vec<AbsolutePath>,
    /// Path actually executed, when one was found.
    pub executable_path: Option<AbsolutePath>,
    /// Reported version string, when the probe returned one.
    pub version: Option<String>,
    /// Availability result.
    pub status: ToolAvailability,
}

impl ToolDetection {
    /// Whether this tool is usable.
    pub fn is_available(&self) -> bool {
        self.status.is_available()
    }
}

/// Evidence that the configured validator started with the selected Python.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidatorProbe {
    /// Exit code reported by the validator, when it exited.
    pub exit_code: Option<i32>,
    /// Whether the validator wrote anything to stdout or stderr.
    pub responded: bool,
}

/// Detection result for the user's SDD validator script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidatorDetection {
    /// Constant [`ToolRequirement::HtmlDocsValidator`].
    pub tool: ToolRequirement,
    /// Explicit script paths configured by the host.
    pub configured_paths: Vec<AbsolutePath>,
    /// Validator script actually selected.
    pub script_path: Option<AbsolutePath>,
    /// Python interpreter selected for the script.
    pub interpreter_path: Option<AbsolutePath>,
    /// Python version reported by the interpreter.
    pub version: Option<PythonVersion>,
    /// Availability result.
    pub status: ToolAvailability,
    /// Bounded no-argument probe result. It is not a validation success claim.
    pub probe: Option<ValidatorProbe>,
}

impl ValidatorDetection {
    /// Whether the validator is usable.
    pub fn is_available(&self) -> bool {
        self.status.is_available()
    }
}

/// One unmet toolchain requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolchainDeficiency {
    /// Unmet requirement.
    pub tool: ToolRequirement,
    /// Explicit paths configured by the host, in order.
    pub configured_paths: Vec<AbsolutePath>,
    /// Why the requirement is unmet.
    pub status: ToolAvailability,
}

/// Result of detecting every H1 toolchain requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolchainReport {
    /// Git detection.
    pub git: ToolDetection,
    /// Python detection.
    pub python: ToolDetection,
    /// SDD HTML validator detection.
    pub html_docs: ValidatorDetection,
}

impl ToolchainReport {
    /// Whether every required tool is usable.
    pub fn is_ready(&self) -> bool {
        self.git.is_available() && self.python.is_available() && self.html_docs.is_available()
    }

    /// Returns the deficiency for one requirement, if unmet.
    pub fn deficiency(&self, tool: ToolRequirement) -> Option<ToolchainDeficiency> {
        match tool {
            ToolRequirement::Git => detection_deficiency(&self.git),
            ToolRequirement::Python => detection_deficiency(&self.python),
            ToolRequirement::HtmlDocsValidator => self.validator_def(),
        }
    }

    /// Returns every unmet requirement in stable order.
    pub fn deficiencies(&self) -> Vec<ToolchainDeficiency> {
        [
            ToolRequirement::Git,
            ToolRequirement::Python,
            ToolRequirement::HtmlDocsValidator,
        ]
        .into_iter()
        .filter_map(|tool| self.deficiency(tool))
        .collect()
    }

    /// Returns an error-like deficiency result when `tool` is unusable.
    pub fn require(&self, tool: ToolRequirement) -> Result<(), ToolchainDeficiency> {
        match self.deficiency(tool) {
            Some(deficiency) => Err(deficiency),
            None => Ok(()),
        }
    }

    fn validator_def(&self) -> Option<ToolchainDeficiency> {
        if self.html_docs.is_available() {
            return None;
        }
        Some(ToolchainDeficiency {
            tool: ToolRequirement::HtmlDocsValidator,
            configured_paths: self.html_docs.configured_paths.clone(),
            status: self.html_docs.status.clone(),
        })
    }
}

fn detection_deficiency(detection: &ToolDetection) -> Option<ToolchainDeficiency> {
    if detection.is_available() {
        return None;
    }
    Some(ToolchainDeficiency {
        tool: detection.tool,
        configured_paths: detection.configured_paths.clone(),
        status: detection.status.clone(),
    })
}

/// Host-supplied toolchain configuration.
///
/// `path_dirs` is a snapshot of `PATH`; it is used only after configured
/// `search_dirs`. Relative directory entries are ignored. Explicit executable
/// paths are authoritative and are the only candidates considered when
/// present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainConfig {
    search_dirs: Vec<PathBuf>,
    path_dirs: Vec<PathBuf>,
    git_paths: Vec<PathBuf>,
    python_paths: Vec<PathBuf>,
    html_docs_paths: Vec<PathBuf>,
    minimum_python: PythonVersion,
}

impl ToolchainConfig {
    /// An empty configuration with no directories or explicit paths.
    pub fn empty() -> Self {
        Self {
            search_dirs: Vec::new(),
            path_dirs: Vec::new(),
            git_paths: Vec::new(),
            python_paths: Vec::new(),
            html_docs_paths: Vec::new(),
            minimum_python: MINIMUM_PYTHON_VERSION,
        }
    }

    /// Captures the current `PATH` directories. The process environment is
    /// only read here, so detection itself is deterministic.
    pub fn from_environment() -> Self {
        let path_dirs = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        Self {
            path_dirs,
            ..Self::empty()
        }
    }

    /// Replaces the captured `PATH` directory list.
    pub fn with_path_dirs<I, P>(mut self, dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.path_dirs = dirs
            .into_iter()
            .map(|dir| dir.as_ref().to_path_buf())
            .collect();
        self
    }

    /// Adds a configured directory searched before `PATH`.
    pub fn with_search_dir(mut self, dir: impl AsRef<Path>) -> Result<Self, CoreError> {
        self.search_dirs
            .push(validate_absolute_path("toolchain.searchDir", dir.as_ref())?);
        Ok(self)
    }

    /// Adds an explicit Git executable candidate.
    pub fn with_git_path(mut self, path: impl AsRef<Path>) -> Result<Self, CoreError> {
        self.git_paths
            .push(validate_absolute_path("toolchain.git", path.as_ref())?);
        Ok(self)
    }

    /// Adds an explicit Python executable candidate.
    pub fn with_python_path(mut self, path: impl AsRef<Path>) -> Result<Self, CoreError> {
        self.python_paths
            .push(validate_absolute_path("toolchain.python", path.as_ref())?);
        Ok(self)
    }

    /// Adds an explicit validator script candidate.
    pub fn with_html_docs_path(mut self, path: impl AsRef<Path>) -> Result<Self, CoreError> {
        self.html_docs_paths
            .push(validate_absolute_path("toolchain.htmlDocs", path.as_ref())?);
        Ok(self)
    }

    /// Configured search directories.
    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    /// Captured `PATH` directories.
    pub fn path_dirs(&self) -> &[PathBuf] {
        &self.path_dirs
    }

    /// Minimum Python version.
    pub const fn minimum_python(&self) -> PythonVersion {
        self.minimum_python
    }
}

impl Default for ToolchainConfig {
    fn default() -> Self {
        Self::empty()
    }
}

fn validate_absolute_path(field: &str, path: &Path) -> Result<PathBuf, CoreError> {
    let Some(text) = path.to_str() else {
        return Err(CoreError::InvalidValue {
            field: field.to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: "path is not valid UTF-8".to_owned(),
            },
        });
    };
    AbsolutePath::new(text)?;
    Ok(path.to_path_buf())
}

/// Runs detection against one configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainDetector {
    config: ToolchainConfig,
}

impl ToolchainDetector {
    /// Creates a detector for `config`.
    pub fn new(config: ToolchainConfig) -> Self {
        Self { config }
    }

    /// Borrows the configuration.
    pub fn config(&self) -> &ToolchainConfig {
        &self.config
    }

    /// Detects Git, Python, and the configured SDD validator.
    pub fn detect(&self) -> ToolchainReport {
        let git = self.detect_git();
        let python = self.detect_python();
        let html_docs = self.detect_html_docs(&python);
        ToolchainReport {
            git,
            python,
            html_docs,
        }
    }

    fn detect_git(&self) -> ToolDetection {
        let resolved = self.resolve_executable(&self.config.git_paths, "git");
        let mut detection = ToolDetection {
            tool: ToolRequirement::Git,
            configured_paths: resolved.configured,
            executable_path: resolved.path.as_ref().map(|path| absolute(path)),
            version: None,
            status: resolved.failure,
        };
        if let Some(path) = &resolved.path {
            match Command::new(path).arg("--version").output() {
                Ok(output) if output.status.success() => {
                    detection.status = ToolAvailability::Available;
                    detection.version = first_line(&output.stdout)
                        .map(|line| {
                            line.strip_prefix("git version ")
                                .unwrap_or(line.as_str())
                                .to_owned()
                        })
                        .or_else(|| first_line(&output.stderr));
                }
                Ok(output) => {
                    detection.status = ToolAvailability::ProbeFailed {
                        detail: format!("git --version exited with {:?}", output.status.code()),
                    };
                }
                Err(error) => {
                    detection.status = ToolAvailability::ProbeFailed {
                        detail: format!("cannot execute git: {:?}", error.kind()),
                    };
                }
            }
        }
        detection
    }

    fn detect_python(&self) -> ToolDetection {
        let resolved = self.resolve_executable(&self.config.python_paths, "python3");
        let mut detection = ToolDetection {
            tool: ToolRequirement::Python,
            configured_paths: resolved.configured,
            executable_path: resolved.path.as_ref().map(|path| absolute(path)),
            version: None,
            status: resolved.failure,
        };
        if let Some(path) = &resolved.path {
            match Command::new(path).arg("--version").output() {
                Ok(output) => match python_version(&output) {
                    Some(version) => {
                        detection.version = Some(version.to_string());
                        detection.status = if version >= self.config.minimum_python {
                            ToolAvailability::Available
                        } else {
                            ToolAvailability::InsufficientVersion {
                                minimum: self.config.minimum_python,
                                found: version,
                            }
                        };
                    }
                    None => {
                        detection.status = ToolAvailability::ProbeFailed {
                            detail: "python --version did not report a version".to_owned(),
                        };
                    }
                },
                Err(error) => {
                    detection.status = ToolAvailability::ProbeFailed {
                        detail: format!("cannot execute python: {:?}", error.kind()),
                    };
                }
            }
        }
        detection
    }

    fn detect_html_docs(&self, python: &ToolDetection) -> ValidatorDetection {
        let resolved = self.resolve_executable(&self.config.html_docs_paths, "html-docs");
        let mut detection = ValidatorDetection {
            tool: ToolRequirement::HtmlDocsValidator,
            configured_paths: resolved.configured,
            script_path: resolved.path.as_ref().map(|path| absolute(path)),
            interpreter_path: python.executable_path.clone(),
            version: python
                .version
                .as_deref()
                .and_then(|value| value.parse().ok()),
            status: resolved.failure,
            probe: None,
        };
        if let Some(script) = &resolved.path {
            if !python.is_available() {
                detection.status = match &python.status {
                    ToolAvailability::InsufficientVersion { minimum, found } => {
                        ToolAvailability::InsufficientVersion {
                            minimum: *minimum,
                            found: *found,
                        }
                    }
                    _ => ToolAvailability::InterpreterMissing,
                };
                detection.probe = None;
                return detection;
            }
            let Some(interpreter) = python.executable_path.as_ref() else {
                detection.status = ToolAvailability::InterpreterMissing;
                return detection;
            };
            match probe_validator(interpreter.as_path(), script) {
                Ok(probe) => {
                    detection.status = ToolAvailability::Available;
                    detection.probe = Some(probe);
                }
                Err(status) => {
                    detection.status = status;
                    detection.probe = None;
                }
            }
        }
        detection
    }

    fn resolve_executable(&self, explicit: &[PathBuf], name: &str) -> ResolvedExecutable {
        let configured = explicit.iter().map(|path| absolute(path)).collect();
        let candidates = if explicit.is_empty() {
            let mut seen = BTreeSet::new();
            self.config
                .search_dirs
                .iter()
                .chain(self.config.path_dirs.iter())
                .map(|dir| dir.join(name))
                .filter(|path| path.is_absolute())
                .filter(|path| seen.insert(path.clone()))
                .collect()
        } else {
            explicit.to_vec()
        };

        let mut first_failure = None;
        for candidate in candidates {
            match fs::metadata(&candidate) {
                Ok(metadata) if !metadata.is_file() => {
                    first_failure.get_or_insert(ToolAvailability::NotAFile {
                        path: candidate.to_string_lossy().into_owned(),
                    });
                }
                Ok(metadata) if !is_executable(&metadata) => {
                    first_failure.get_or_insert(ToolAvailability::NotExecutable {
                        path: candidate.to_string_lossy().into_owned(),
                    });
                }
                Ok(_) => {
                    return ResolvedExecutable {
                        path: Some(candidate),
                        configured,
                        failure: ToolAvailability::Available,
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    first_failure.get_or_insert(ToolAvailability::Missing);
                }
                Err(error) => {
                    first_failure.get_or_insert(ToolAvailability::Io {
                        path: candidate.to_string_lossy().into_owned(),
                        error_kind: format!("{:?}", error.kind()),
                    });
                }
            }
        }
        ResolvedExecutable {
            path: None,
            configured,
            failure: first_failure.unwrap_or(ToolAvailability::Missing),
        }
    }
}

struct ResolvedExecutable {
    path: Option<PathBuf>,
    configured: Vec<AbsolutePath>,
    failure: ToolAvailability,
}

fn absolute(path: &Path) -> AbsolutePath {
    AbsolutePath::new(path.to_string_lossy().into_owned())
        .expect("configured toolchain paths are absolute UTF-8")
}

fn python_version(output: &std::process::Output) -> Option<PythonVersion> {
    PythonVersion::from_banner(&String::from_utf8_lossy(&output.stdout))
        .or_else(|| PythonVersion::from_banner(&String::from_utf8_lossy(&output.stderr)))
}

fn first_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn probe_validator(interpreter: &Path, script: &Path) -> Result<ValidatorProbe, ToolAvailability> {
    let output = Command::new(interpreter)
        .arg("-B")
        .arg(script)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| ToolAvailability::ProbeFailed {
            detail: format!("cannot start validator: {:?}", error.kind()),
        })?;
    Ok(ValidatorProbe {
        exit_code: output.status.code(),
        responded: !output.stdout.is_empty() || !output.stderr.is_empty(),
    })
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_python_banner() {
        assert_eq!(
            PythonVersion::from_banner("Python 3.14.7\n"),
            Some(PythonVersion::new(3, 14, 7))
        );
        assert_eq!(
            PythonVersion::from_banner("Python 3.10\n"),
            Some(PythonVersion::new(3, 10, 0))
        );
        assert_eq!(PythonVersion::from_banner("not a version"), None);
    }

    #[test]
    fn version_order_is_numeric() {
        assert!(PythonVersion::new(3, 11, 0) < PythonVersion::new(3, 12, 0));
        assert!(PythonVersion::new(3, 9, 6) < MINIMUM_PYTHON_VERSION);
    }

    #[test]
    fn config_rejects_relative_explicit_paths() {
        assert!(ToolchainConfig::empty().with_git_path("bin/git").is_err());
        assert!(
            ToolchainConfig::empty()
                .with_python_path("/usr/bin/python3")
                .is_ok()
        );
    }
}
