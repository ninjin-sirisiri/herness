//! Read-only access to one configured SDD pack.
//!
//! A pack root is an explicit, absolute directory supplied by the host. Skills
//! are addressed as `skills/<id>/SKILL.md` below that root. Relative
//! references inside a skill resolve against the skill's own location inside
//! the pack, never against the project, the process working directory, or a
//! copied `SKILL.md`. This module never writes to the pack.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::path::AbsolutePath;
use crate::skills::digest::SkillDigest;
use crate::skills::error::SkillFailure;

const SKILL_DOCUMENT: &str = "SKILL.md";
const SKILLS_DIRECTORY: &str = "skills";
const FINGERPRINT_DOMAIN: &[u8] = b"herness.skill.fingerprint.v1\0";

/// Identifier of one skill directory below `<pack-root>/skills/`.
///
/// The identifier is a single path component. A copied `SKILL.md` elsewhere is
/// not an alternative identifier or a canonical source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SkillId(String);

impl SkillId {
    /// Validates a single skill directory name.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        let invalid = |detail: &str| CoreError::InvalidValue {
            field: "skillId".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: detail.to_owned(),
            },
        };
        if value.is_empty() {
            return Err(invalid("must not be empty"));
        }
        if value.contains('\0') {
            return Err(invalid("must not contain a NUL byte"));
        }
        if value == "." || value == ".." {
            return Err(invalid("must name a skill directory, not a relative path"));
        }
        if value.contains('/') || value.contains('\\') {
            return Err(invalid("must be a single path component"));
        }
        Ok(Self(value))
    }

    /// Borrows the skill directory name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SkillId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SkillId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for SkillId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SkillId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// One referenced file included in a skill fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillReference {
    /// Reference text as written in the skill or supplied by the host.
    pub declared: String,
    /// Canonical absolute path inside the pack.
    pub path: AbsolutePath,
    /// Pack-relative path using `/` separators.
    pub relative_path: String,
    /// SHA-256 of the original reference bytes.
    pub digest: SkillDigest,
    /// Number of bytes read.
    pub byte_length: u64,
}

/// Fingerprint of a skill document and the referenced files included with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillFingerprint {
    /// SHA-256 over the original `SKILL.md` bytes.
    pub document: SkillDigest,
    /// Referenced files, ordered by pack-relative path.
    pub references: Vec<SkillReference>,
    /// SHA-256 over the domain-separated document and reference digests.
    pub combined: SkillDigest,
}

impl SkillFingerprint {
    /// Finds an included reference by pack-relative path.
    pub fn reference(&self, relative_path: &str) -> Option<&SkillReference> {
        self.references
            .iter()
            .find(|reference| reference.relative_path == relative_path)
    }
}

/// Identity of the pack source a skill was loaded from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillSource {
    /// Canonical pack root supplied by the host.
    pub pack_root: AbsolutePath,
    /// Skill directory name.
    pub skill_id: SkillId,
    /// Canonical path of the loaded `SKILL.md` inside the pack.
    pub skill_path: AbsolutePath,
    /// SHA-256 over the original `SKILL.md` bytes.
    pub document_digest: SkillDigest,
}

/// A skill loaded from the pack plus the fingerprint captured at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillDocument {
    source: SkillSource,
    text: String,
    fingerprint: SkillFingerprint,
    explicit_references: Vec<String>,
}

impl SkillDocument {
    /// Source identity of the loaded document.
    pub fn source(&self) -> &SkillSource {
        &self.source
    }

    /// Original UTF-8 skill text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Fingerprint captured when the document was loaded.
    pub fn fingerprint(&self) -> &SkillFingerprint {
        &self.fingerprint
    }

    /// Explicit relative references supplied at load time.
    pub fn explicit_references(&self) -> &[String] {
        &self.explicit_references
    }

    /// Recomputes the fingerprint and reports whether anything changed.
    pub fn revalidate(&self) -> Result<SkillRevalidation, CoreError> {
        let pack = SkillPack::open(self.source.pack_root.as_path())?;
        let current = pack.load_impl(&self.source.skill_id, &self.explicit_references)?;
        let changes = changes_between(&self.fingerprint, &current.fingerprint);
        Ok(SkillRevalidation {
            previous: self.fingerprint.clone(),
            current: current.fingerprint,
            changes,
        })
    }

    /// Reloads the skill from the pack with the same explicit references.
    pub fn reload(&self) -> Result<Self, CoreError> {
        let pack = SkillPack::open(self.source.pack_root.as_path())?;
        pack.load_impl(&self.source.skill_id, &self.explicit_references)
    }

    /// Fails with [`SkillFailure::ChangedDuringRun`] when the pack is no
    /// longer byte-identical to the loaded fingerprint.
    pub fn ensure_current(&self) -> Result<(), CoreError> {
        let revalidation = self.revalidate()?;
        if revalidation.changed() {
            return Err(self.error(SkillFailure::ChangedDuringRun {
                previous: revalidation.previous.combined,
                current: revalidation.current.combined,
            }));
        }
        Ok(())
    }

    fn error(&self, failure: SkillFailure) -> CoreError {
        CoreError::SkillFailed {
            skill: self.source.skill_id.clone(),
            failure,
        }
    }
}

/// One change observed while revalidating a skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum SkillChange {
    /// The `SKILL.md` bytes changed.
    DocumentChanged {
        /// Fingerprint at load time.
        previous: SkillDigest,
        /// Fingerprint observed now.
        current: SkillDigest,
    },
    /// An included reference changed.
    ReferenceChanged {
        /// Pack-relative path.
        path: String,
        /// Digest at load time.
        previous: SkillDigest,
        /// Digest observed now.
        current: SkillDigest,
    },
    /// A new referenced file is now included.
    ReferenceAdded {
        /// Pack-relative path.
        path: String,
        /// Digest observed now.
        current: SkillDigest,
    },
    /// A previously included referenced file is no longer included.
    ReferenceRemoved {
        /// Pack-relative path.
        path: String,
        /// Digest at load time.
        previous: SkillDigest,
    },
}

/// Result of recomputing a loaded skill's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillRevalidation {
    /// Fingerprint captured at load time.
    pub previous: SkillFingerprint,
    /// Fingerprint observed now.
    pub current: SkillFingerprint,
    /// Structured changes, ordered by pack-relative path.
    pub changes: Vec<SkillChange>,
}

impl SkillRevalidation {
    /// Whether any document or included reference changed.
    pub fn changed(&self) -> bool {
        !self.changes.is_empty()
    }
}

/// One configured SDD pack root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPack {
    root: PathBuf,
}

impl SkillPack {
    /// Opens an existing absolute pack directory and canonicalizes its root.
    ///
    /// Read-only: opening validates the root but never creates or modifies
    /// anything.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CoreError> {
        let path = path.as_ref();
        let display = path.to_string_lossy().into_owned();
        let Some(text) = path.to_str() else {
            return Err(CoreError::InvalidValue {
                field: "packRoot".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "pack root is not valid UTF-8".to_owned(),
                },
            });
        };
        AbsolutePath::new(text)?;
        let root = fs::canonicalize(path).map_err(|error| CoreError::InvalidValue {
            field: "packRoot".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: format!("cannot canonicalize {}: {}", display, error.kind()),
            },
        })?;
        let metadata = fs::metadata(&root).map_err(|error| CoreError::InvalidValue {
            field: "packRoot".to_owned(),
            violation: ArgumentViolation::Invalid {
                detail: format!("cannot read {}: {}", display, error.kind()),
            },
        })?;
        if !metadata.is_dir() {
            return Err(CoreError::InvalidValue {
                field: "packRoot".to_owned(),
                violation: ArgumentViolation::Invalid {
                    detail: "pack root is not a directory".to_owned(),
                },
            });
        }
        Ok(Self { root })
    }

    /// Canonical pack root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Canonical pack root as a contract path value.
    pub fn root_absolute(&self) -> Result<AbsolutePath, CoreError> {
        AbsolutePath::new(self.root.to_string_lossy().into_owned())
    }

    /// Loads `<pack-root>/skills/<id>/SKILL.md`, including markdown link
    /// targets that resolve to files inside the pack.
    pub fn load(&self, id: &SkillId) -> Result<SkillDocument, CoreError> {
        self.load_impl(id, &[])
    }

    /// Loads a skill and adds explicit references relative to the skill's
    /// directory.
    ///
    /// Explicit references are for prose mentions that are not markdown links,
    /// such as a template named in running text. Duplicate paths are included
    /// once.
    pub fn load_with_references<S: AsRef<str>>(
        &self,
        id: &SkillId,
        references: &[S],
    ) -> Result<SkillDocument, CoreError> {
        let references = references
            .iter()
            .map(|reference| reference.as_ref().to_owned())
            .collect::<Vec<_>>();
        self.load_impl(id, &references)
    }

    fn load_impl(
        &self,
        id: &SkillId,
        explicit_references: &[String],
    ) -> Result<SkillDocument, CoreError> {
        let skill_directory = self.root.join(SKILLS_DIRECTORY).join(id.as_str());
        let requested_path = skill_directory.join(SKILL_DOCUMENT);
        let skill_path = self.canonical_file(id, &requested_path)?;
        let bytes = self.read_bytes(id, &skill_path)?;
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| {
            self.error(
                id,
                SkillFailure::InvalidUtf8 {
                    path: skill_path.to_string_lossy().into_owned(),
                },
            )
        })?;
        let document_digest = SkillDigest::of_bytes(&bytes);

        let mut requested = Vec::new();
        for target in markdown_link_targets(&text) {
            requested.push((target, false));
        }
        for reference in explicit_references {
            requested.push((reference.clone(), true));
        }

        let mut resolved = Vec::new();
        for (declared, explicit) in requested {
            let Some(reference) =
                self.resolve_reference(&skill_directory, &declared, explicit, id)?
            else {
                continue;
            };
            resolved.push(reference);
        }
        resolved.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        resolved.dedup_by(|left, right| left.relative_path == right.relative_path);

        let mut references = Vec::with_capacity(resolved.len());
        for reference in resolved {
            let bytes = self.read_bytes(id, &reference.path)?;
            references.push(SkillReference {
                declared: reference.declared,
                path: AbsolutePath::new(reference.path.to_string_lossy().into_owned())?,
                relative_path: reference.relative_path,
                digest: SkillDigest::of_bytes(&bytes),
                byte_length: bytes.len() as u64,
            });
        }
        let combined = combined_digest(&document_digest, &references);

        let pack_root = AbsolutePath::new(self.root.to_string_lossy().into_owned())?;
        let skill_path = AbsolutePath::new(skill_path.to_string_lossy().into_owned())?;
        Ok(SkillDocument {
            source: SkillSource {
                pack_root,
                skill_id: id.clone(),
                skill_path,
                document_digest: document_digest.clone(),
            },
            text,
            fingerprint: SkillFingerprint {
                document: document_digest,
                references,
                combined,
            },
            explicit_references: explicit_references.to_vec(),
        })
    }

    fn canonical_file(&self, id: &SkillId, path: &Path) -> Result<PathBuf, CoreError> {
        let canonical = match fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(self.error(
                    id,
                    SkillFailure::NotFound {
                        path: path.to_string_lossy().into_owned(),
                    },
                ));
            }
            Err(error) => {
                return Err(self.error(
                    id,
                    SkillFailure::Io {
                        path: path.to_string_lossy().into_owned(),
                        error_kind: format!("{:?}", error.kind()),
                    },
                ));
            }
        };
        if !canonical.starts_with(&self.root) {
            return Err(self.error(
                id,
                SkillFailure::OutsidePack {
                    path: canonical.to_string_lossy().into_owned(),
                },
            ));
        }
        let metadata = fs::metadata(&canonical).map_err(|error| {
            self.error(
                id,
                SkillFailure::Io {
                    path: canonical.to_string_lossy().into_owned(),
                    error_kind: format!("{:?}", error.kind()),
                },
            )
        })?;
        if !metadata.is_file() {
            return Err(self.error(
                id,
                SkillFailure::NotAFile {
                    path: canonical.to_string_lossy().into_owned(),
                },
            ));
        }
        Ok(canonical)
    }

    fn resolve_reference(
        &self,
        skill_directory: &Path,
        declared: &str,
        explicit: bool,
        id: &SkillId,
    ) -> Result<Option<ResolvedReference>, CoreError> {
        let relative = Path::new(declared);
        if relative.is_absolute() {
            return Err(self.error(
                id,
                SkillFailure::InvalidReference {
                    reference: declared.to_owned(),
                    detail: "absolute references do not resolve against the pack".to_owned(),
                },
            ));
        }
        if relative
            .components()
            .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
        {
            return Err(self.error(
                id,
                SkillFailure::InvalidReference {
                    reference: declared.to_owned(),
                    detail: "reference must be relative to the skill directory".to_owned(),
                },
            ));
        }

        let candidate = skill_directory.join(relative);
        let canonical = match fs::canonicalize(&candidate) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if explicit {
                    return Err(self.error(
                        id,
                        SkillFailure::NotFound {
                            path: candidate.to_string_lossy().into_owned(),
                        },
                    ));
                }
                return Ok(None);
            }
            Err(error) => {
                return Err(self.error(
                    id,
                    SkillFailure::Io {
                        path: candidate.to_string_lossy().into_owned(),
                        error_kind: format!("{:?}", error.kind()),
                    },
                ));
            }
        };
        if !canonical.starts_with(&self.root) {
            return Err(self.error(
                id,
                SkillFailure::OutsidePack {
                    path: canonical.to_string_lossy().into_owned(),
                },
            ));
        }
        let metadata = fs::metadata(&canonical).map_err(|error| {
            self.error(
                id,
                SkillFailure::Io {
                    path: canonical.to_string_lossy().into_owned(),
                    error_kind: format!("{:?}", error.kind()),
                },
            )
        })?;
        if !metadata.is_file() {
            if explicit {
                return Err(self.error(
                    id,
                    SkillFailure::NotAFile {
                        path: canonical.to_string_lossy().into_owned(),
                    },
                ));
            }
            return Ok(None);
        }
        Ok(Some(ResolvedReference {
            declared: declared.to_owned(),
            path: canonical.clone(),
            relative_path: pack_relative(&self.root, &canonical)
                .map_err(|failure| self.error(id, failure))?,
        }))
    }

    fn read_bytes(&self, id: &SkillId, path: &Path) -> Result<Vec<u8>, CoreError> {
        fs::read(path).map_err(|error| {
            self.error(
                id,
                SkillFailure::Io {
                    path: path.to_string_lossy().into_owned(),
                    error_kind: format!("{:?}", error.kind()),
                },
            )
        })
    }

    fn error(&self, id: &SkillId, failure: SkillFailure) -> CoreError {
        CoreError::SkillFailed {
            skill: id.clone(),
            failure,
        }
    }
}

struct ResolvedReference {
    declared: String,
    path: PathBuf,
    relative_path: String,
}

fn pack_relative(root: &Path, path: &Path) -> Result<String, SkillFailure> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SkillFailure::OutsidePack {
            path: path.to_string_lossy().into_owned(),
        })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(SkillFailure::InvalidReference {
                        reference: relative.to_string_lossy().into_owned(),
                        detail: "pack-relative path is not valid UTF-8".to_owned(),
                    });
                };
                parts.push(part);
            }
            Component::CurDir => {}
            _ => {
                return Err(SkillFailure::OutsidePack {
                    path: path.to_string_lossy().into_owned(),
                });
            }
        }
    }
    Ok(parts.join("/"))
}

fn combined_digest(document: &SkillDigest, references: &[SkillReference]) -> SkillDigest {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hash_field(&mut hasher, document.as_str().as_bytes());
    hasher.update((references.len() as u64).to_be_bytes());
    for reference in references {
        hash_field(&mut hasher, reference.relative_path.as_bytes());
        hash_field(&mut hasher, reference.digest.as_str().as_bytes());
    }
    SkillDigest::from_sha256(hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn changes_between(previous: &SkillFingerprint, current: &SkillFingerprint) -> Vec<SkillChange> {
    let mut changes = Vec::new();
    if previous.document != current.document {
        changes.push(SkillChange::DocumentChanged {
            previous: previous.document.clone(),
            current: current.document.clone(),
        });
    }

    let previous_refs = previous
        .references
        .iter()
        .map(|reference| (reference.relative_path.clone(), reference))
        .collect::<BTreeMap<_, _>>();
    let current_refs = current
        .references
        .iter()
        .map(|reference| (reference.relative_path.clone(), reference))
        .collect::<BTreeMap<_, _>>();

    for (path, reference) in &current_refs {
        match previous_refs.get(path) {
            Some(previous_reference) if previous_reference.digest != reference.digest => {
                changes.push(SkillChange::ReferenceChanged {
                    path: path.clone(),
                    previous: previous_reference.digest.clone(),
                    current: reference.digest.clone(),
                });
            }
            Some(_) => {}
            None => changes.push(SkillChange::ReferenceAdded {
                path: path.clone(),
                current: reference.digest.clone(),
            }),
        }
    }
    for (path, reference) in &previous_refs {
        if !current_refs.contains_key(path) {
            changes.push(SkillChange::ReferenceRemoved {
                path: path.clone(),
                previous: reference.digest.clone(),
            });
        }
    }
    changes
}

/// Extracts relative file targets from markdown links (`[text](target)`).
///
/// External URLs, anchors, absolute paths, and empty targets are ignored.
/// Missing targets are ignored by loading; a target that exists outside the
/// pack is rejected by resolution.
fn markdown_link_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find("](") {
        let start = cursor + offset + 2;
        let Some(end) = text[start..].find(')') else {
            break;
        };
        let end = start + end;
        if let Some(target) = normalize_markdown_target(&text[start..end]) {
            targets.push(target);
        }
        cursor = end + 1;
    }
    targets
}

fn normalize_markdown_target(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let target = if let Some(rest) = raw.strip_prefix('<') {
        let end = rest.find('>')?;
        &rest[..end]
    } else {
        raw.split_whitespace().next()?
    };
    let target = target.split('#').next().unwrap_or_default();
    if target.is_empty() || target.starts_with('/') {
        return None;
    }
    let lowered = target.to_ascii_lowercase();
    if lowered.starts_with("http://")
        || lowered.starts_with("https://")
        || lowered.starts_with("mailto:")
        || lowered.starts_with("tel:")
        || lowered.starts_with("data:")
    {
        return None;
    }
    Some(target.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_id_is_one_component() {
        assert!(SkillId::new("sdd-execute").is_ok());
        assert!(SkillId::new("").is_err());
        assert!(SkillId::new(".").is_err());
        assert!(SkillId::new("..").is_err());
        assert!(SkillId::new("a/b").is_err());
        assert!(SkillId::new("a\\b").is_err());
    }

    #[test]
    fn markdown_targets_skip_external_anchors_and_absolute_paths() {
        let targets = markdown_link_targets(
            "[a](reference.md) [b](https://example.com/x) [c](#anchor) [d](/etc/passwd) \
             [e](<files/with space.md>) ![f](image.png)",
        );
        assert_eq!(
            targets,
            vec![
                "reference.md".to_owned(),
                "files/with space.md".to_owned(),
                "image.png".to_owned()
            ]
        );
    }
}
