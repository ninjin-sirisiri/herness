//! Immutable authoring workspace snapshots.
//!
//! One generation is authored from exactly the bytes that were observed for the
//! Markdown source, the current HTML companion, the shared CSS, and every
//! declared resource. This module reads those bytes through the same
//! [`SourceReadPort`] the observer uses, so canonical project-relative paths,
//! root checks, and symlink escapes are handled in one place. It never writes a
//! formal document, companion, CSS file, or settings record.
//!
//! The returned [`AuthoringSnapshot`] carries the exact bytes and their
//! SHA-256 digests plus the policy/condition identity from the approved H3
//! settings. [`AuthoringSnapshot::brief`] renders the immutable authoring
//! packet text; the candidate artifact slots carry the same exact bytes for the
//! child's `candidate_read` calls.

use herness_supervision::{ConditionDigest, ConditionVersion, ContentDigest};

use crate::document::{DocumentKey, FingerprintSet, SourceSnapshot};
use crate::error::H3Error;
use crate::observer::{
    DependencyKind, DependencyPath, FileRead, SourceReadError, SourceReadPort,
    dependency_fingerprint,
};

/// Maximum CSS bytes accepted into one authoring snapshot.
pub const MAX_SHARED_CSS_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum bytes accepted for one referenced resource.
pub const MAX_RESOURCE_BYTES: u64 = 8 * 1024 * 1024;

/// The kind of SDD document an authoring brief targets.
///
/// The common resolver decides the real Target set. This label only mirrors the
/// declared categories so the brief can describe the document type; it does
/// not discover or admit Targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocumentKind {
    /// The project `CONTEXT.md`.
    Context,
    /// A decision record under `docs/adr/`.
    Adr,
    /// A design specification under `docs/sdd/specs/`.
    Spec,
    /// An implementation plan under `docs/sdd/plans/`.
    Plan,
    /// Any other declared Markdown Target.
    Markdown,
}

impl DocumentKind {
    /// Classifies one canonical Target path.
    pub fn from_path(path: &str) -> Self {
        if path == "CONTEXT.md" {
            Self::Context
        } else if path.starts_with("docs/adr/") {
            Self::Adr
        } else if path.starts_with("docs/sdd/specs/") {
            Self::Spec
        } else if path.starts_with("docs/sdd/plans/") {
            Self::Plan
        } else {
            Self::Markdown
        }
    }

    /// Stable label used in the packet.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::Adr => "adr",
            Self::Spec => "specification",
            Self::Plan => "plan",
            Self::Markdown => "markdown",
        }
    }
}

/// Exact bytes and digest of one immutable authoring input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedInput {
    path: String,
    bytes: u64,
    digest: ContentDigest,
    text: String,
}

impl CapturedInput {
    /// Canonical project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact UTF-8 byte length.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// SHA-256 of the exact bytes.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Exact text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Exact bytes and digest of one referenced local resource.
///
/// Resources may be binary images. The authoring brief carries their path,
/// length, and digest; the child does not receive a native read path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedResource {
    path: String,
    bytes: u64,
    digest: ContentDigest,
}

impl CapturedResource {
    /// Canonical project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exact byte length.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// SHA-256 of the exact bytes.
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// The approved policy, condition, and limit context for one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringPolicy {
    settings_fingerprint: ContentDigest,
    policy_version: String,
    policy_fingerprint: ContentDigest,
    pack_fingerprint: ContentDigest,
    condition_version: ConditionVersion,
    conditions_digest: ConditionDigest,
    source_bytes_limit: u64,
    css_bytes_limit: u64,
    resource_bytes_limit: u64,
}

impl AuthoringPolicy {
    /// Creates a policy context from already-approved values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings_fingerprint: ContentDigest,
        policy_version: impl Into<String>,
        policy_fingerprint: ContentDigest,
        pack_fingerprint: ContentDigest,
        condition_version: ConditionVersion,
        conditions_digest: ConditionDigest,
        source_bytes_limit: u64,
        css_bytes_limit: u64,
        resource_bytes_limit: u64,
    ) -> Result<Self, H3Error> {
        let policy_version = policy_version.into();
        if policy_version.trim().is_empty() {
            return Err(H3Error::empty("policyVersion"));
        }
        if source_bytes_limit == 0 {
            return Err(H3Error::must_be_positive("sourceBytesLimit"));
        }
        if css_bytes_limit == 0 {
            return Err(H3Error::must_be_positive("cssBytesLimit"));
        }
        if resource_bytes_limit == 0 {
            return Err(H3Error::must_be_positive("resourceBytesLimit"));
        }
        Ok(Self {
            settings_fingerprint,
            policy_version,
            policy_fingerprint,
            pack_fingerprint,
            condition_version,
            conditions_digest,
            source_bytes_limit,
            css_bytes_limit,
            resource_bytes_limit,
        })
    }

    /// Fingerprint of the approved H3 settings version.
    pub const fn settings_fingerprint(&self) -> &ContentDigest {
        &self.settings_fingerprint
    }

    /// Approved common SDD policy version.
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Approved common SDD policy fingerprint.
    pub const fn policy_fingerprint(&self) -> &ContentDigest {
        &self.policy_fingerprint
    }

    /// Approved pack integration fingerprint.
    pub const fn pack_fingerprint(&self) -> &ContentDigest {
        &self.pack_fingerprint
    }

    /// Approved H2 condition version.
    pub const fn condition_version(&self) -> ConditionVersion {
        self.condition_version
    }

    /// Exact approved condition-content digest.
    pub const fn conditions_digest(&self) -> &ConditionDigest {
        &self.conditions_digest
    }

    /// Maximum Markdown source bytes.
    pub const fn source_bytes_limit(&self) -> u64 {
        self.source_bytes_limit
    }

    /// Maximum shared CSS bytes.
    pub const fn css_bytes_limit(&self) -> u64 {
        self.css_bytes_limit
    }

    /// Maximum bytes for one referenced resource.
    pub const fn resource_bytes_limit(&self) -> u64 {
        self.resource_bytes_limit
    }
}

/// Request to capture one immutable authoring snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCaptureRequest {
    document: DocumentKey,
    source: SourceSnapshot,
    dependencies: Vec<DependencyPath>,
    policy: AuthoringPolicy,
}

impl WorkspaceCaptureRequest {
    /// Creates a capture request for one observed stable source revision.
    pub fn new(
        document: DocumentKey,
        source: SourceSnapshot,
        mut dependencies: Vec<DependencyPath>,
        policy: AuthoringPolicy,
    ) -> Result<Self, H3Error> {
        dependencies.sort_by(|left, right| {
            left.path()
                .cmp(right.path())
                .then_with(|| left.kind().as_str().cmp(right.kind().as_str()))
        });
        for pair in dependencies.windows(2) {
            if pair[0].path() == pair[1].path() {
                return Err(H3Error::invalid(
                    "dependencies",
                    "one authoring snapshot cannot declare the same dependency twice",
                ));
            }
        }
        let css = dependencies
            .iter()
            .filter(|dependency| dependency.kind() == DependencyKind::Css)
            .count();
        if css > 1 {
            return Err(H3Error::invalid(
                "dependencies.css",
                "the candidate store exposes exactly one shared CSS snapshot",
            ));
        }
        Ok(Self {
            document,
            source,
            dependencies,
            policy,
        })
    }

    /// Document being authored.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Exact source revision and digest the generation is bound to.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Declared CSS and resource dependencies.
    pub fn dependencies(&self) -> &[DependencyPath] {
        &self.dependencies
    }

    /// Approved policy and limit context.
    pub const fn policy(&self) -> &AuthoringPolicy {
        &self.policy
    }
}

/// One immutable authoring snapshot for a generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringSnapshot {
    document: DocumentKey,
    source: SourceSnapshot,
    source_markdown: CapturedInput,
    existing_html: Option<CapturedInput>,
    shared_css: Option<CapturedInput>,
    resources: Vec<CapturedResource>,
    fingerprints: FingerprintSet,
    policy: AuthoringPolicy,
}

impl AuthoringSnapshot {
    /// Document this snapshot belongs to.
    pub const fn document(&self) -> &DocumentKey {
        &self.document
    }

    /// Source revision and digest this snapshot was read at.
    pub const fn source(&self) -> &SourceSnapshot {
        &self.source
    }

    /// Exact Markdown source.
    pub const fn source_markdown(&self) -> &CapturedInput {
        &self.source_markdown
    }

    /// Current HTML companion, when one exists.
    pub const fn existing_html(&self) -> Option<&CapturedInput> {
        self.existing_html.as_ref()
    }

    /// Shared CSS snapshot, when one is declared and exists.
    pub const fn shared_css(&self) -> Option<&CapturedInput> {
        self.shared_css.as_ref()
    }

    /// Referenced local resources in canonical path order.
    pub fn resources(&self) -> &[CapturedResource] {
        &self.resources
    }

    /// Separate fingerprints for this exact snapshot.
    pub const fn fingerprints(&self) -> &FingerprintSet {
        &self.fingerprints
    }

    /// Approved policy/condition context.
    pub const fn policy(&self) -> &AuthoringPolicy {
        &self.policy
    }

    /// Stable digest over every exact authoring input and the policy context.
    pub fn digest(&self) -> ContentDigest {
        let mut lines = vec![
            format!("h3-authoring-snapshot:{}", self.document.target_path()),
            format!("source:{}", self.source.digest()),
            format!("source-bytes:{}", self.source_markdown.bytes()),
        ];
        lines.push(format!("policy:{}", self.policy.policy_fingerprint));
        lines.push(format!("pack:{}", self.policy.pack_fingerprint));
        lines.push(format!(
            "conditions:{}:{}",
            self.policy.condition_version.get(),
            self.policy.conditions_digest
        ));
        if let Some(html) = &self.existing_html {
            lines.push(format!("existing-html:{}:{}", html.path, html.digest));
        } else {
            lines.push("existing-html:absent".to_owned());
        }
        if let Some(css) = &self.shared_css {
            lines.push(format!("css:{}:{}", css.path, css.digest));
        } else {
            lines.push("css:absent".to_owned());
        }
        for resource in &self.resources {
            lines.push(format!("resource:{}:{}", resource.path, resource.digest));
        }
        ContentDigest::sha256(lines.join("\n").as_bytes())
    }

    /// Deterministic, non-generic authoring brief for the H2 work packet.
    ///
    /// The brief names the exact immutable bytes the child must read through
    /// `candidate_read`. It never embeds a model-authored instruction and never
    /// grants a formal file or shell path.
    pub fn brief(&self) -> String {
        self.brief_inner(None)
    }

    /// The same brief plus the host-issued candidate handle the child must use
    /// as the `handle` argument of every candidate tool.
    pub fn brief_with_handle(&self, handle: &herness_core::ArtifactHandle) -> String {
        self.brief_inner(Some(handle))
    }

    fn brief_inner(&self, handle: Option<&herness_core::ArtifactHandle>) -> String {
        let kind = DocumentKind::from_path(self.document.target_path());
        let mut lines = Vec::new();
        lines.push(format!(
            "Author the HTML companion for the approved Target Markdown `{}` ({}).",
            self.document.target_path(),
            kind.as_str()
        ));
        lines.push(String::new());
        lines.push("Immutable authoring snapshot; do not substitute another version:".to_owned());
        lines.push(format!(
            "- source_markdown: path `{}`, {} bytes, digest {}",
            self.source_markdown.path, self.source_markdown.bytes, self.source_markdown.digest
        ));
        match &self.existing_html {
            Some(html) => lines.push(format!(
                "- existing_html: path `{}`, {} bytes, digest {}",
                html.path, html.bytes, html.digest
            )),
            None => lines.push("- existing_html: absent".to_owned()),
        }
        match &self.shared_css {
            Some(css) => lines.push(format!(
                "- shared_css: path `{}`, {} bytes, digest {}",
                css.path, css.bytes, css.digest
            )),
            None => lines.push("- shared_css: absent".to_owned()),
        }
        if self.resources.is_empty() {
            lines.push("- resources: none".to_owned());
        } else {
            for resource in &self.resources {
                lines.push(format!(
                    "- resource `{}`: {} bytes, digest {}",
                    resource.path, resource.bytes, resource.digest
                ));
            }
        }
        lines.push(String::new());
        lines.push("Approved policy and conditions:".to_owned());
        lines.push(format!(
            "- common SDD policy: {} ({})",
            self.policy.policy_version, self.policy.policy_fingerprint
        ));
        lines.push(format!(
            "- pack fingerprint: {}",
            self.policy.pack_fingerprint
        ));
        lines.push(format!(
            "- conditions version {} digest {}",
            self.policy.condition_version.get(),
            self.policy.conditions_digest
        ));
        lines.push(String::new());
        lines.push("Authoring rules:".to_owned());
        lines.push(
            "- Read the exact source, existing HTML, shared CSS, and resources only through \
             `candidate_read` with the host-issued artifact handle."
                .to_owned(),
        );
        lines.push(
            "- Write the candidate document with `candidate_write` or `candidate_edit` and the \
             `candidate_html` slot, and the visible-source mapping with `candidate_provenance`. \
             Record a concrete rationale."
                .to_owned(),
        );
        lines.push(
            "- Preserve the full meaning, conditions, exceptions, negations, scope, permissions, \
             failure results, dependencies, and required order. Paraphrasing and reordering are \
             allowed; a summary must not replace required information."
                .to_owned(),
        );
        lines.push(
            "- Use the shared CSS classes only. Do not add inline CSS, inline styles, scripts, \
             event attributes, foreignObject, external references, runtime drawing, animation, \
             or arbitrary embedded HTML."
                .to_owned(),
        );
        lines.push(
            "- Never write the formal Markdown, HTML companion, CSS, settings, evidence, or \
             receipt. Never request a project path, native file tool, or shell."
                .to_owned(),
        );
        if let Some(handle) = handle {
            lines.push(String::new());
            lines.push(format!(
                "Candidate handle JSON: {}",
                serde_json::json!({
                    "projectId": handle.project_id(),
                    "jobId": handle.job_id(),
                    "generation": handle.generation(),
                    "token": handle.token(),
                })
            ));
        }
        lines.push(String::new());
        lines.push(format!("Snapshot digest: {}", self.digest()));
        lines.join("\n")
    }
}

/// Read boundary used by the coordinator to build one immutable snapshot.
pub trait AuthoringWorkspace {
    /// Reads the exact bytes for one generation without writing anything.
    fn capture(&self, request: &WorkspaceCaptureRequest) -> Result<AuthoringSnapshot, H3Error>;
}

/// Workspace reader over the observer's canonical source read port.
#[derive(Debug, Clone)]
pub struct WorkspaceReader<R> {
    reader: R,
}

impl<R: SourceReadPort> WorkspaceReader<R> {
    /// Creates a reader over an existing source read port.
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }
}

impl<R: SourceReadPort> AuthoringWorkspace for WorkspaceReader<R> {
    fn capture(&self, request: &WorkspaceCaptureRequest) -> Result<AuthoringSnapshot, H3Error> {
        let policy = &request.policy;
        let source = read_exact(
            &self.reader,
            request.document.target_path(),
            policy.source_bytes_limit,
            "sourceMarkdown",
        )?;
        if source.digest != *request.source.digest() {
            return Err(H3Error::invalid(
                "sourceDigest",
                "the stable read no longer matches the observed source revision",
            ));
        }

        let companion_path = request.document.companion_path();
        let existing_html = read_optional(
            &self.reader,
            &companion_path,
            policy.resource_bytes_limit,
            "existingHtml",
        )?;

        let mut shared_css = None;
        let mut resources = Vec::new();
        let mut css_digests = Vec::new();
        let mut resource_digests = Vec::new();
        for dependency in &request.dependencies {
            let limit = match dependency.kind() {
                DependencyKind::Css => policy.css_bytes_limit,
                DependencyKind::Resource => policy.resource_bytes_limit,
            };
            match dependency.kind() {
                DependencyKind::Css => {
                    let Some(captured) =
                        read_optional(&self.reader, dependency.path(), limit, "dependency")?
                    else {
                        continue;
                    };
                    css_digests.push((captured.path.clone(), captured.digest.clone()));
                    shared_css = Some(captured);
                }
                DependencyKind::Resource => {
                    let Some(captured) = read_resource(&self.reader, dependency.path(), limit)?
                    else {
                        continue;
                    };
                    resource_digests.push((captured.path.clone(), captured.digest.clone()));
                    resources.push(captured);
                }
            }
        }

        let css_entries = css_digests
            .iter()
            .map(|(path, digest)| (path.as_str(), digest.clone()));
        let resource_entries = resource_digests
            .iter()
            .map(|(path, digest)| (path.as_str(), digest.clone()));
        let css_fingerprint = dependency_fingerprint(DependencyKind::Css, css_entries);
        let resources_fingerprint =
            dependency_fingerprint(DependencyKind::Resource, resource_entries);
        let fingerprints = FingerprintSet::new(
            policy.settings_fingerprint.clone(),
            policy.policy_fingerprint.clone(),
            css_fingerprint,
            resources_fingerprint,
            None,
            None,
            None,
        );

        Ok(AuthoringSnapshot {
            document: request.document.clone(),
            source: request.source.clone(),
            source_markdown: source,
            existing_html,
            shared_css,
            resources,
            fingerprints,
            policy: request.policy.clone(),
        })
    }
}

fn read_exact<R: SourceReadPort>(
    reader: &R,
    path: &str,
    limit: u64,
    field: &'static str,
) -> Result<CapturedInput, H3Error> {
    let read = read_stable(reader, path, field)?;
    if read.bytes().len() as u64 > limit {
        return Err(H3Error::Unavailable {
            capability: "authoring.workspace".to_owned(),
            detail: format!(
                "{field} `{path}` is {} bytes, over the approved {limit} byte limit; it is held, not truncated",
                read.bytes().len()
            ),
        });
    }
    captured(path, read)
}

fn read_optional<R: SourceReadPort>(
    reader: &R,
    path: &str,
    limit: u64,
    field: &'static str,
) -> Result<Option<CapturedInput>, H3Error> {
    match reader.read(path) {
        Ok(read) => {
            if read.bytes().len() as u64 > limit {
                return Err(H3Error::Unavailable {
                    capability: "authoring.workspace".to_owned(),
                    detail: format!(
                        "{field} `{path}` is {} bytes, over the approved {limit} byte limit; it is held, not truncated",
                        read.bytes().len()
                    ),
                });
            }
            Ok(Some(captured(path, read)?))
        }
        Err(SourceReadError::NotFound) => Ok(None),
        Err(error) => Err(read_error(field, path, error)),
    }
}

fn read_resource<R: SourceReadPort>(
    reader: &R,
    path: &str,
    limit: u64,
) -> Result<Option<CapturedResource>, H3Error> {
    match reader.read(path) {
        Ok(read) => {
            if read.bytes().len() as u64 > limit {
                return Err(H3Error::Unavailable {
                    capability: "authoring.workspace".to_owned(),
                    detail: format!(
                        "resource `{path}` is {} bytes, over the approved {limit} byte limit; it is held, not truncated",
                        read.bytes().len()
                    ),
                });
            }
            Ok(Some(CapturedResource {
                path: path.to_owned(),
                bytes: read.bytes().len() as u64,
                digest: ContentDigest::sha256(read.bytes()),
            }))
        }
        Err(SourceReadError::NotFound) => Ok(None),
        Err(error) => Err(read_error("resource", path, error)),
    }
}

fn read_stable<R: SourceReadPort>(
    reader: &R,
    path: &str,
    field: &'static str,
) -> Result<FileRead, H3Error> {
    let read = reader
        .read(path)
        .map_err(|error| read_error(field, path, error))?;
    if !read.is_stable() {
        return Err(H3Error::Unavailable {
            capability: "authoring.workspace".to_owned(),
            detail: format!("{field} `{path}` changed while it was being read"),
        });
    }
    Ok(read)
}

fn read_error(field: &'static str, path: &str, error: SourceReadError) -> H3Error {
    H3Error::Unavailable {
        capability: "authoring.workspace".to_owned(),
        detail: format!("{field} `{path}` is unavailable ({})", error.as_str()),
    }
}

fn captured(path: &str, read: FileRead) -> Result<CapturedInput, H3Error> {
    let text = String::from_utf8(read.bytes().to_vec()).map_err(|_| H3Error::Unavailable {
        capability: "authoring.workspace".to_owned(),
        detail: format!("`{path}` is not valid UTF-8"),
    })?;
    Ok(CapturedInput {
        path: path.to_owned(),
        bytes: read.bytes().len() as u64,
        digest: ContentDigest::sha256(read.bytes()),
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{SourceRevision, SourceSnapshot};
    use crate::observer::{DependencyKind, DependencyPath, FileRead, SourceReadError};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeReader {
        files: BTreeMap<String, Vec<u8>>,
    }

    impl SourceReadPort for FakeReader {
        fn read(&self, path: &str) -> Result<FileRead, SourceReadError> {
            self.files
                .get(path)
                .cloned()
                .map(|bytes| FileRead::new(bytes, true))
                .ok_or(SourceReadError::NotFound)
        }
    }

    fn document() -> DocumentKey {
        DocumentKey::new(herness_core::ProjectId::new(), "docs/sdd/specs/example.md")
            .expect("document")
    }

    fn policy() -> AuthoringPolicy {
        AuthoringPolicy::new(
            ContentDigest::sha256(b"settings"),
            "sdd-html-policy-v1",
            ContentDigest::sha256(b"policy"),
            ContentDigest::sha256(b"pack"),
            ConditionVersion::new(1).expect("version"),
            ConditionDigest::sha256(b"conditions"),
            2 * 1024 * 1024,
            MAX_SHARED_CSS_BYTES,
            MAX_RESOURCE_BYTES,
        )
        .expect("policy")
    }

    #[test]
    fn captures_exact_bytes_and_binds_the_declared_dependencies() {
        let mut reader = FakeReader::default();
        reader.files.insert(
            "docs/sdd/specs/example.md".to_owned(),
            b"# Source\n".to_vec(),
        );
        reader.files.insert(
            "docs/sdd/specs/example.html".to_owned(),
            b"<html></html>".to_vec(),
        );
        reader
            .files
            .insert("assets/shared.css".to_owned(), b"body {}".to_vec());
        reader
            .files
            .insert("assets/logo.png".to_owned(), b"png".to_vec());
        let source = SourceSnapshot::new(
            SourceRevision::new(3).expect("revision"),
            ContentDigest::sha256(b"# Source\n"),
        );
        let deps = vec![
            DependencyPath::new("assets/shared.css", DependencyKind::Css).expect("css"),
            DependencyPath::new("assets/logo.png", DependencyKind::Resource).expect("resource"),
        ];
        let request = WorkspaceCaptureRequest::new(document(), source.clone(), deps, policy())
            .expect("request");
        let snapshot = WorkspaceReader::new(reader)
            .capture(&request)
            .expect("snapshot");
        assert_eq!(snapshot.source(), &source);
        assert_eq!(snapshot.source_markdown().text(), "# Source\n");
        assert_eq!(
            snapshot.source_markdown().digest(),
            &ContentDigest::sha256(b"# Source\n")
        );
        assert_eq!(
            snapshot.existing_html().expect("html").text(),
            "<html></html>"
        );
        assert_eq!(snapshot.shared_css().expect("css").text(), "body {}");
        assert_eq!(snapshot.resources().len(), 1);
        assert!(snapshot.brief().contains("source_markdown"));
        assert!(snapshot.brief().contains("digest"));
        assert!(!snapshot.brief().contains("Work toward"));
    }

    #[test]
    fn source_digest_or_size_mismatch_is_held_not_truncated() {
        let mut reader = FakeReader::default();
        reader
            .files
            .insert("docs/sdd/specs/example.md".to_owned(), b"changed".to_vec());
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(b"original"),
        );
        let request = WorkspaceCaptureRequest::new(document(), source, Vec::new(), policy())
            .expect("request");
        assert!(WorkspaceReader::new(reader).capture(&request).is_err());
    }

    #[test]
    fn over_limit_source_is_held_and_binary_resources_keep_exact_digests() {
        let mut reader = FakeReader::default();
        reader
            .files
            .insert("docs/sdd/specs/example.md".to_owned(), b"12345".to_vec());
        reader
            .files
            .insert("assets/logo.png".to_owned(), vec![0xff, 0x00, 0xfe]);
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(b"12345"),
        );
        let mut small = policy();
        small.source_bytes_limit = 4;
        let request =
            WorkspaceCaptureRequest::new(document(), source.clone(), Vec::new(), small).expect("request");
        assert!(WorkspaceReader::new(reader).capture(&request).is_err());

        let mut reader = FakeReader::default();
        reader
            .files
            .insert("docs/sdd/specs/example.md".to_owned(), b"12345".to_vec());
        reader
            .files
            .insert("assets/logo.png".to_owned(), vec![0xff, 0x00, 0xfe]);
        let deps = vec![DependencyPath::new("assets/logo.png", DependencyKind::Resource)
            .expect("resource")];
        let request =
            WorkspaceCaptureRequest::new(document(), source, deps, policy()).expect("request");
        let snapshot = WorkspaceReader::new(reader)
            .capture(&request)
            .expect("binary resource snapshot");
        assert_eq!(snapshot.resources().len(), 1);
        assert_eq!(snapshot.resources()[0].bytes(), 3);
        assert_eq!(
            snapshot.resources()[0].digest(),
            &ContentDigest::sha256(&[0xff, 0x00, 0xfe])
        );
    }

    #[test]
    fn multiple_css_inputs_are_rejected_instead_of_merged() {
        let deps = vec![
            DependencyPath::new("a.css", DependencyKind::Css).expect("css"),
            DependencyPath::new("b.css", DependencyKind::Css).expect("css"),
        ];
        let source = SourceSnapshot::new(
            SourceRevision::new(1).expect("revision"),
            ContentDigest::sha256(b"x"),
        );
        assert!(WorkspaceCaptureRequest::new(document(), source, deps, policy()).is_err());
    }
}
