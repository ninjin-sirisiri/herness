//! Black-box tests for the native file tools behind the permission gateway.
//!
//! Each test uses a temporary project, a real SQLite store in a temporary
//! application-data root, and the public `ToolGateway` boundary. No engine,
//! Tauri, network, or real credential is involved.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use herness_core::*;
use herness_runtime_tests::fixtures::ProjectFixture;
use herness_store::test_support::{CommitFault, ResultFault};
use herness_store::{Store, StoreConfig};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct Harness {
    _temp: TempDir,
    project_root: PathBuf,
    outside_root: PathBuf,
    config: StoreConfig,
    fixture: ProjectFixture,
    admin: PolicyAdmin,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let project = temp.path().join("project");
        fs::create_dir_all(&project).expect("project directory");
        let project_root = fs::canonicalize(&project).expect("canonical project");
        let outside_root = temp.path().join("outside");
        fs::create_dir_all(&outside_root).expect("outside directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("app data root");
        config
            .ensure_outside_project(&project_root)
            .expect("app data root is outside the project");
        Self {
            _temp: temp,
            project_root,
            outside_root,
            config,
            fixture: ProjectFixture::new(),
            admin: PolicyAdmin::new(),
        }
    }

    fn cwd(&self) -> AbsolutePath {
        AbsolutePath::new(self.project_root.to_string_lossy().into_owned())
            .expect("project root is absolute")
    }

    fn policy(&self) -> PermissionPolicy {
        self.admin.policy().clone()
    }

    fn grant(&self, policy: &PermissionPolicy) -> GrantScope {
        GrantScope::for_run(self.fixture.project_id, policy)
    }

    fn store(&self) -> Store {
        Store::open(self.config.clone()).expect("open store")
    }

    fn executor(&self) -> NativeFileTools<Store> {
        NativeFileTools::new(
            ProjectRoot::new(&self.project_root).expect("project root"),
            self.fixture.agent_id,
            self.fixture.session_id,
            self.store(),
        )
        .expect("file executor")
    }

    fn gateway(&self) -> ToolGateway<NativeFileTools<Store>> {
        ToolGateway::new(self.executor())
    }

    /// Allows every file tool over the whole project.
    fn allow_project_files(&mut self) {
        for tool in [
            ToolName::Read,
            ToolName::Search,
            ToolName::Write,
            ToolName::Edit,
        ] {
            self.admin
                .add_rule(
                    PermissionRule::allow(
                        RuleTarget::FilePath {
                            tool,
                            root: AbsolutePath::new(
                                self.project_root.to_string_lossy().into_owned(),
                            )
                            .expect("absolute root"),
                        },
                        MatchMethod::PathPrefix,
                    )
                    .expect("rule"),
                )
                .expect("add rule");
        }
    }

    fn allow_tool(&mut self, tool: ToolName) {
        self.admin
            .add_rule(
                PermissionRule::allow(RuleTarget::Tool { tool }, MatchMethod::AnyInvocation)
                    .expect("rule"),
            )
            .expect("add rule");
    }

    fn write_op(&self, path: &str, content: &str, rationale: &str) -> FrozenOperation {
        self.freeze(
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new(path).expect("path"),
                content: content.to_owned(),
                rationale: Rationale::new(rationale).expect("rationale"),
            }),
        )
    }

    fn write_op_with_id(
        &self,
        operation: OperationId,
        path: &str,
        content: &str,
        rationale: &str,
    ) -> FrozenOperation {
        self.freeze_with(
            operation,
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new(path).expect("path"),
                content: content.to_owned(),
                rationale: Rationale::new(rationale).expect("rationale"),
            }),
        )
    }

    fn edit_op(
        &self,
        path: &str,
        old_text: &str,
        new_text: &str,
        rationale: &str,
        expected: Option<FileVersion>,
    ) -> FrozenOperation {
        self.freeze(
            ToolName::Edit,
            ToolArguments::Edit(EditArgs {
                path: NonEmptyText::new(path).expect("path"),
                old_text: old_text.to_owned(),
                new_text: new_text.to_owned(),
                rationale: Rationale::new(rationale).expect("rationale"),
                expected_version: expected,
            }),
        )
    }

    fn read_op(&self, path: &str, offset: Option<u64>, limit: Option<u64>) -> FrozenOperation {
        self.freeze(
            ToolName::Read,
            ToolArguments::Read(ReadArgs {
                path: NonEmptyText::new(path).expect("path"),
                offset,
                limit,
            }),
        )
    }

    fn search_op(
        &self,
        query: &str,
        path: Option<&str>,
        glob: Option<&str>,
        max_results: Option<u32>,
    ) -> FrozenOperation {
        self.freeze(
            ToolName::Search,
            ToolArguments::Search(SearchArgs {
                query: NonEmptyText::new(query).expect("query"),
                path: path.map(|value| NonEmptyText::new(value).expect("path")),
                glob: glob.map(|value| NonEmptyText::new(value).expect("glob")),
                max_results,
            }),
        )
    }

    fn freeze(&self, tool: ToolName, arguments: ToolArguments) -> FrozenOperation {
        self.freeze_with(self.fixture.operation_id(), tool, arguments)
    }

    fn freeze_with(
        &self,
        operation: OperationId,
        tool: ToolName,
        arguments: ToolArguments,
    ) -> FrozenOperation {
        FrozenOperation::new(
            operation,
            self.fixture.run_id,
            tool,
            arguments,
            self.cwd(),
            self.admin.policy().version(),
            self.admin.policy().mode(),
        )
        .expect("frozen operation")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project_root.join(relative)
    }
}

fn context() -> EvaluationContext {
    EvaluationContext::new("file tool test", Vec::new())
}

fn execute_through_gateway(
    gateway: &mut ToolGateway<NativeFileTools<Store>>,
    policy: &PermissionPolicy,
    grant: &GrantScope,
    operation: &FrozenOperation,
) -> Result<FileToolOutput, CoreError> {
    let outcome = gateway
        .authorize(policy, grant, operation, &context(), None)
        .expect("authorize");
    let authorization = match outcome {
        PermissionOutcome::Allow { authorization } => authorization,
        other => panic!("expected allow, got {other:?}"),
    };
    gateway
        .execute(policy, operation, &authorization)
        .map_err(|error| match error {
            GatewayError::Executor(error) => error,
            GatewayError::Approval(error) => panic!("unexpected approval error: {error}"),
        })
}

fn expect_allow<E: ToolExecutor>(
    gateway: &mut ToolGateway<E>,
    policy: &PermissionPolicy,
    grant: &GrantScope,
    operation: &FrozenOperation,
) -> Authorization {
    match gateway
        .authorize(policy, grant, operation, &context(), None)
        .expect("authorize")
    {
        PermissionOutcome::Allow { authorization } => authorization,
        other => panic!("expected allow, got {other:?}"),
    }
}

fn expect_file_failure(error: CoreError) -> (ToolName, FileFailure) {
    match error {
        CoreError::FileToolFailed { tool, failure } => (tool, failure),
        other => panic!("expected a file tool failure, got {other:?}"),
    }
}

fn executor_error(error: GatewayError) -> CoreError {
    match error {
        GatewayError::Executor(error) => error,
        GatewayError::Approval(error) => panic!("unexpected approval error: {error}"),
    }
}

fn expect_change(output: FileToolOutput) -> FileChange {
    match output {
        FileToolOutput::Change(change) => *change,
        other => panic!("expected a file change, got {other:?}"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn operation_record(store: &Store, operation: OperationId) -> Option<OperationRecord> {
    store.operation(&operation).expect("read operation")
}

fn events(store: &Store, project: ProjectId) -> Vec<Event> {
    let mut events = store
        .history(HistoryQuery::first(project))
        .expect("history")
        .events()
        .to_vec();
    events.sort_by_key(Event::sequence);
    events
}

fn event_of_kind<'a>(events: &'a [Event], kind: &str) -> Option<&'a Event> {
    events.iter().find(|event| event.kind().as_str() == kind)
}

#[test]
fn write_records_before_and_after_versions_diff_and_audit_correspondence() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let content = "alpha\nbeta\n";
    let operation = harness.write_op("notes.txt", content, "record the note");

    let change = expect_change(
        execute_through_gateway(&mut gateway, &policy, &grant, &operation).expect("write"),
    );
    let absolute = harness.path("notes.txt");
    assert_eq!(fs::read_to_string(&absolute).expect("file"), content);
    assert!(change.created());
    assert_eq!(change.before_version(), None);
    assert_eq!(
        change.after_version().as_str(),
        sha256_hex(content.as_bytes())
    );
    assert!(change.diff().text().contains("+alpha\n"));
    assert!(change.diff().text().contains("+beta\n"));

    let notification = change.notification();
    assert_eq!(notification.kind().as_str(), FILE_CHANGE_EVENT_KIND);
    assert_eq!(notification.operation_id(), Some(operation.operation_id()));
    let payload = notification.payload().as_value();
    assert_eq!(payload["path"], absolute.to_string_lossy().as_ref());
    assert_eq!(payload["tool"], "write");
    assert_eq!(payload["created"], true);
    assert!(payload["beforeVersion"].is_null());
    assert_eq!(
        payload["afterVersion"],
        sha256_hex(content.as_bytes()).as_str()
    );
    assert!(payload["diff"].as_str().unwrap().contains("+alpha\n"));
    assert_eq!(payload["rationale"], "record the note");

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    assert!(
        record.result().is_some(),
        "result must be durable after success"
    );
    assert_eq!(
        record.result().unwrap().outcome(),
        OperationOutcome::Applied
    );
    assert_eq!(record.intent().operation(), &operation);
    let files = record.result().unwrap().evidence().files();
    assert_eq!(files.len(), 1);
    assert_eq!(
        files[0].path().as_str(),
        absolute.to_string_lossy().as_ref()
    );
    assert_eq!(files[0].before_version(), None);
    assert_eq!(
        files[0].after_version().unwrap().as_str(),
        sha256_hex(content.as_bytes())
    );

    let events = events(store, harness.fixture.project_id);
    let intended = event_of_kind(&events, FILE_CHANGE_INTENDED_EVENT_KIND).expect("intent event");
    let applied = event_of_kind(&events, FILE_CHANGE_EVENT_KIND).expect("change event");
    assert!(intended.sequence() < applied.sequence());
    assert_eq!(
        intended.payload().as_value()["afterVersion"],
        sha256_hex(content.as_bytes()).as_str()
    );
    assert_eq!(
        applied.payload().as_value()["created"],
        true,
        "the durable notification corresponds to the applied result"
    );
    assert_eq!(
        store
            .pending_operations(&harness.fixture.project_id)
            .expect("pending"),
        Vec::new()
    );
}

#[test]
fn edit_records_before_and_after_versions_and_created_false() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    fs::write(harness.path("notes.txt"), "alpha\nbeta\ngamma\n").expect("initial file");
    let before = sha256_hex(b"alpha\nbeta\ngamma\n");
    let after = sha256_hex(b"alpha\nBETA\ngamma\n");
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.edit_op(
        "notes.txt",
        "beta",
        "BETA",
        "capitalize beta",
        Some(FileVersion::new(before.clone()).expect("version")),
    );

    let change = expect_change(
        execute_through_gateway(&mut gateway, &policy, &grant, &operation).expect("edit"),
    );
    assert_eq!(
        fs::read_to_string(harness.path("notes.txt")).expect("file"),
        "alpha\nBETA\ngamma\n"
    );
    assert!(!change.created());
    assert_eq!(change.before_version().expect("before").as_str(), before);
    assert_eq!(change.after_version().as_str(), after);
    assert!(change.diff().text().contains("-beta\n"));
    assert!(change.diff().text().contains("+BETA\n"));
    let payload = change.notification().payload().as_value();
    assert_eq!(payload["created"], false);
    assert_eq!(payload["beforeVersion"], before.as_str());
    assert_eq!(payload["afterVersion"], after.as_str());

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("record");
    let result = record.result().expect("result");
    assert_eq!(result.outcome(), OperationOutcome::Applied);
    let observation = &result.evidence().files()[0];
    assert_eq!(
        observation.before_version().expect("before").as_str(),
        before
    );
    assert_eq!(observation.after_version().expect("after").as_str(), after);
}

#[test]
fn whitespace_or_missing_rationale_is_rejected_before_any_file_change() {
    let harness = Harness::new();

    for rationale in ["", "   ", "\t\n"] {
        let payload = serde_json::json!({
            "tool": "write",
            "arguments": {
                "path": "notes.txt",
                "content": "content",
                "rationale": rationale,
            }
        });
        assert!(
            serde_json::from_value::<ToolArguments>(payload).is_err(),
            "rationale {rationale:?} must be rejected"
        );
    }
    let missing = serde_json::json!({
        "tool": "edit",
        "arguments": {
            "path": "notes.txt",
            "oldText": "a",
            "newText": "b",
        }
    });
    assert!(
        serde_json::from_value::<ToolArguments>(missing).is_err(),
        "missing rationale must be rejected"
    );
    assert!(Rationale::new(" \t\n ").is_err());
    assert!(!harness.path("notes.txt").exists());
    assert!(
        harness
            .store()
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .is_empty()
    );
}

#[test]
fn write_is_create_only_and_edit_has_distinct_failure_conditions() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    fs::write(harness.path("existing.txt"), "original\n").expect("existing");
    fs::write(harness.path("multi.txt"), "one\ntwo\none\n").expect("multi");
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();

    let write_existing = harness.write_op("existing.txt", "replacement\n", "replace");
    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_existing)
            .expect_err("create only"),
    );
    assert_eq!(tool, ToolName::Write);
    assert!(matches!(failure, FileFailure::AlreadyExists { .. }));
    assert_eq!(
        fs::read_to_string(harness.path("existing.txt")).expect("file"),
        "original\n"
    );

    let write_directory = harness.write_op("folder", "x", "create");
    fs::create_dir_all(harness.path("folder")).expect("directory");
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_directory)
            .expect_err("directory target"),
    );
    assert!(matches!(failure, FileFailure::AlreadyExists { .. }));

    let write_missing_parent = harness.write_op("missing/new.txt", "x", "create");
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_missing_parent)
            .expect_err("missing parent"),
    );
    assert!(matches!(failure, FileFailure::ParentMissing { .. }));

    let write_file_parent = harness.write_op("existing.txt/new.txt", "x", "create");
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_file_parent)
            .expect_err("file parent"),
    );
    assert!(
        matches!(failure, FileFailure::ParentNotDirectory { .. }),
        "{failure:?}"
    );

    let edit_missing = harness.edit_op("missing.txt", "a", "b", "edit", None);
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &edit_missing)
            .expect_err("missing file"),
    );
    assert!(matches!(failure, FileFailure::NotFound { .. }));

    let edit_not_found = harness.edit_op("multi.txt", "absent", "x", "edit", None);
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &edit_not_found)
            .expect_err("missing text"),
    );
    assert!(matches!(failure, FileFailure::EditTextNotFound { .. }));

    let edit_ambiguous = harness.edit_op("multi.txt", "one", "1", "edit", None);
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &edit_ambiguous)
            .expect_err("ambiguous text"),
    );
    assert!(matches!(
        failure,
        FileFailure::EditTextNotUnique { occurrences: 2, .. }
    ));

    let edit_empty = harness.edit_op("multi.txt", "", "x", "edit", None);
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &edit_empty)
            .expect_err("empty text"),
    );
    assert!(matches!(failure, FileFailure::EditTextEmpty));

    let edit_stale = harness.edit_op(
        "multi.txt",
        "two",
        "TWO",
        "edit",
        Some(FileVersion::new(sha256_hex(b"different")).expect("version")),
    );
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &edit_stale)
            .expect_err("stale version"),
    );
    assert!(matches!(failure, FileFailure::VersionConflict { .. }));

    // None of the failures recorded an intent or changed the files.
    let store = gateway.executor().store();
    assert_eq!(
        fs::read_to_string(harness.path("multi.txt")).expect("file"),
        "one\ntwo\none\n"
    );
    assert!(
        store
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .is_empty()
    );
    assert_eq!(
        fs::read_to_string(harness.path("existing.txt")).expect("file"),
        "original\n"
    );
}

#[test]
fn external_change_prevents_a_stale_edit() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    fs::write(harness.path("notes.txt"), "value = 1\n").expect("initial");
    let observed = FileVersion::new(sha256_hex(b"value = 1\n")).expect("version");
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.edit_op(
        "notes.txt",
        "value = 1",
        "value = 2",
        "update value",
        Some(observed.clone()),
    );

    // Another writer changes the file after the model observed it.
    fs::write(harness.path("notes.txt"), "value = 99\n").expect("external change");

    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &operation).expect_err("stale edit"),
    );
    assert_eq!(tool, ToolName::Edit);
    assert!(matches!(
        failure,
        FileFailure::VersionConflict { expected, actual, .. }
            if expected == observed
                && actual.as_str() == sha256_hex(b"value = 99\n")
    ));
    assert_eq!(
        fs::read_to_string(harness.path("notes.txt")).expect("file"),
        "value = 99\n"
    );
    assert!(
        operation_record(gateway.executor().store(), operation.operation_id()).is_none(),
        "a capture-time conflict records no intent"
    );
}

#[test]
fn concurrent_edits_serialize_and_the_loser_sees_a_version_conflict() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    fs::write(harness.path("notes.txt"), "value = 1\n").expect("initial");
    let version = FileVersion::new(sha256_hex(b"value = 1\n")).expect("version");
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let first = harness.edit_op(
        "notes.txt",
        "value = 1",
        "value = 2",
        "first edit",
        Some(version.clone()),
    );
    let second = harness.edit_op(
        "notes.txt",
        "value = 1",
        "value = 3",
        "second edit",
        Some(version),
    );

    let config = harness.config.clone();
    let project = harness.project_root.clone();
    let fixture = harness.fixture;
    let locks = Arc::new(FileLockRegistry::new());
    let barrier = Arc::new(Barrier::new(2));

    let run = |operation: FrozenOperation, locks: Arc<FileLockRegistry>| {
        let config = config.clone();
        let project = project.clone();
        let policy = policy.clone();
        let grant = grant.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let store = Store::open(config).expect("store");
            let executor = NativeFileTools::with_lock_registry(
                ProjectRoot::new(&project).expect("root"),
                fixture.agent_id,
                fixture.session_id,
                store,
                locks,
            )
            .expect("executor");
            let mut gateway = ToolGateway::new(executor);
            barrier.wait();
            execute_through_gateway(&mut gateway, &policy, &grant, &operation)
        })
    };

    let first = run(first, Arc::clone(&locks));
    let second = run(second, locks);
    let first = first.join().expect("first thread");
    let second = second.join().expect("second thread");

    let successes = [&first, &second]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    let conflicts = [&first, &second]
        .iter()
        .filter(|result| {
            matches!(
                result,
                Err(CoreError::FileToolFailed {
                    failure: FileFailure::VersionConflict { .. },
                    ..
                })
            )
        })
        .count();
    assert_eq!(successes, 1, "exactly one concurrent edit may apply");
    assert_eq!(
        conflicts, 1,
        "the other edit must observe a version conflict"
    );

    let content = fs::read_to_string(harness.path("notes.txt")).expect("file");
    assert!(
        content == "value = 2\n" || content == "value = 3\n",
        "the file must contain exactly one winning edit, found {content:?}"
    );

    let store = harness.store();
    let pending = store
        .pending_operations(&harness.fixture.project_id)
        .expect("pending");
    assert!(
        pending.is_empty(),
        "the losing capture-time conflict records no intent"
    );
}

#[cfg(unix)]
#[test]
fn symlink_escape_parent_symlink_and_parent_component_escape_are_rejected() {
    use std::os::unix::fs::symlink;

    let mut harness = Harness::new();
    for tool in [
        ToolName::Read,
        ToolName::Search,
        ToolName::Write,
        ToolName::Edit,
    ] {
        harness.allow_tool(tool);
    }
    fs::write(harness.path("inside.txt"), "inside needle\n").expect("inside");
    fs::write(harness.outside_dir().join("secret.txt"), "outside secret\n").expect("outside");
    symlink(
        harness.outside_dir().join("secret.txt"),
        harness.path("link.txt"),
    )
    .expect("file symlink");
    symlink(harness.outside_dir(), harness.path("escape")).expect("directory symlink");
    symlink(harness.path("inside.txt"), harness.path("inside-link.txt")).expect("inside symlink");

    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();

    let read_link = harness.read_op("link.txt", None, None);
    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &read_link)
            .expect_err("file symlink read"),
    );
    assert_eq!(tool, ToolName::Read);
    assert!(matches!(failure, FileFailure::SymlinkNotAllowed { .. }));

    let read_inside_link = harness.read_op("inside-link.txt", None, None);
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &read_inside_link)
            .expect_err("inside symlink read"),
    );
    assert!(matches!(failure, FileFailure::SymlinkNotAllowed { .. }));

    let write_link = harness.write_op("link.txt", "overwritten\n", "write through link");
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_link)
            .expect_err("file symlink write"),
    );
    assert!(matches!(failure, FileFailure::SymlinkNotAllowed { .. }));

    let write_parent_symlink =
        harness.write_op("escape/new.txt", "created\n", "create through parent link");
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_parent_symlink)
            .expect_err("parent symlink"),
    );
    assert!(matches!(failure, FileFailure::SymlinkNotAllowed { .. }));

    let write_escape = harness.write_op("../escaped.txt", "created\n", "escape the root");
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &write_escape)
            .expect_err(".. escape"),
    );
    assert!(matches!(failure, FileFailure::PathOutsideProject { .. }));

    let read_outside = harness.read_op(
        &harness.outside_dir().join("secret.txt").to_string_lossy(),
        None,
        None,
    );
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &read_outside)
            .expect_err("read outside"),
    );
    assert!(matches!(failure, FileFailure::PathOutsideProject { .. }));

    let search_outside = harness.search_op(
        "secret",
        Some(&harness.outside_dir().to_string_lossy()),
        None,
        None,
    );
    let (_, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &search_outside)
            .expect_err("search outside"),
    );
    assert!(matches!(failure, FileFailure::PathOutsideProject { .. }));

    // A search over the project skips the escaping symlink and finds only the
    // regular in-project file.
    let search_inside = harness.search_op("needle", None, None, None);
    let output = execute_through_gateway(&mut gateway, &policy, &grant, &search_inside)
        .expect("search inside");
    let FileToolOutput::Search(result) = output else {
        panic!("expected search output");
    };
    assert_eq!(result.matches().len(), 1);
    assert_eq!(
        result.matches()[0].path().as_str(),
        harness.path("inside.txt").to_string_lossy().as_ref()
    );

    assert_eq!(
        fs::read_to_string(harness.outside_dir().join("secret.txt")).expect("outside file"),
        "outside secret\n"
    );
    assert_eq!(
        fs::read_to_string(harness.path("link.txt")).expect("symlink content"),
        "outside secret\n"
    );
    assert!(!harness.outside_dir().join("new.txt").exists());
    assert!(
        !harness
            .project_root
            .parent()
            .expect("project parent")
            .join("escaped.txt")
            .exists()
    );
}

impl Harness {
    fn outside_dir(&self) -> PathBuf {
        fs::canonicalize(&self.outside_root).expect("canonical outside")
    }
}

#[test]
fn read_and_search_go_through_the_gateway_and_stay_inside_the_root() {
    let mut harness = Harness::new();
    harness.allow_tool(ToolName::Read);
    harness.allow_tool(ToolName::Search);
    fs::create_dir_all(harness.path("src")).expect("src dir");
    fs::write(
        harness.path("src/main.rs"),
        "needle one\nsecond\nthird\nfourth\n",
    )
    .expect("main");
    fs::write(harness.path("src/other.txt"), "needle two\n").expect("other");
    fs::write(harness.path("src/binary.bin"), [0xff, 0xfe, 0x00]).expect("binary");
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();

    let read = harness.read_op("src/main.rs", Some(2), Some(2));
    let output = execute_through_gateway(&mut gateway, &policy, &grant, &read).expect("read");
    let FileToolOutput::Read(result) = output else {
        panic!("expected read output");
    };
    assert_eq!(result.text(), "second\nthird");
    assert_eq!(result.start_line(), 2);
    assert_eq!(result.end_line(), Some(3));
    assert_eq!(result.total_lines(), 4);
    assert!(result.truncated());
    assert_eq!(
        result.version().as_str(),
        sha256_hex(b"needle one\nsecond\nthird\nfourth\n")
    );

    let read_past_end = harness.read_op("src/main.rs", Some(99), Some(10));
    let output =
        execute_through_gateway(&mut gateway, &policy, &grant, &read_past_end).expect("read past");
    let FileToolOutput::Read(result) = output else {
        panic!("expected read output");
    };
    assert_eq!(result.text(), "");
    assert_eq!(result.end_line(), None);
    assert!(!result.truncated());

    // Search defaults are deterministic and the glob filters by path.
    let search = harness.search_op("needle", None, Some("**/*.rs"), Some(10));
    let output = execute_through_gateway(&mut gateway, &policy, &grant, &search).expect("search");
    let FileToolOutput::Search(result) = output else {
        panic!("expected search output");
    };
    assert_eq!(result.matches().len(), 1);
    let found = &result.matches()[0];
    assert_eq!(
        found.path().as_str(),
        harness.path("src/main.rs").to_string_lossy().as_ref()
    );
    assert_eq!(found.line(), 1);
    assert_eq!(found.column(), 1);
    assert!(found.preview().contains("needle one"));
    assert!(!result.truncated());

    let search_literal = harness.search_op("second", Some("src"), None, Some(1));
    let output =
        execute_through_gateway(&mut gateway, &policy, &grant, &search_literal).expect("search");
    let FileToolOutput::Search(result) = output else {
        panic!("expected search output");
    };
    assert_eq!(result.matches().len(), 1);
    assert_eq!(result.matches()[0].line(), 2);
    assert_eq!(result.matches()[0].column(), 1);

    // The same tool-wide permission allows these operations to reach the
    // executor, which then rejects the out-of-root target itself.
    let read_outside = harness.read_op(
        &harness.outside_root.join("outside.txt").to_string_lossy(),
        None,
        None,
    );
    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &read_outside)
            .expect_err("read outside"),
    );
    assert_eq!(tool, ToolName::Read);
    assert!(matches!(failure, FileFailure::PathOutsideProject { .. }));

    let search_outside = harness.search_op(
        "anything",
        Some(&harness.outside_root.to_string_lossy()),
        None,
        None,
    );
    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &search_outside)
            .expect_err("search outside"),
    );
    assert_eq!(tool, ToolName::Search);
    assert!(matches!(failure, FileFailure::PathOutsideProject { .. }));
}

#[test]
fn post_write_result_fault_leaves_intent_without_result_for_reconciliation() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.write_op("notes.txt", "written\n", "record");
    gateway
        .executor_mut()
        .store_mut()
        .set_result_fault(Some(ResultFault::BeforeUpdate));

    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &operation)
            .expect_err("result persistence fault"),
    );
    assert_eq!(tool, ToolName::Write);
    assert!(matches!(failure, FileFailure::Unverifiable { .. }));
    assert_eq!(
        fs::read_to_string(harness.path("notes.txt")).expect("file keeps content"),
        "written\n"
    );

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("intent is visible");
    assert!(record.result().is_none(), "the result must be absent");
    assert_eq!(record.intent().operation(), &operation);
    assert_eq!(
        store
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .iter()
            .map(|intent| intent.operation().operation_id())
            .collect::<Vec<_>>(),
        vec![operation.operation_id()]
    );
    let history = events(store, harness.fixture.project_id);
    assert!(event_of_kind(&history, FILE_CHANGE_INTENDED_EVENT_KIND).is_some());
    assert!(event_of_kind(&history, FILE_CHANGE_EVENT_KIND).is_none());

    // A second connection sees exactly the same durable facts.
    let other = harness.store();
    let record = operation_record(&other, operation.operation_id()).expect("other sees intent");
    assert!(record.result().is_none());
    assert_eq!(
        other
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .len(),
        1
    );
    assert_eq!(
        other
            .unresolved_operations(&harness.fixture.project_id)
            .expect("unresolved")
            .len(),
        1
    );
}

#[test]
fn pre_write_persistence_fault_leaves_the_file_untouched() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.write_op("notes.txt", "content\n", "record");
    gateway
        .executor_mut()
        .store_mut()
        .set_commit_fault(Some(CommitFault::BeforeCommit));

    let (tool, failure) = expect_file_failure(
        execute_through_gateway(&mut gateway, &policy, &grant, &operation)
            .expect_err("intent commit fault"),
    );
    assert_eq!(tool, ToolName::Write);
    assert!(matches!(failure, FileFailure::NotExecutable { .. }));
    assert!(!harness.path("notes.txt").exists());
    let store = gateway.executor().store();
    assert!(operation_record(store, operation.operation_id()).is_none());
    assert!(events(store, harness.fixture.project_id).is_empty());

    // The rolled-back operation id can be used again by a fresh gateway.
    let mut retry = harness.gateway();
    let output = execute_through_gateway(&mut retry, &policy, &grant, &operation).expect("retry");
    let change = expect_change(output);
    assert!(change.created());
    assert_eq!(
        fs::read_to_string(harness.path("notes.txt")).expect("file"),
        "content\n"
    );
}

#[test]
fn duplicate_operation_id_applies_the_write_once() {
    let mut harness = Harness::new();
    harness.allow_project_files();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let operation = harness.write_op("notes.txt", "first\n", "record");
    let mut first = harness.gateway();
    expect_change(
        execute_through_gateway(&mut first, &policy, &grant, &operation).expect("first write"),
    );
    assert_eq!(
        fs::read_to_string(harness.path("notes.txt")).expect("file"),
        "first\n"
    );

    // Same operation id, different final arguments: the store must reject it
    // before any side effect, even with a fresh permission ledger.
    let duplicate = harness.write_op_with_id(
        operation.operation_id(),
        "notes.txt",
        "second\n",
        "duplicate",
    );
    let mut second = harness.gateway();
    let authorization = expect_allow(&mut second, &policy, &grant, &duplicate);
    let error = second
        .execute(&policy, &duplicate, &authorization)
        .expect_err("duplicate operation id");
    assert_eq!(
        executor_error(error),
        CoreError::DuplicateOperation {
            operation: operation.operation_id()
        }
    );
    assert_eq!(
        fs::read_to_string(harness.path("notes.txt")).expect("file"),
        "first\n",
        "the duplicate must not overwrite the first application"
    );

    let store = second.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("record");
    assert_eq!(record.intent().operation(), &operation);
    assert_eq!(
        record.result().expect("result").outcome(),
        OperationOutcome::Applied
    );
}

#[test]
fn a_read_grant_is_not_a_write_grant_for_the_sdd_pack() {
    let mut harness = Harness::new();
    let pack = harness.outside_root.join("sdd");
    fs::create_dir_all(&pack).expect("pack");
    let pack_file = pack.join("notes.md");
    fs::write(&pack_file, "pack content\n").expect("pack file");
    let pack_root = AbsolutePath::new(pack.to_string_lossy().into_owned()).expect("pack root");
    harness
        .admin
        .add_rule(
            PermissionRule::allow(
                RuleTarget::FilePath {
                    tool: ToolName::Read,
                    root: pack_root,
                },
                MatchMethod::PathPrefix,
            )
            .expect("rule"),
        )
        .expect("read allow");

    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let path = pack_file.to_string_lossy().into_owned();
    let read = harness.read_op(&path, None, None);
    let write = harness.write_op(&path, "overwritten\n", "write pack");

    // The read rule matches the read operation, but not the write operation.
    let read_authorization = expect_allow(&mut gateway, &policy, &grant, &read);
    assert!(grant.permits(&read));
    assert!(grant.permits(&write), "the run ceiling covers both tools");
    let outcome = gateway
        .authorize(&policy, &grant, &write, &context(), None)
        .expect("authorize write");
    let request = match outcome {
        PermissionOutcome::AwaitingApproval { request } => request,
        other => panic!("expected the write to wait for a human, got {other:?}"),
    };
    assert_eq!(request.reason(), &HumanWaitReason::NoMatchingAllowRule);

    // Even a human approval cannot escape the executor's project root.
    let approval = gateway
        .approve(&policy, &write, harness.fixture.project_id)
        .expect("approve");
    let (tool, failure) = expect_file_failure(executor_error(
        gateway
            .execute(&policy, &write, &approval)
            .expect_err("write outside project root"),
    ));
    assert_eq!(tool, ToolName::Write);
    assert!(matches!(failure, FileFailure::PathOutsideProject { .. }));
    assert_eq!(
        fs::read_to_string(&pack_file).expect("pack file unchanged"),
        "pack content\n"
    );

    // The read authorization is independent and was not consumed by the write.
    let _ = read_authorization;
}

// ---------------------------------------------------------------------------
// Candidate-only artifact tools
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TestArtifactState {
    artifacts: BTreeMap<ArtifactSlot, ArtifactSnapshot>,
    writes: usize,
    intent_seen_before_write: bool,
}

struct TestArtifactPort {
    handle: ArtifactHandle,
    project: ProjectId,
    inspect_store: Option<Store>,
    state: Arc<Mutex<TestArtifactState>>,
}

impl std::fmt::Debug for TestArtifactPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestArtifactPort")
            .field("handle", &self.handle)
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl TestArtifactPort {
    fn new(
        handle: ArtifactHandle,
        project: ProjectId,
        inspect_store: Option<Store>,
    ) -> (Self, Arc<Mutex<TestArtifactState>>) {
        let state = Arc::new(Mutex::new(TestArtifactState::default()));
        (
            Self {
                handle,
                project,
                inspect_store,
                state: Arc::clone(&state),
            },
            state,
        )
    }

    fn seed(&mut self, artifact: ArtifactSlot, content: &str) {
        self.state.lock().expect("state").artifacts.insert(
            artifact,
            ArtifactSnapshot::new(
                artifact,
                hash_bytes(content.as_bytes()),
                content.to_owned(),
            ),
        );
    }
}

impl ArtifactPort for TestArtifactPort {
    fn read_artifact(
        &mut self,
        handle: &ArtifactHandle,
        artifact: ArtifactSlot,
    ) -> Result<Option<ArtifactSnapshot>, ArtifactFailure> {
        if handle != &self.handle {
            return Err(ArtifactFailure::StaleHandle {
                expected_generation: self.handle.generation(),
                found_generation: handle.generation(),
            });
        }
        Ok(self
            .state
            .lock()
            .expect("state")
            .artifacts
            .get(&artifact)
            .cloned())
    }

    fn write_artifact(
        &mut self,
        handle: &ArtifactHandle,
        artifact: ArtifactSlot,
        content: &str,
        expected_version: Option<&FileVersion>,
    ) -> Result<ArtifactSnapshot, ArtifactFailure> {
        if handle != &self.handle {
            return Err(ArtifactFailure::StaleHandle {
                expected_generation: self.handle.generation(),
                found_generation: handle.generation(),
            });
        }
        if !artifact.is_candidate() {
            return Err(ArtifactFailure::NotCandidateTarget { artifact });
        }
        let mut state = self.state.lock().expect("state");
        let current = state.artifacts.get(&artifact).cloned();
        if expected_version != current.as_ref().map(ArtifactSnapshot::version) {
            return Err(ArtifactFailure::VersionConflict {
                artifact,
                expected: expected_version.cloned().unwrap_or_else(|| {
                    FileVersion::new("absent").expect("placeholder version")
                }),
                actual: current
                    .as_ref()
                    .map(|snapshot| snapshot.version().clone())
                    .unwrap_or_else(|| FileVersion::new("absent").expect("placeholder version")),
            });
        }
        if let Some(store) = &self.inspect_store {
            let pending = store
                .pending_operations(&self.project)
                .expect("pending operations");
            let intended = store
                .history(HistoryQuery::first(self.project))
                .expect("history")
                .events()
                .iter()
                .any(|event| event.kind().as_str() == ARTIFACT_CHANGE_INTENDED_EVENT_KIND);
            state.intent_seen_before_write = !pending.is_empty() && intended;
        }
        let snapshot = ArtifactSnapshot::new(
            artifact,
            hash_bytes(content.as_bytes()),
            content.to_owned(),
        );
        state.artifacts.insert(artifact, snapshot.clone());
        state.writes += 1;
        Ok(snapshot)
    }
}

fn allow_candidate_tools(harness: &mut Harness) {
    for tool in [
        ToolName::CandidateRead,
        ToolName::CandidateWrite,
        ToolName::CandidateEdit,
    ] {
        harness.allow_tool(tool);
    }
}

fn candidate_grant(harness: &Harness, policy: &PermissionPolicy) -> GrantScope {
    GrantScope::for_candidate_run(harness.fixture.project_id, policy)
}

fn candidate_write_op(
    harness: &Harness,
    handle: &ArtifactHandle,
    artifact: ArtifactSlot,
    content: &str,
    rationale: &str,
) -> FrozenOperation {
    harness.freeze(
        ToolName::CandidateWrite,
        ToolArguments::CandidateWrite(CandidateWriteArgs {
            handle: handle.clone(),
            artifact,
            content: content.to_owned(),
            rationale: Rationale::new(rationale).expect("rationale"),
        }),
    )
}

fn candidate_edit_op(
    harness: &Harness,
    handle: &ArtifactHandle,
    artifact: ArtifactSlot,
    old_text: &str,
    new_text: &str,
    rationale: &str,
    expected_version: Option<FileVersion>,
) -> FrozenOperation {
    harness.freeze(
        ToolName::CandidateEdit,
        ToolArguments::CandidateEdit(CandidateEditArgs {
            handle: handle.clone(),
            artifact,
            old_text: old_text.to_owned(),
            new_text: new_text.to_owned(),
            rationale: Rationale::new(rationale).expect("rationale"),
            expected_version,
        }),
    )
}

fn candidate_read_op(
    harness: &Harness,
    handle: &ArtifactHandle,
    artifact: ArtifactSlot,
) -> FrozenOperation {
    harness.freeze(
        ToolName::CandidateRead,
        ToolArguments::CandidateRead(CandidateReadArgs {
            handle: handle.clone(),
            artifact,
        }),
    )
}

fn expect_artifact_failure(error: CoreError) -> (ToolName, ArtifactFailure) {
    match error {
        CoreError::ArtifactToolFailed { tool, failure } => (tool, failure),
        other => panic!("expected a candidate artifact failure, got {other:?}"),
    }
}

#[test]
fn candidate_write_and_edit_persist_intent_before_the_host_artifact_change() {
    let mut harness = Harness::new();
    allow_candidate_tools(&mut harness);
    let policy = harness.policy();
    let grant = candidate_grant(&harness, &policy);
    let handle = ArtifactHandle::new(
        harness.fixture.project_id,
        "job-1",
        2,
        "capability-token",
    )
    .expect("handle");
    let (port, state) =
        TestArtifactPort::new(handle.clone(), harness.fixture.project_id, Some(harness.store()));
    let mut gateway = ToolGateway::new(
        CandidateArtifactTools::new(
            harness.store(),
            harness.fixture.agent_id,
            harness.fixture.session_id,
            handle.clone(),
            port,
        )
        .expect("candidate executor"),
    );

    let write = candidate_write_op(
        &harness,
        &handle,
        ArtifactSlot::CandidateHtml,
        "<html><body>v1</body></html>",
        "author the first candidate",
    );
    let authorization = expect_allow(&mut gateway, &policy, &grant, &write);
    let output = gateway
        .execute(&policy, &write, &authorization)
        .expect("candidate write");
    let change = match output {
        CandidateToolOutput::Change(change) => *change,
        other => panic!("expected a candidate change, got {other:?}"),
    };
    assert!(change.created());
    assert_eq!(change.artifact(), ArtifactSlot::CandidateHtml);
    assert_eq!(
        state
            .lock()
            .expect("state")
            .artifacts
            .get(&ArtifactSlot::CandidateHtml)
            .expect("candidate")
            .content(),
        "<html><body>v1</body></html>"
    );
    assert!(
        state.lock().expect("state").intent_seen_before_write,
        "the intent and intended event must be durable before the host write"
    );

    let stored_events = events(gateway.executor().store(), harness.fixture.project_id);
    let intended =
        event_of_kind(&stored_events, ARTIFACT_CHANGE_INTENDED_EVENT_KIND).expect("intended");
    assert_eq!(
        intended.payload().as_value()["rationale"],
        "author the first candidate"
    );
    assert_eq!(intended.payload().as_value()["artifact"], "candidate_html");
    assert!(event_of_kind(&stored_events, ARTIFACT_CHANGE_EVENT_KIND).is_some());
    let record = operation_record(gateway.executor().store(), write.operation_id()).expect("record");
    assert_eq!(
        record.result().expect("result").outcome(),
        OperationOutcome::Applied
    );
    assert!(
        gateway
            .executor()
            .store()
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .is_empty()
    );

    let edit = candidate_edit_op(
        &harness,
        &handle,
        ArtifactSlot::CandidateHtml,
        "v1",
        "v2",
        "revise the candidate",
        Some(change.after_version().clone()),
    );
    let authorization = expect_allow(&mut gateway, &policy, &grant, &edit);
    let output = gateway
        .execute(&policy, &edit, &authorization)
        .expect("candidate edit");
    let changed = match output {
        CandidateToolOutput::Change(change) => *change,
        other => panic!("expected a candidate change, got {other:?}"),
    };
    assert!(!changed.created());
    assert_eq!(
        changed.before_version().expect("before"),
        change.after_version()
    );
    assert_eq!(
        state
            .lock()
            .expect("state")
            .artifacts
            .get(&ArtifactSlot::CandidateHtml)
            .expect("candidate")
            .content(),
        "<html><body>v2</body></html>"
    );
    let stored_events = events(gateway.executor().store(), harness.fixture.project_id);
    assert!(stored_events.iter().filter(|event| {
        event.kind().as_str() == ARTIFACT_CHANGE_EVENT_KIND
    }).count() >= 2);
    assert!(stored_events.iter().any(|event| {
        event.kind().as_str() == ARTIFACT_CHANGE_EVENT_KIND
            && event.payload().as_value()["rationale"] == "revise the candidate"
    }));
}

#[test]
fn candidate_read_returns_immutable_snapshots_and_current_candidates() {
    let mut harness = Harness::new();
    allow_candidate_tools(&mut harness);
    let policy = harness.policy();
    let grant = candidate_grant(&harness, &policy);
    let handle = ArtifactHandle::new(
        harness.fixture.project_id,
        "job-1",
        2,
        "capability-token",
    )
    .expect("handle");
    let (mut port, state) =
        TestArtifactPort::new(handle.clone(), harness.fixture.project_id, None);
    port.seed(ArtifactSlot::SourceMarkdown, "# Source\n");
    port.seed(ArtifactSlot::ExistingHtml, "<html>old</html>");
    let mut gateway = ToolGateway::new(
        CandidateArtifactTools::new(
            harness.store(),
            harness.fixture.agent_id,
            harness.fixture.session_id,
            handle.clone(),
            port,
        )
        .expect("candidate executor"),
    );

    let read = candidate_read_op(&harness, &handle, ArtifactSlot::SourceMarkdown);
    let authorization = expect_allow(&mut gateway, &policy, &grant, &read);
    let output = gateway
        .execute(&policy, &read, &authorization)
        .expect("snapshot read");
    let CandidateToolOutput::Read(read_output) = output else {
        panic!("expected a candidate read");
    };
    assert_eq!(read_output.artifact(), ArtifactSlot::SourceMarkdown);
    assert_eq!(read_output.content(), "# Source\n");
    assert_eq!(state.lock().expect("state").writes, 0);

    let missing = candidate_read_op(&harness, &handle, ArtifactSlot::CandidateHtml);
    let authorization = expect_allow(&mut gateway, &policy, &grant, &missing);
    let error = gateway
        .execute(&policy, &missing, &authorization)
        .expect_err("missing candidate");
    let (tool, failure) = expect_artifact_failure(executor_error(error));
    assert_eq!(tool, ToolName::CandidateRead);
    assert_eq!(
        failure,
        ArtifactFailure::NotFound {
            artifact: ArtifactSlot::CandidateHtml
        }
    );
}

#[test]
fn candidate_write_and_edit_reject_formal_or_snapshot_targets_at_schema() {
    let handle = ArtifactHandle::new(ProjectId::new(), "job", 1, "token").expect("handle");
    for artifact in [
        ArtifactSlot::SourceMarkdown,
        ArtifactSlot::ExistingHtml,
        ArtifactSlot::SharedCss,
    ] {
        let json = serde_json::json!({
            "tool": "candidate_write",
            "arguments": {
                "handle": &handle,
                "artifact": &artifact,
                "content": "x",
                "rationale": "must not be accepted"
            }
        });
        let error = serde_json::from_value::<ToolArguments>(json)
            .expect_err("formal target must not deserialize");
        assert!(
            error.to_string().contains("candidate_html"),
            "unexpected error: {error}"
        );

        let project = handle.project_id();
        let operation = FrozenOperation::new(
            OperationId::new(project),
            RunId::new(project),
            ToolName::CandidateWrite,
            ToolArguments::CandidateWrite(CandidateWriteArgs {
                handle: handle.clone(),
                artifact,
                content: "x".to_owned(),
                rationale: Rationale::new("must not be accepted").expect("rationale"),
            }),
            AbsolutePath::new("/tmp/project").expect("absolute"),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        );
        assert!(operation.is_err(), "formal target must not freeze");
    }

    let edit_json = serde_json::json!({
        "tool": "candidate_edit",
        "arguments": {
            "handle": &handle,
            "artifact": "shared_css",
            "oldText": "a",
            "newText": "b",
            "rationale": "must not be accepted"
        }
    });
    assert!(serde_json::from_value::<ToolArguments>(edit_json).is_err());
}

#[test]
fn candidate_empty_rationale_is_rejected_before_any_side_effect() {
    let handle = ArtifactHandle::new(ProjectId::new(), "job", 1, "token").expect("handle");
    for rationale in ["", "   ", "\n\t"] {
        let json = serde_json::json!({
            "tool": "candidate_write",
            "arguments": {
                "handle": &handle,
                "artifact": "candidate_html",
                "content": "<html></html>",
                "rationale": rationale
            }
        });
        let error =
            serde_json::from_value::<ToolArguments>(json).expect_err("empty rationale must fail");
        assert!(
            error.to_string().contains("invalid rationale"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn candidate_executor_rejects_stale_handles_other_projects_and_shell_before_persistence() {
    let mut harness = Harness::new();
    allow_candidate_tools(&mut harness);
    harness.allow_tool(ToolName::Bash);
    let policy = harness.policy();
    let current = ArtifactHandle::new(
        harness.fixture.project_id,
        "job-1",
        2,
        "current-token",
    )
    .expect("current handle");
    let (port, state) =
        TestArtifactPort::new(current.clone(), harness.fixture.project_id, Some(harness.store()));
    let mut gateway = ToolGateway::new(
        CandidateArtifactTools::new(
            harness.store(),
            harness.fixture.agent_id,
            harness.fixture.session_id,
            current.clone(),
            port,
        )
        .expect("candidate executor"),
    );

    let stale = ArtifactHandle::new(
        harness.fixture.project_id,
        "job-1",
        1,
        "stale-token",
    )
    .expect("stale handle");
    let stale_write = candidate_write_op(
        &harness,
        &stale,
        ArtifactSlot::CandidateHtml,
        "<html>stale</html>",
        "stale generation",
    );
    let authorization = expect_allow(
        &mut gateway,
        &policy,
        &candidate_grant(&harness, &policy),
        &stale_write,
    );
    let error = gateway
        .execute(&policy, &stale_write, &authorization)
        .expect_err("stale handle");
    let (tool, failure) = expect_artifact_failure(executor_error(error));
    assert_eq!(tool, ToolName::CandidateWrite);
    assert_eq!(
        failure,
        ArtifactFailure::StaleHandle {
            expected_generation: 2,
            found_generation: 1
        }
    );
    assert_eq!(state.lock().expect("state").writes, 0);

    let other_project = ProjectFixture::new();
    let foreign = ArtifactHandle::new(other_project.project_id, "job-1", 2, "foreign-token")
        .expect("foreign handle");
    let foreign_write = candidate_write_op(
        &harness,
        &foreign,
        ArtifactSlot::CandidateHtml,
        "<html>foreign</html>",
        "foreign project",
    );
    let authorization = expect_allow(
        &mut gateway,
        &policy,
        &candidate_grant(&harness, &policy),
        &foreign_write,
    );
    let error = gateway
        .execute(&policy, &foreign_write, &authorization)
        .expect_err("foreign project");
    assert!(matches!(
        executor_error(error),
        CoreError::CrossProjectReference {
            id_kind: IdKind::Project,
            ..
        }
    ));

    let bash = harness.freeze(
        ToolName::Bash,
        ToolArguments::Bash(BashArgs {
            command: NonEmptyText::new("printf 'shell' > formal.html").expect("command"),
            purpose: Purpose::new("forbidden candidate shell").expect("purpose"),
            timeout_ms: None,
        }),
    );
    let shell_grant = GrantScope::new(
        harness.fixture.project_id,
        vec![
            PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Bash,
                },
                MatchMethod::AnyInvocation,
            )
            .expect("bash rule"),
        ],
        policy.mode(),
        policy.version(),
    )
    .expect("shell grant");
    let authorization = expect_allow(&mut gateway, &policy, &shell_grant, &bash);
    let error = gateway
        .execute(&policy, &bash, &authorization)
        .expect_err("shell in candidate context");
    let (tool, failure) = expect_artifact_failure(executor_error(error));
    assert_eq!(tool, ToolName::Bash);
    assert_eq!(
        failure,
        ArtifactFailure::ToolNotAllowed {
            tool: ToolName::Bash
        }
    );
    assert_eq!(state.lock().expect("state").writes, 0);
    assert!(!harness.path("formal.html").exists());

    let events = events(gateway.executor().store(), harness.fixture.project_id);
    assert!(!events.iter().any(|event| {
        event.kind().as_str() == ARTIFACT_CHANGE_EVENT_KIND
            || event.kind().as_str() == ARTIFACT_CHANGE_INTENDED_EVENT_KIND
    }));
    assert!(
        gateway
            .executor()
            .store()
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .is_empty()
    );
}

#[test]
fn candidate_edit_rejects_version_conflicts_and_non_unique_text_before_intent() {
    let mut harness = Harness::new();
    allow_candidate_tools(&mut harness);
    let policy = harness.policy();
    let grant = candidate_grant(&harness, &policy);
    let handle = ArtifactHandle::new(
        harness.fixture.project_id,
        "job-1",
        2,
        "capability-token",
    )
    .expect("handle");
    let (mut port, state) =
        TestArtifactPort::new(handle.clone(), harness.fixture.project_id, Some(harness.store()));
    port.seed(ArtifactSlot::CandidateHtml, "<html>same same</html>");
    let mut gateway = ToolGateway::new(
        CandidateArtifactTools::new(
            harness.store(),
            harness.fixture.agent_id,
            harness.fixture.session_id,
            handle.clone(),
            port,
        )
        .expect("candidate executor"),
    );

    let stale_version = candidate_edit_op(
        &harness,
        &handle,
        ArtifactSlot::CandidateHtml,
        "same",
        "different",
        "version conflict",
        Some(FileVersion::new("0000").expect("version")),
    );
    let authorization = expect_allow(&mut gateway, &policy, &grant, &stale_version);
    let error = gateway
        .execute(&policy, &stale_version, &authorization)
        .expect_err("version conflict");
    let (_, failure) = expect_artifact_failure(executor_error(error));
    assert!(matches!(
        failure,
        ArtifactFailure::VersionConflict {
            artifact: ArtifactSlot::CandidateHtml,
            ..
        }
    ));

    let non_unique = candidate_edit_op(
        &harness,
        &handle,
        ArtifactSlot::CandidateHtml,
        "same",
        "different",
        "non-unique text",
        None,
    );
    let authorization = expect_allow(&mut gateway, &policy, &grant, &non_unique);
    let error = gateway
        .execute(&policy, &non_unique, &authorization)
        .expect_err("non-unique old text");
    let (_, failure) = expect_artifact_failure(executor_error(error));
    assert_eq!(
        failure,
        ArtifactFailure::EditTextNotUnique {
            artifact: ArtifactSlot::CandidateHtml,
            occurrences: 2
        }
    );
    assert_eq!(state.lock().expect("state").writes, 0);
    let events = events(gateway.executor().store(), harness.fixture.project_id);
    assert!(!events.iter().any(|event| {
        event.kind().as_str() == ARTIFACT_CHANGE_INTENDED_EVENT_KIND
    }));
}

#[test]
fn unwired_candidate_capability_is_explicitly_unsupported() {
    let mut harness = Harness::new();
    allow_candidate_tools(&mut harness);
    let policy = harness.policy();
    let grant = candidate_grant(&harness, &policy);
    let handle = ArtifactHandle::new(
        harness.fixture.project_id,
        "job-1",
        1,
        "capability-token",
    )
    .expect("handle");
    let mut gateway = ToolGateway::new(
        CandidateArtifactTools::new(
            harness.store(),
            harness.fixture.agent_id,
            harness.fixture.session_id,
            handle.clone(),
            UnavailableArtifactPort,
        )
        .expect("candidate executor"),
    );
    let write = candidate_write_op(
        &harness,
        &handle,
        ArtifactSlot::CandidateHtml,
        "<html></html>",
        "unavailable store",
    );
    let authorization = expect_allow(&mut gateway, &policy, &grant, &write);
    let error = gateway
        .execute(&policy, &write, &authorization)
        .expect_err("unavailable artifact store");
    assert_eq!(
        executor_error(error),
        CoreError::UnsupportedPortFeature {
            feature: PortFeature::ArtifactStore
        }
    );
    let events = events(gateway.executor().store(), harness.fixture.project_id);
    assert!(
        !events
            .iter()
            .any(|event| event.kind().as_str() == ARTIFACT_CHANGE_EVENT_KIND)
    );
}
