//! Black-box tests for the `bash` tool and managed process groups.
//!
//! Each test uses a temporary project, a real SQLite store in a temporary
//! application-data root, and the public `ToolGateway` boundary. Process
//! creation goes through a counting launcher so pre-rejection cases can prove
//! that no process was created. No engine, Tauri, network, or real credential
//! is involved.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use herness_core::*;
use herness_runtime_tests::fixtures::ProjectFixture;
use herness_store::test_support::{CommitFault, ResultFault};
use herness_store::{Store, StoreConfig};
use serde_json::json;
use tempfile::TempDir;

/// Wraps the real launcher and counts spawn attempts.
struct CountingLauncher {
    inner: SystemLauncher,
    spawns: Arc<AtomicUsize>,
}

impl ProcessLauncher for CountingLauncher {
    type Child = SystemChild;

    fn spawn(&mut self, request: &SpawnRequest) -> std::io::Result<SystemChild> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.inner.spawn(request)
    }
}

struct Harness {
    _temp: TempDir,
    project_root: PathBuf,
    config: StoreConfig,
    fixture: ProjectFixture,
    admin: PolicyAdmin,
    supervisor: ProcessSupervisor,
    spawns: Arc<AtomicUsize>,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let project = temp.path().join("project");
        fs::create_dir_all(&project).expect("project directory");
        let project_root = fs::canonicalize(&project).expect("canonical project");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("app data root");
        config
            .ensure_outside_project(&project_root)
            .expect("app data root is outside the project");
        Self {
            _temp: temp,
            project_root,
            config,
            fixture: ProjectFixture::new(),
            admin: PolicyAdmin::new(),
            supervisor: ProcessSupervisor::new(),
            spawns: Arc::new(AtomicUsize::new(0)),
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

    fn executor(&self) -> BashExecutor<Store, CountingLauncher> {
        BashExecutor::new(
            self.fixture.agent_id,
            self.fixture.session_id,
            self.store(),
            CountingLauncher {
                inner: SystemLauncher,
                spawns: Arc::clone(&self.spawns),
            },
            self.supervisor.clone(),
        )
        .expect("bash executor")
        .with_timeout_grace(Duration::from_millis(400))
        .with_confirm_timeout(Duration::from_millis(2_000))
        .with_capture_timeout(Duration::from_millis(500))
    }

    fn gateway(&self) -> ToolGateway<BashExecutor<Store, CountingLauncher>> {
        ToolGateway::new(self.executor())
    }

    fn allow_bash(&mut self) {
        self.admin
            .add_rule(
                PermissionRule::allow(
                    RuleTarget::Tool {
                        tool: ToolName::Bash,
                    },
                    MatchMethod::AnyInvocation,
                )
                .expect("rule"),
            )
            .expect("add rule");
    }

    fn bash_op(&self, command: &str, purpose: &str, timeout_ms: Option<u64>) -> FrozenOperation {
        self.freeze(self.fixture.operation_id(), command, purpose, timeout_ms)
    }

    fn freeze(
        &self,
        operation: OperationId,
        command: &str,
        purpose: &str,
        timeout_ms: Option<u64>,
    ) -> FrozenOperation {
        FrozenOperation::new(
            operation,
            self.fixture.run_id,
            ToolName::Bash,
            ToolArguments::Bash(BashArgs {
                command: NonEmptyText::new(command).expect("command"),
                purpose: Purpose::new(purpose).expect("purpose"),
                timeout_ms,
            }),
            self.cwd(),
            self.admin.policy().version(),
            self.admin.policy().mode(),
        )
        .expect("frozen operation")
    }

    fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project_root.join(relative)
    }
}

fn context() -> EvaluationContext {
    EvaluationContext::new("shell tool test", Vec::new())
}

fn expect_allow(
    gateway: &mut ToolGateway<BashExecutor<Store, CountingLauncher>>,
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

fn execute_through_gateway(
    gateway: &mut ToolGateway<BashExecutor<Store, CountingLauncher>>,
    policy: &PermissionPolicy,
    grant: &GrantScope,
    operation: &FrozenOperation,
) -> Result<BashOutput, CoreError> {
    let authorization = expect_allow(gateway, policy, grant, operation);
    gateway
        .execute(policy, operation, &authorization)
        .map_err(|error| match error {
            GatewayError::Executor(error) => error,
            GatewayError::Approval(error) => panic!("unexpected approval error: {error}"),
        })
}

fn expect_shell_failure(error: CoreError) -> (ToolName, ShellFailure) {
    match error {
        CoreError::ShellToolFailed { tool, failure } => (tool, failure),
        other => panic!("expected a shell tool failure, got {other:?}"),
    }
}

fn expect_gateway_shell_failure(error: GatewayError) -> (ToolName, ShellFailure) {
    match error {
        GatewayError::Executor(error) => expect_shell_failure(error),
        GatewayError::Approval(error) => panic!("unexpected approval error: {error}"),
    }
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

fn wait_for_file(path: &Path) -> u64 {
    let text = wait_for_text(path);
    text.trim().parse().expect("pid file contains a pid")
}

fn wait_for_text(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_exists(pid: u64) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_until_gone(pid: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_exists(pid) {
        assert!(
            Instant::now() < deadline,
            "process {pid} still exists after stop"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn kill_process(pid: u64) {
    let _ = Command::new("/bin/kill")
        .args(["-9", &pid.to_string()])
        .status();
}

#[test]
fn empty_or_whitespace_purpose_is_rejected_at_deserialization_without_spawn() {
    let harness = Harness::new();
    let rejected = serde_json::from_value::<ToolArguments>(json!({
        "tool": "bash",
        "arguments": {
            "command": "touch should-not-exist",
            "purpose": "   "
        }
    }));
    assert!(
        rejected.is_err(),
        "empty purpose must be rejected as a schema error"
    );
    assert_eq!(harness.spawn_count(), 0);
    assert!(!harness.path("should-not-exist").exists());
}

#[test]
fn denied_permission_never_spawns() {
    let mut harness = Harness::new();
    let command = "touch denied.txt";
    harness
        .admin
        .add_rule(
            PermissionRule::deny(
                RuleTarget::BashCommand {
                    command: command.to_owned(),
                },
                MatchMethod::ExactCommand,
            )
            .expect("rule"),
        )
        .expect("add rule");
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.bash_op(command, "attempt a denied command", None);

    let outcome = gateway
        .authorize(&policy, &grant, &operation, &context(), None)
        .expect("authorize");
    assert!(matches!(outcome, PermissionOutcome::Deny { .. }));
    assert_eq!(harness.spawn_count(), 0);
    assert!(!harness.path("denied.txt").exists());
}

#[test]
fn unapproved_operation_waits_and_never_spawns() {
    let harness = Harness::new();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.bash_op("touch unapproved.txt", "attempt unapproved work", None);

    let outcome = gateway
        .authorize(&policy, &grant, &operation, &context(), None)
        .expect("authorize");
    match outcome {
        PermissionOutcome::AwaitingApproval { request } => {
            assert_eq!(request.operation_id(), operation.operation_id());
        }
        other => panic!("expected human wait, got {other:?}"),
    }
    assert_eq!(harness.spawn_count(), 0);
    assert!(!harness.path("unapproved.txt").exists());
}

#[test]
fn pre_save_persistence_failure_never_spawns() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();

    for fault in [CommitFault::BeforeRows, CommitFault::BeforeCommit] {
        gateway
            .executor_mut()
            .store_mut()
            .set_commit_fault(Some(fault));
        let operation = harness.bash_op("touch pre-save.txt", "must not run", None);
        let error = execute_through_gateway(&mut gateway, &policy, &grant, &operation)
            .expect_err("pre-save failure must prevent execution");
        let (tool, failure) = expect_shell_failure(error);
        assert_eq!(tool, ToolName::Bash);
        assert!(matches!(failure, ShellFailure::NotExecutable { .. }));
        assert_eq!(harness.spawn_count(), 0);
        assert!(!harness.path("pre-save.txt").exists());
        assert!(operation_record(gateway.executor().store(), operation.operation_id()).is_none());
        gateway.executor_mut().store_mut().set_commit_fault(None);
    }
}

#[test]
fn new_spawns_are_refused_after_stop_begins() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let _ = harness.supervisor.stop_all(Duration::ZERO);
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.bash_op("touch after-stop.txt", "must not start after stop", None);

    let error = execute_through_gateway(&mut gateway, &policy, &grant, &operation)
        .expect_err("a stopped host must refuse new work");
    let (_, failure) = expect_shell_failure(error);
    assert!(matches!(failure, ShellFailure::Stopped { confirmed: true }));
    assert_eq!(harness.spawn_count(), 0);
    assert!(!harness.path("after-stop.txt").exists());

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let result = record.result().expect("refusal is recorded");
    assert_eq!(result.outcome(), OperationOutcome::NotApplied);
    assert!(result.evidence().shell().is_none());
}

#[test]
fn stop_terminates_child_and_grandchild_and_reports_stop_requested() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    // The managed shell starts a child shell, which starts a grandchild
    // `sleep`. All remain in the managed process group.
    let command = concat!(
        "sh -c 'sleep 30 & echo \"$!\" > grandchild.pid; wait' &\n",
        "echo \"$!\" > child.pid\n",
        "echo \"$$\" > shell.pid\n",
        "sleep 30\n"
    );
    let operation = harness.bash_op(command, "start a process tree for stop", None);
    let authorization = expect_allow(&mut gateway, &policy, &grant, &operation);

    let policy_clone = policy.clone();
    let operation_clone = operation.clone();
    let supervisor = harness.supervisor.clone();
    let handle = thread::spawn(move || {
        let result = gateway.execute(&policy_clone, &operation_clone, &authorization);
        (gateway, result)
    });

    let shell_pid = wait_for_file(&harness.path("shell.pid"));
    let child_pid = wait_for_file(&harness.path("child.pid"));
    let grandchild_pid = wait_for_file(&harness.path("grandchild.pid"));
    assert!(process_exists(shell_pid));
    assert!(process_exists(child_pid));
    assert!(process_exists(grandchild_pid));

    let report = supervisor.stop_all(Duration::from_millis(800));
    assert!(
        report.all_confirmed(),
        "managed groups must be confirmed gone: {report:?}"
    );

    let (gateway, result) = handle.join().expect("executor thread");
    let error = result.expect_err("a stopped command is not a success");
    let (_, failure) = expect_gateway_shell_failure(error);
    assert!(matches!(failure, ShellFailure::Stopped { confirmed: true }));

    wait_until_gone(shell_pid);
    wait_until_gone(child_pid);
    wait_until_gone(grandchild_pid);

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let result = record.result().expect("stopped result is persisted");
    assert_eq!(result.outcome(), OperationOutcome::Unverifiable);
    assert!(!result.evidence().shell_outcome_unknown());
    assert!(result.evidence().files().is_empty());
    let observation = result.evidence().shell().expect("shell observation");
    assert_eq!(observation.stop_status(), ShellStopStatus::StopRequested);
    assert_eq!(observation.pid(), shell_pid as u32);
    assert_eq!(observation.pgid(), shell_pid as u32);

    let events = events(store, harness.fixture.project_id);
    let started = event_of_kind(&events, SHELL_STARTED_EVENT_KIND).expect("started event");
    let spawned = event_of_kind(&events, SHELL_SPAWNED_EVENT_KIND).expect("spawned event");
    let finished = event_of_kind(&events, SHELL_FINISHED_EVENT_KIND).expect("finished event");
    assert!(started.sequence() < spawned.sequence());
    assert!(spawned.sequence() < finished.sequence());
    assert_eq!(spawned.payload().as_value()["pid"], shell_pid);
    assert_eq!(
        finished.payload().as_value()["stopStatus"],
        "stop_requested"
    );
}

#[test]
fn stop_escalates_to_sigkill_when_sigterm_is_ignored() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let command = "trap '' TERM; echo \"$$\" > stubborn.pid; sleep 30";
    let operation = harness.bash_op(command, "ignore cooperative termination", None);
    let authorization = expect_allow(&mut gateway, &policy, &grant, &operation);

    let policy_clone = policy.clone();
    let operation_clone = operation.clone();
    let supervisor = harness.supervisor.clone();
    let handle = thread::spawn(move || {
        let result = gateway.execute(&policy_clone, &operation_clone, &authorization);
        (gateway, result)
    });

    let pid = wait_for_file(&harness.path("stubborn.pid"));
    let report = supervisor.stop_all(Duration::from_millis(200));
    assert!(report.all_confirmed());
    assert!(
        report.reports().iter().any(GroupStopReport::kill_sent),
        "SIGKILL must be sent after the grace period"
    );

    let (gateway, result) = handle.join().expect("executor thread");
    let (_, failure) =
        expect_gateway_shell_failure(result.expect_err("a force-stopped command is not a success"));
    assert!(matches!(failure, ShellFailure::Stopped { confirmed: true }));
    wait_until_gone(pid);

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let observation = record
        .result()
        .expect("result persisted")
        .evidence()
        .shell()
        .expect("shell observation")
        .clone();
    assert_eq!(observation.stop_status(), ShellStopStatus::StopRequested);
    // SIGKILL is 9 on the macOS/unix targets supported by this workspace.
    assert_eq!(observation.terminating_signal(), Some(9));
}

#[test]
fn evidence_without_a_shell_field_stays_compatible_and_unknown_fields_are_rejected() {
    let old: OperationEvidence = serde_json::from_value(json!({
        "files": [],
        "shellOutcomeUnknown": false
    }))
    .expect("evidence written before the shell field must still load");
    assert!(old.shell().is_none());
    assert!(!old.shell_outcome_unknown());

    let unknown = json!({
        "files": [],
        "shellOutcomeUnknown": false,
        "unexpected": true
    });
    assert!(serde_json::from_value::<OperationEvidence>(unknown).is_err());
}

#[test]
fn output_flood_is_bounded_marked_truncated_and_persisted() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let command = concat!(
        "/bin/dd if=/dev/zero bs=1024 count=512 2>/dev/null | /usr/bin/tr '\\000' a; ",
        "/bin/dd if=/dev/zero bs=1024 count=512 2>/dev/null | /usr/bin/tr '\\000' b >&2"
    );
    let operation = harness.bash_op(command, "produce a large amount of output", None);

    let output = execute_through_gateway(&mut gateway, &policy, &grant, &operation)
        .expect("flooding output must not block completion");
    let observation = output.observation();
    assert_eq!(observation.stop_status(), ShellStopStatus::Completed);
    assert_eq!(observation.stdout().original_bytes(), 512 * 1024);
    assert_eq!(observation.stderr().original_bytes(), 512 * 1024);
    assert!(observation.stdout().truncated());
    assert!(observation.stderr().truncated());
    assert!(
        observation
            .stdout()
            .text()
            .contains("[herness output truncated:"),
        "truncation must be explicit"
    );
    assert!(
        observation.stdout().text().len() <= 2 * DEFAULT_OUTPUT_LIMIT + 256,
        "retained output must stay bounded"
    );
    assert_eq!(output.outcome(), OperationOutcome::Applied);

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let result = record.result().expect("result persisted");
    assert_eq!(result.outcome(), OperationOutcome::Applied);
    let persisted = result.evidence().shell().expect("persisted observation");
    assert!(!result.evidence().shell_outcome_unknown());
    assert_eq!(persisted.stdout().original_bytes(), 512 * 1024);
    assert!(persisted.stdout().truncated());
    assert!(persisted.stderr().truncated());
    assert_eq!(persisted.stop_status(), ShellStopStatus::Completed);
}

#[test]
fn persistence_failure_after_stop_is_unverifiable_and_not_success() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    gateway
        .executor_mut()
        .store_mut()
        .set_result_fault(Some(ResultFault::BeforeUpdate));
    let command = "echo started > stopped-work.txt; sleep 30";
    let operation = harness.bash_op(command, "work that will be stopped", None);
    let authorization = expect_allow(&mut gateway, &policy, &grant, &operation);

    let policy_clone = policy.clone();
    let operation_clone = operation.clone();
    let supervisor = harness.supervisor.clone();
    let handle = thread::spawn(move || {
        let result = gateway.execute(&policy_clone, &operation_clone, &authorization);
        (gateway, result)
    });

    wait_for_text(&harness.path("stopped-work.txt"));
    let report = supervisor.stop_all(Duration::from_millis(800));
    assert!(report.all_confirmed());
    let (gateway, result) = handle.join().expect("executor thread");
    let error = result.expect_err("a store failure must not be reported as success");
    let (_, failure) = expect_gateway_shell_failure(error);
    assert!(matches!(failure, ShellFailure::Unverifiable { .. }));

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    assert!(
        record.result().is_none(),
        "the failed result write leaves the intent pending"
    );
    assert!(
        store
            .pending_operations(&harness.fixture.project_id)
            .expect("pending")
            .iter()
            .any(|intent| intent.operation().operation_id() == operation.operation_id())
    );
    let unresolved = store
        .unresolved_operations(&harness.fixture.project_id)
        .expect("unresolved");
    assert!(
        unresolved
            .iter()
            .any(|record| record.intent().operation().operation_id() == operation.operation_id())
    );
}

#[test]
fn shell_created_file_has_no_file_change_event_or_rationale() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let purpose = "create a note without a file rationale";
    let operation = harness.bash_op(
        "echo content > shell-created.txt; echo visible",
        purpose,
        None,
    );

    let output =
        execute_through_gateway(&mut gateway, &policy, &grant, &operation).expect("bash command");
    assert_eq!(
        fs::read_to_string(harness.path("shell-created.txt")).expect("file"),
        "content\n"
    );
    assert!(output.observation().stdout().text().contains("visible"));

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let result = record.result().expect("result persisted");
    assert!(
        result.evidence().files().is_empty(),
        "bash must not fabricate per-file evidence"
    );
    let observation = result.evidence().shell().expect("shell observation");
    assert!(observation.stdout().text().contains("visible"));

    let events = events(store, harness.fixture.project_id);
    assert!(
        !events.iter().any(|event| {
            event.kind().as_str() == FILE_CHANGE_EVENT_KIND
                || event.kind().as_str() == FILE_CHANGE_INTENDED_EVENT_KIND
        }),
        "bash must not emit file.change events"
    );
    for event in &events {
        assert!(
            event.payload().as_value().get("rationale").is_none(),
            "no event may carry a fabricated file rationale"
        );
    }
    let started = event_of_kind(&events, SHELL_STARTED_EVENT_KIND).expect("started event");
    assert_eq!(started.payload().as_value()["purpose"], purpose);
    assert_eq!(
        started.payload().as_value()["command"],
        "echo content > shell-created.txt; echo visible"
    );
}

#[test]
fn timeout_terminates_group_and_is_not_success() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    let operation = harness.bash_op("sleep 30", "run past a short timeout", Some(120));

    let started = Instant::now();
    let error = execute_through_gateway(&mut gateway, &policy, &grant, &operation)
        .expect_err("a timed-out command is not a success");
    let (_, failure) = expect_shell_failure(error);
    assert!(matches!(
        failure,
        ShellFailure::TimedOut { confirmed: true }
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "timeout termination must be bounded"
    );

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let result = record.result().expect("timed-out observation is persisted");
    assert_eq!(result.outcome(), OperationOutcome::Unverifiable);
    assert!(!result.evidence().shell_outcome_unknown());
    let observation = result.evidence().shell().expect("shell observation");
    assert_eq!(observation.stop_status(), ShellStopStatus::Timeout);
    assert!(observation.terminating_signal().is_some());
    assert_eq!(observation.exit_code(), None);
    assert!(!process_exists(u64::from(observation.pid())));
}

#[test]
fn restart_does_not_resend_and_pending_shell_result_stays_unverified() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let operation = harness.bash_op(
        "echo made > made.txt",
        "create a file then lose the result record",
        None,
    );

    {
        let mut gateway = harness.gateway();
        gateway
            .executor_mut()
            .store_mut()
            .set_result_fault(Some(ResultFault::BeforeUpdate));
        let error = execute_through_gateway(&mut gateway, &policy, &grant, &operation)
            .expect_err("result persistence failure must not be success");
        let (_, failure) = expect_shell_failure(error);
        assert!(matches!(failure, ShellFailure::Unverifiable { .. }));
    }
    assert_eq!(harness.spawn_count(), 1);
    assert_eq!(
        fs::read_to_string(harness.path("made.txt")).expect("file"),
        "made\n"
    );

    // Reopen the store in a new connection, as a restarted host would.
    let store = harness.store();
    let pending = store
        .pending_operations(&harness.fixture.project_id)
        .expect("pending");
    let intent = pending
        .iter()
        .find(|intent| intent.operation().operation_id() == operation.operation_id())
        .expect("pending shell intent");
    assert_eq!(intent.operation(), &operation);
    let unresolved = store
        .unresolved_operations(&harness.fixture.project_id)
        .expect("unresolved");
    let record = unresolved
        .iter()
        .find(|record| record.intent().operation().operation_id() == operation.operation_id())
        .expect("unresolved shell record");
    let events = store
        .events_after(
            &harness.fixture.project_id,
            None,
            HistoryLimit::new(50).expect("limit"),
        )
        .expect("events");
    let reconciliation =
        reconcile_shell_operation(record, &events).expect("bash reconciliation data");
    assert_eq!(reconciliation.command(), "echo made > made.txt");
    assert_eq!(reconciliation.cwd(), &harness.cwd());
    assert_eq!(
        reconciliation.purpose(),
        "create a file then lose the result record"
    );
    assert!(reconciliation.pid().is_some(), "spawned pid is recorded");
    assert!(reconciliation.pgid().is_some(), "spawned pgid is recorded");
    assert!(reconciliation.shell_outcome_unknown());
    assert_eq!(reconciliation.outcome(), None);
    // A file exists whose content matches the command, but that is not proof
    // of shell success.
    assert!(reconciliation.observation().is_none());
    assert_ne!(reconciliation.outcome(), Some(OperationOutcome::Applied));

    // A restarted host must not resend the command.
    let mut restarted = harness.gateway();
    let authorization = expect_allow(&mut restarted, &policy, &grant, &operation);
    let error = match restarted.execute(&policy, &operation, &authorization) {
        Err(GatewayError::Executor(error)) => error,
        other => panic!("expected executor duplicate error, got {other:?}"),
    };
    assert!(matches!(error, CoreError::DuplicateOperation { .. }));
    assert_eq!(harness.spawn_count(), 1, "restart must not spawn again");
}

#[test]
fn detached_descendant_is_outside_the_managed_group_guarantee() {
    let mut harness = Harness::new();
    harness.allow_bash();
    let policy = harness.policy();
    let grant = harness.grant(&policy);
    let mut gateway = harness.gateway();
    // `POSIX::setsid()` moves the descendant into a new session/group, which
    // the managed group stop cannot see. The result must only describe the
    // managed group; the detached process is intentionally untracked.
    let command = concat!(
        "/usr/bin/perl -e 'use POSIX; POSIX::setsid(); open my $fh, \">\", \"detached.ready\" or exit 1; print $fh \"ready\"; close $fh; sleep 30' &\n",
        "echo \"$!\" > detached.pid\n",
        "echo \"$$\" > shell.pid\n",
        "sleep 30\n"
    );
    let operation = harness.bash_op(command, "demonstrate a detached descendant", None);
    let authorization = expect_allow(&mut gateway, &policy, &grant, &operation);
    let policy_clone = policy.clone();
    let operation_clone = operation.clone();
    let supervisor = harness.supervisor.clone();
    let handle = thread::spawn(move || {
        let result = gateway.execute(&policy_clone, &operation_clone, &authorization);
        (gateway, result)
    });

    let shell_pid = wait_for_file(&harness.path("shell.pid"));
    let detached_pid = wait_for_file(&harness.path("detached.pid"));
    wait_for_text(&harness.path("detached.ready"));
    let report = supervisor.stop_all(Duration::from_millis(800));
    assert!(report.all_confirmed(), "managed group is confirmed gone");
    let (gateway, result) = handle.join().expect("executor thread");
    let (_, failure) =
        expect_gateway_shell_failure(result.expect_err("a stopped command is not a success"));
    assert!(matches!(failure, ShellFailure::Stopped { confirmed: true }));

    // The managed shell is gone, but the detached descendant survives. The
    // host does not claim to have stopped it.
    wait_until_gone(shell_pid);
    assert!(
        process_exists(detached_pid),
        "detached process is intentionally outside the group guarantee"
    );
    kill_process(detached_pid);
    wait_until_gone(detached_pid);

    let store = gateway.executor().store();
    let record = operation_record(store, operation.operation_id()).expect("operation record");
    let observation = record
        .result()
        .expect("result persisted")
        .evidence()
        .shell()
        .expect("shell observation")
        .clone();
    assert_eq!(observation.stop_status(), ShellStopStatus::StopRequested);
    // The observation describes only the managed group; it carries no claim
    // about the detached descendant that survived.
    assert_eq!(observation.pgid(), shell_pid as u32);
}
