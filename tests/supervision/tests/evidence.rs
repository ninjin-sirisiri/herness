//! H2 verification evidence, freshness, and durable supervision-store tests.
//!
//! Every workspace, executor, and provider value is synthetic. The permission
//! tests use the real H1 `PermissionService` through `ToolGateway` with a fake
//! executor; nothing runs a real shell, reads a real project, or calls a
//! provider.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use herness_core::CoreError;
use herness_core::contracts::{AbsolutePath, OperationId, ProjectId, RunId, Timestamp};
use herness_core::permissions::{
    EvaluationContext, GrantScope, MatchMethod, PermissionPolicy, PermissionRule, PolicyAdmin,
    RuleTarget,
};
use herness_core::tools::{
    BashArgs, NonEmptyText, Purpose, ToolArguments, ToolExecutor, ToolGateway, ToolName,
};
use herness_store::test_support::{
    CommitFault, MigrationFault, open_at_schema_version, open_with_migration_fault,
};
use herness_store::{Store, StoreConfig};
use herness_supervision::SupervisionError;
use herness_supervision::assessment::ConditionVerdict;
use herness_supervision::command::{SupervisionCommand, SupervisionRequest, execute_command};
use herness_supervision::evidence::{
    CheckStatus, EvidenceAcquirer, EvidenceOutcome, EvidenceRecord, EvidenceScope,
    RequiredCheckResult, TargetVersion, VerificationOperation,
};
use herness_supervision::freshness::{
    CompletionFreshness, EvidenceApplicability, InputOrigin, ManifestCoverage, TargetManifest,
    TargetReadSet, WorkspaceInput, WorkspaceSnapshotPort,
};
use herness_supervision::ids::{CheckId, ConditionId, EvidenceId, SupervisionId};
use herness_supervision::ports::{EvidenceStorePort, SupervisionStorePort};
use herness_supervision::profiles::ProfileThresholds;
use herness_supervision::state::{CompletionSnapshot, SupervisionRecord, SupervisionState};
use herness_supervision::verification::{
    GatewayVerification, VerificationDisposition, VerificationExecution, VerificationPlan,
    VerificationService, validate_evidence_record,
};
use herness_supervision_tests::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Synthetic workspace and evidence fixtures
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct WorkspaceState {
    head: Option<String>,
    listed: BTreeMap<String, InputOrigin>,
    files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
struct SharedWorkspace(Rc<RefCell<WorkspaceState>>);

impl SharedWorkspace {
    fn new(head: Option<&str>) -> Self {
        Self(Rc::new(RefCell::new(WorkspaceState {
            head: head.map(str::to_owned),
            ..WorkspaceState::default()
        })))
    }

    fn track(&self, path: &str, origin: InputOrigin, bytes: &[u8]) {
        let mut state = self.0.borrow_mut();
        state.listed.insert(path.to_owned(), origin);
        state.files.insert(path.to_owned(), bytes.to_vec());
    }

    fn set(&self, path: &str, bytes: &[u8]) {
        self.0
            .borrow_mut()
            .files
            .insert(path.to_owned(), bytes.to_vec());
    }

    fn remove_keeping_listing(&self, path: &str) {
        self.0.borrow_mut().files.remove(path);
    }
}

impl WorkspaceSnapshotPort for SharedWorkspace {
    fn head(&self) -> Result<Option<String>, SupervisionError> {
        Ok(self.0.borrow().head.clone())
    }

    fn inputs(&self) -> Result<Vec<WorkspaceInput>, SupervisionError> {
        self.0
            .borrow()
            .listed
            .iter()
            .map(|(path, origin)| WorkspaceInput::new(path, *origin))
            .collect()
    }

    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, SupervisionError> {
        Ok(self.0.borrow().files.get(path).cloned())
    }
}

fn service(workspace: &SharedWorkspace) -> VerificationService<SharedWorkspace, FixedClock> {
    VerificationService::new(workspace.clone(), FixedClock)
}

fn capture(workspace: &SharedWorkspace, version: u64, paths: &[&str]) -> TargetManifest {
    service(workspace)
        .capture(
            project(),
            TargetVersion::new(version).expect("version"),
            TargetReadSet::Declared(paths.iter().map(|path| (*path).to_owned()).collect()),
        )
        .expect("manifest")
}

fn evidence_for(
    manifest: &TargetManifest,
    ids: Ids,
    evidence_id: EvidenceId,
    check: CheckId,
    condition: ConditionId,
    status: CheckStatus,
    sequence: u64,
) -> EvidenceRecord {
    EvidenceRecord::new(
        evidence_id,
        ids.supervision,
        Some(condition),
        Some(check),
        EvidenceAcquirer::ChildAgent,
        VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
        EvidenceOutcome::new(
            match status {
                CheckStatus::Pass | CheckStatus::Inconclusive => Some(0),
                CheckStatus::Fail => Some(1),
                _ => None,
            },
            None,
            false,
            false,
            "cargo test: 12 passed; 0 failed; 0 ignored",
        )
        .expect("outcome"),
        manifest.target_scope().expect("target"),
        EvidenceScope::new(
            vec!["src/lib.rs".to_owned()],
            vec!["fixture package only; no network".to_owned()],
        )
        .expect("scope"),
        status,
        sequence,
        now(),
    )
    .expect("evidence")
}

#[derive(Default)]
struct MemoryEvidenceStore {
    records: BTreeMap<EvidenceId, EvidenceRecord>,
}

impl EvidenceStorePort for MemoryEvidenceStore {
    fn append(&mut self, evidence: EvidenceRecord) -> Result<EvidenceRecord, SupervisionError> {
        if let Some(existing) = self.records.get(&evidence.id()) {
            if existing == &evidence {
                return Ok(existing.clone());
            }
            return Err(SupervisionError::EvidenceContractViolation {
                field: "evidence.id".to_owned(),
                detail: "a different record is already stored for this id".to_owned(),
            });
        }
        self.records.insert(evidence.id(), evidence.clone());
        Ok(evidence)
    }

    fn get(
        &self,
        project_id: ProjectId,
        evidence_id: EvidenceId,
    ) -> Result<Option<EvidenceRecord>, SupervisionError> {
        evidence_id.validate_in(project_id)?;
        Ok(self.records.get(&evidence_id).cloned())
    }

    fn list_for_supervision(
        &self,
        project_id: ProjectId,
        supervision_id: SupervisionId,
    ) -> Result<Vec<EvidenceRecord>, SupervisionError> {
        supervision_id.validate_in(project_id)?;
        let mut records = self
            .records
            .values()
            .filter(|record| record.supervision_id() == supervision_id)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by_key(EvidenceRecord::sequence);
        Ok(records)
    }
}

struct FakeExecutor {
    calls: Rc<Cell<usize>>,
    result: VerificationExecution,
    during: Option<Box<dyn FnOnce()>>,
}

impl FakeExecutor {
    fn new(calls: Rc<Cell<usize>>, result: VerificationExecution) -> Self {
        Self {
            calls,
            result,
            during: None,
        }
    }

    fn with_during(mut self, during: Box<dyn FnOnce()>) -> Self {
        self.during = Some(during);
        self
    }
}

impl ToolExecutor for FakeExecutor {
    type Output = VerificationExecution;

    fn execute(
        &mut self,
        _operation: &herness_core::contracts::FrozenOperation,
    ) -> Result<Self::Output, CoreError> {
        self.calls.set(self.calls.get() + 1);
        if let Some(during) = self.during.take() {
            during();
        }
        Ok(self.result.clone())
    }
}

fn pass_execution() -> VerificationExecution {
    VerificationExecution::new(
        CheckStatus::Pass,
        Some(0),
        None,
        false,
        false,
        "cargo test: 12 passed; 0 failed; 0 ignored",
    )
    .expect("pass execution")
}

fn policy_with(effect: &str) -> PermissionPolicy {
    let mut admin = PolicyAdmin::new();
    let rule = match effect {
        "allow" => PermissionRule::allow(
            RuleTarget::Tool {
                tool: ToolName::Bash,
            },
            MatchMethod::AnyInvocation,
        ),
        "deny" => PermissionRule::deny(
            RuleTarget::Tool {
                tool: ToolName::Bash,
            },
            MatchMethod::AnyInvocation,
        ),
        "ask" => PermissionRule::ask(
            RuleTarget::Tool {
                tool: ToolName::Bash,
            },
            MatchMethod::AnyInvocation,
        ),
        _ => panic!("unknown effect"),
    }
    .expect("rule");
    admin.add_rule(rule).expect("add rule");
    admin.policy().clone()
}

fn bash_operation(
    policy: &PermissionPolicy,
    command: &str,
) -> herness_core::contracts::FrozenOperation {
    herness_core::contracts::FrozenOperation::new(
        OperationId::new(project()),
        RunId::new(project()),
        ToolName::Bash,
        ToolArguments::Bash(BashArgs {
            command: NonEmptyText::new(command).expect("command"),
            purpose: Purpose::new("run the approved verification").expect("purpose"),
            timeout_ms: None,
        }),
        AbsolutePath::new("/tmp/herness-evidence-fixture").expect("absolute"),
        policy.version(),
        policy.mode(),
    )
    .expect("frozen operation")
}

fn plan(ids: Ids, sequence: u64) -> VerificationPlan {
    VerificationPlan::new(
        ids.evidence_a,
        ids.supervision,
        Some(ids.condition_a),
        Some(ids.check_a),
        EvidenceAcquirer::ChildAgent,
        None,
        VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
        EvidenceScope::new(
            vec!["src/lib.rs".to_owned()],
            vec!["fixture package only; no network".to_owned()],
        )
        .expect("scope"),
        sequence,
        TargetVersion::new(1).expect("version"),
        TargetReadSet::Declared(vec!["src/lib.rs".to_owned()]),
    )
    .expect("plan")
}

// ---------------------------------------------------------------------------
// Five-item validation and status distinctions
// ---------------------------------------------------------------------------

#[test]
fn statuses_stay_distinct_and_nonzero_signal_timeout_or_truncation_never_pass() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(Some("0123456789abcdef"));
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"fixture source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);

    for (status, sequence) in [
        (CheckStatus::Pass, 1),
        (CheckStatus::Fail, 2),
        (CheckStatus::NotRun, 3),
        (CheckStatus::Unavailable, 4),
        (CheckStatus::Inconclusive, 5),
    ] {
        let record = evidence_for(
            &manifest,
            fixture,
            fixture.evidence_a,
            fixture.check_a,
            fixture.condition_a,
            status,
            sequence,
        );
        // NotRun/Unavailable fixtures have no command result, so they are
        // recorded through an equivalent-operation path instead.
        let record = if matches!(status, CheckStatus::NotRun | CheckStatus::Unavailable) {
            EvidenceRecord::new(
                fixture.evidence_a,
                fixture.supervision,
                Some(fixture.condition_a),
                Some(fixture.check_a),
                EvidenceAcquirer::ChildAgent,
                VerificationOperation::equivalent("the check did not run").expect("operation"),
                EvidenceOutcome::new(
                    None,
                    None,
                    false,
                    false,
                    "not run: the fixture executor was unavailable",
                )
                .expect("outcome"),
                manifest.target_scope().expect("target"),
                EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
                status,
                sequence,
                now(),
            )
            .expect("evidence")
        } else {
            record.with_observer("child-agent-fixture")
        };
        validate_evidence_record(&record, None).expect("valid fixture evidence");
        assert_eq!(record.status(), status);
        assert_eq!(record.status().is_pass(), status == CheckStatus::Pass);
        let result = RequiredCheckResult::from_evidence(
            &record,
            herness_supervision::conditions::ConditionVersion::new(1).expect("version"),
        )
        .expect("check result");
        assert_eq!(result.status(), status);
    }

    assert!(
        VerificationExecution::new(
            CheckStatus::Pass,
            Some(1),
            None,
            false,
            false,
            "cargo test: 1 failed",
        )
        .is_err()
    );
    assert!(
        VerificationExecution::new(
            CheckStatus::Pass,
            None,
            Some(9),
            false,
            false,
            "terminated by signal 9",
        )
        .is_err()
    );
    assert!(
        VerificationExecution::new(
            CheckStatus::Pass,
            Some(0),
            None,
            true,
            false,
            "timed out after 60 s",
        )
        .is_err()
    );
    assert!(
        VerificationExecution::new(
            CheckStatus::Pass,
            Some(0),
            None,
            false,
            true,
            "output truncated after 64 KiB",
        )
        .is_err()
    );

    let fail = VerificationExecution::new(
        CheckStatus::Fail,
        Some(1),
        None,
        false,
        false,
        "cargo test: 1 failed",
    )
    .expect("fail result");
    assert!(!fail.status().is_pass());
}

#[test]
fn applied_operation_missing_result_and_fake_success_are_rejected() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"fixture source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);

    assert!(
        VerificationExecution::new(
            CheckStatus::Pass,
            None,
            None,
            false,
            false,
            "the operation was applied",
        )
        .is_err()
    );
    assert!(VerificationExecution::observed(CheckStatus::Pass, "DONE").is_err());

    let missing_result = EvidenceRecord::new(
        fixture.evidence_a,
        fixture.supervision,
        Some(fixture.condition_a),
        Some(fixture.check_a),
        EvidenceAcquirer::ChildAgent,
        VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
        EvidenceOutcome::new(
            None,
            None,
            false,
            false,
            "the child agent said it succeeded",
        )
        .expect("outcome"),
        manifest.target_scope().expect("target"),
        EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
        CheckStatus::Pass,
        1,
        now(),
    )
    .expect("record");
    assert!(matches!(
        validate_evidence_record(
            &missing_result,
            Some(herness_core::OperationOutcome::Applied)
        ),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));

    let fake_done = EvidenceRecord::new(
        fixture.evidence_a,
        fixture.supervision,
        Some(fixture.condition_a),
        Some(fixture.check_a),
        EvidenceAcquirer::ChildAgent,
        VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
        EvidenceOutcome::new(Some(0), None, false, false, "DONE").expect("outcome"),
        manifest.target_scope().expect("target"),
        EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
        CheckStatus::Pass,
        1,
        now(),
    )
    .expect("record");
    assert!(matches!(
        validate_evidence_record(&fake_done, None),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));

    let successful = evidence_for(
        &manifest,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );
    assert!(
        validate_evidence_record(&successful, Some(herness_core::OperationOutcome::Applied))
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Manifests and freshness
// ---------------------------------------------------------------------------

#[test]
fn same_head_with_different_content_changes_the_manifest_and_invalidates_evidence() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(Some("0123456789abcdef"));
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"version one");

    let before = capture(&workspace, 1, &["src/lib.rs"]);
    assert_eq!(before.head(), Some("0123456789abcdef"));
    let evidence = evidence_for(
        &before,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );

    workspace.set("src/lib.rs", b"version two");
    let after = capture(&workspace, 1, &["src/lib.rs"]);
    assert_eq!(after.head(), Some("0123456789abcdef"));
    assert_ne!(
        before.manifest_digest().expect("digest"),
        after.manifest_digest().expect("digest")
    );
    assert_ne!(
        before.entry("src/lib.rs").expect("entry").digest(),
        after.entry("src/lib.rs").expect("entry").digest()
    );

    let freshness = service(&workspace)
        .freshness()
        .evaluate(&after, std::slice::from_ref(&evidence))
        .expect("freshness");
    assert_eq!(
        freshness.evidence()[0].applicability(),
        &EvidenceApplicability::Invalidated {
            changed_paths: vec!["src/lib.rs".to_owned()]
        }
    );
    assert!(!freshness.all_apply());
}

#[test]
fn uncommitted_untracked_external_and_dependency_inputs_are_included() {
    let workspace = SharedWorkspace::new(Some("fedcba9876543210"));
    workspace.track("src/app.rs", InputOrigin::Tracked, b"app");
    workspace.track("src/local.rs", InputOrigin::Uncommitted, b"uncommitted");
    workspace.track("src/new.rs", InputOrigin::Untracked, b"untracked");
    workspace.track("src/external.rs", InputOrigin::External, b"external");
    workspace.track("Cargo.toml", InputOrigin::Dependency, b"[package]");
    workspace.track(".herness/settings.json", InputOrigin::Settings, b"{}");

    let manifest = capture(&workspace, 1, &["src/app.rs"]);
    for path in ["src/app.rs", "Cargo.toml", ".herness/settings.json"] {
        assert!(
            manifest.entry(path).is_some(),
            "{path} must be in the manifest"
        );
    }

    let whole = service(&workspace)
        .widen(project(), TargetVersion::new(1).expect("version"))
        .expect("whole project manifest");
    for path in [
        "src/app.rs",
        "src/local.rs",
        "src/new.rs",
        "src/external.rs",
        "Cargo.toml",
        ".herness/settings.json",
    ] {
        assert!(
            whole.entry(path).is_some(),
            "{path} must be in the widened manifest"
        );
        assert!(whole.read_set().iter().any(|item| item == path));
    }

    let before = whole.manifest_digest().expect("digest");
    workspace.set("src/local.rs", b"uncommitted changed");
    workspace.set("src/new.rs", b"untracked changed");
    workspace.set("src/external.rs", b"shell changed");
    workspace.set("Cargo.toml", b"[package]\nname = \"changed\"");
    let after = service(&workspace)
        .widen(project(), TargetVersion::new(2).expect("version"))
        .expect("whole project manifest");
    let diff = after.diff(&whole);
    assert_eq!(
        diff.changed(),
        &[
            "Cargo.toml".to_owned(),
            "src/external.rs".to_owned(),
            "src/local.rs".to_owned(),
            "src/new.rs".to_owned(),
        ]
    );
    assert_ne!(before, after.manifest_digest().expect("digest"));

    workspace.remove_keeping_listing("src/external.rs");
    let deleted = service(&workspace)
        .widen(project(), TargetVersion::new(3).expect("version"))
        .expect("whole project manifest");
    let entry = deleted.entry("src/external.rs").expect("deleted entry");
    assert!(!entry.present());
    assert!(
        deleted
            .diff(&after)
            .changed()
            .contains(&"src/external.rs".to_owned())
    );
}

#[test]
fn unrelated_changes_preserve_evidence_and_related_changes_invalidate_only_affected() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/a.rs", InputOrigin::Tracked, b"a one");
    workspace.track("src/b.rs", InputOrigin::Tracked, b"b one");
    workspace.track("src/unrelated.txt", InputOrigin::Tracked, b"unrelated");

    let manifest_a = capture(&workspace, 1, &["src/a.rs"]);
    let manifest_b = capture(&workspace, 1, &["src/b.rs"]);
    let evidence_a = evidence_for(
        &manifest_a,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );
    let evidence_b = evidence_for(
        &manifest_b,
        fixture,
        fixture.evidence_b,
        fixture.check_b,
        fixture.condition_b,
        CheckStatus::Pass,
        2,
    );

    workspace.set("src/a.rs", b"a two");
    workspace.set("src/unrelated.txt", b"unrelated changed");
    let current = capture(&workspace, 1, &["src/a.rs", "src/b.rs"]);
    let report = service(&workspace)
        .freshness()
        .evaluate(&current, &[evidence_a.clone(), evidence_b.clone()])
        .expect("freshness");
    assert_eq!(
        report.evidence()[0].applicability(),
        &EvidenceApplicability::Invalidated {
            changed_paths: vec!["src/a.rs".to_owned()]
        }
    );
    assert_eq!(
        report.evidence()[1].applicability(),
        &EvidenceApplicability::Applies
    );
    assert_eq!(report.invalidated(), vec![fixture.evidence_a]);
}

#[test]
fn before_after_and_during_assessment_changes_are_detected() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"stable source");
    let workspaces = workspace.clone();
    let policy = policy_with("allow");

    let calls = Rc::new(Cell::new(0));
    let executor =
        FakeExecutor::new(Rc::clone(&calls), pass_execution()).with_during(Box::new(move || {
            workspaces.set("src/lib.rs", b"changed during verification");
        }));
    let grant = GrantScope::for_run(project(), &policy);
    let mut boundary = GatewayVerification::new(
        ToolGateway::new(executor),
        policy.clone(),
        grant,
        EvaluationContext::new("run the fixture check", vec![]),
    );
    let mut store = MemoryEvidenceStore::default();
    let service = service(&workspace);
    let disposition = service
        .verify(
            &mut store,
            plan(fixture, 1),
            &bash_operation(&policy, "cargo test -p fixture-app --locked"),
            &mut boundary,
        )
        .expect("verify");
    let VerificationDisposition::Recorded(record) = disposition else {
        panic!("expected recorded evidence");
    };
    assert_eq!(calls.get(), 1);
    assert_eq!(record.status(), CheckStatus::Inconclusive);

    let after = capture(&workspace, 1, &["src/lib.rs"]);
    let freshness = service
        .freshness()
        .evaluate(&after, std::slice::from_ref(&record))
        .expect("freshness");
    assert!(freshness.evidence()[0].applicability().is_invalidated());

    // A change after the assessment input was fixed invalidates the result.
    let assessment_target = after.clone();
    workspace.set("src/lib.rs", b"changed during assessment");
    let after_assessment = capture(&workspace, 1, &["src/lib.rs"]);
    assert_ne!(
        assessment_target.manifest_digest().expect("digest"),
        after_assessment.manifest_digest().expect("digest")
    );
    let report = service
        .freshness()
        .evaluate(&after_assessment, std::slice::from_ref(&record))
        .expect("freshness");
    assert!(!report.all_apply());
}

#[test]
fn unknown_scope_is_inconclusive_not_a_pass_or_applicable_target() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"source");
    let known = capture(&workspace, 1, &["src/lib.rs"]);
    let evidence = evidence_for(
        &known,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );
    let unknown = TargetManifest::unknown(
        project(),
        TargetVersion::new(1).expect("version"),
        "workspace listing is unavailable",
    )
    .expect("unknown manifest");
    assert!(unknown.target_scope().is_err());
    assert!(matches!(
        service(&workspace)
            .freshness()
            .evaluate_evidence(&unknown, &evidence)
            .expect("applicability"),
        EvidenceApplicability::UnknownScope { .. }
    ));
    assert!(matches!(unknown.coverage(), ManifestCoverage::Unknown(_)));
}

#[test]
fn stale_assessment_after_a_target_change_is_history_only() {
    let fixture = ids(project());
    let profile = completion_profile(project());
    let mut record = SupervisionRecord::new(&contract(project()));
    let request = assessment_request(
        project(),
        fixture.condition_a,
        &profile,
        vec![fixture.evidence_a],
    );
    let result = assessment_result(&request, ConditionVerdict::Met, request.evidence().to_vec());

    record
        .revise_target(
            herness_supervision::approval::ApprovalActor::Human,
            TargetVersion::new(2).expect("version"),
        )
        .expect("target change requires human confirmation");
    let application = record
        .apply_assessment(&result, ProfileThresholds::normal_llm())
        .expect("apply stale result");
    assert_eq!(
        application,
        herness_supervision::state::AssessmentApplication::Stale
    );
    assert!(record.applied_decisions().is_empty());
    assert_eq!(record.invalidated_decisions().len(), 1);
    assert!(record.unmet_conditions().contains(&fixture.condition_a));
}

// ---------------------------------------------------------------------------
// Post-completion stale handling
// ---------------------------------------------------------------------------

fn completed_record(manifest: &TargetManifest, evidence_id: EvidenceId) -> SupervisionRecord {
    let ids = ids(project());
    let contract = contract(project());
    let mut record = SupervisionRecord::new(&contract);
    let profile = completion_profile(project());
    for (condition, evidence_id) in [
        (ids.condition_a, evidence_id),
        (ids.condition_b, ids.evidence_b),
    ] {
        let request = assessment_request(project(), condition, &profile, vec![evidence_id]);
        let result =
            assessment_result(&request, ConditionVerdict::Met, request.evidence().to_vec());
        assert_eq!(
            record
                .apply_assessment(&result, ProfileThresholds::normal_llm())
                .expect("apply"),
            herness_supervision::state::AssessmentApplication::Applied
        );
    }
    let snapshot = CompletionSnapshot::new(
        contract.conditions().condition_version(),
        manifest.version(),
        contract.profile(),
        contract.consent(),
        contract
            .conditions()
            .checks()
            .iter()
            .map(|check| check.id())
            .collect(),
        vec![evidence_id],
        manifest.manifest_digest().expect("digest"),
        now(),
    )
    .expect("snapshot");
    record.complete(snapshot).expect("complete");
    record
}

#[test]
fn post_completion_related_change_marks_the_snapshot_stale_without_resuming() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"completed source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);
    let evidence = evidence_for(
        &manifest,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );
    let mut record = completed_record(&manifest, fixture.evidence_a);
    assert_eq!(record.state(), SupervisionState::Completed);
    assert!(record.run_group().runs().is_empty());

    workspace.set("src/lib.rs", b"edited after completion");
    let current = capture(&workspace, 2, &["src/lib.rs"]);
    let freshness = service(&workspace)
        .freshness()
        .evaluate_completion(&record, &current, std::slice::from_ref(&evidence))
        .expect("completion freshness");
    let CompletionFreshness::Stale(report) = freshness else {
        panic!("expected a stale completion");
    };
    assert!(!report.auto_resume());
    assert!(report.affected_evidence().contains(&fixture.evidence_a));
    report.apply(&mut record).expect("mark stale");

    assert_eq!(record.state(), SupervisionState::Completed);
    assert!(record.completion().is_some());
    assert!(record.completion_stale().is_some());
    assert!(record.run_group().runs().is_empty());
    assert_eq!(
        record.completion_stale().expect("stale").changed_paths(),
        &["src/lib.rs".to_owned()]
    );
}

// ---------------------------------------------------------------------------
// H1 permission boundary and evidence reuse
// ---------------------------------------------------------------------------

#[test]
fn allowed_h1_operation_records_pass_evidence_and_denied_or_ask_produces_none() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"source");

    let allow_policy = policy_with("allow");
    let calls = Rc::new(Cell::new(0));
    let executor = FakeExecutor::new(Rc::clone(&calls), pass_execution());
    let grant = GrantScope::for_run(project(), &allow_policy);
    let mut allow = GatewayVerification::new(
        ToolGateway::new(executor),
        allow_policy.clone(),
        grant,
        EvaluationContext::new("run the fixture check", vec![]),
    );
    let mut store = MemoryEvidenceStore::default();
    let service = service(&workspace);
    let recorded = service
        .verify(
            &mut store,
            plan(fixture, 1),
            &bash_operation(&allow_policy, "cargo test -p fixture-app --locked"),
            &mut allow,
        )
        .expect("verify");
    let record = recorded.recorded().expect("recorded");
    assert_eq!(record.status(), CheckStatus::Pass);
    assert_eq!(calls.get(), 1);
    assert_eq!(store.records.len(), 1);

    for (effect, expected_calls) in [("deny", 0usize), ("ask", 0usize)] {
        let policy = policy_with(effect);
        let calls = Rc::new(Cell::new(0));
        let executor = FakeExecutor::new(Rc::clone(&calls), pass_execution());
        let grant = GrantScope::for_run(project(), &policy);
        let mut boundary = GatewayVerification::new(
            ToolGateway::new(executor),
            policy.clone(),
            grant,
            EvaluationContext::new("run the fixture check", vec![]),
        );
        let mut store = MemoryEvidenceStore::default();
        let disposition = service
            .verify(
                &mut store,
                plan(fixture, 1),
                &bash_operation(&policy, "cargo test -p fixture-app --locked"),
                &mut boundary,
            )
            .expect("verify");
        assert_eq!(calls.get(), expected_calls, "{effect} must not execute");
        assert!(store.records.is_empty(), "{effect} must not store evidence");
        match (effect, disposition) {
            ("deny", VerificationDisposition::Denied { .. }) => {}
            ("ask", VerificationDisposition::AwaitingHuman { .. }) => {}
            (effect, other) => panic!("unexpected {effect} disposition: {other:?}"),
        }
    }
}

#[test]
fn child_ci_and_human_evidence_reuse_requires_the_same_five_items() {
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);
    let mut store = MemoryEvidenceStore::default();
    let service = service(&workspace);

    for (acquirer, evidence_id, check_id, condition_id, sequence, observer) in [
        (
            EvidenceAcquirer::ChildAgent,
            fixture.evidence_a,
            fixture.check_a,
            fixture.condition_a,
            1,
            None,
        ),
        (
            EvidenceAcquirer::Ci,
            fixture.evidence_b,
            fixture.check_b,
            fixture.condition_b,
            2,
            None,
        ),
        (
            EvidenceAcquirer::Human,
            EvidenceId::new(project()),
            fixture.check_a,
            fixture.condition_a,
            3,
            Some("fixture-reviewer"),
        ),
    ] {
        let mut record = EvidenceRecord::new(
            evidence_id,
            fixture.supervision,
            Some(condition_id),
            Some(check_id),
            acquirer,
            VerificationOperation::equivalent("fixture observation").expect("operation"),
            EvidenceOutcome::new(
                Some(0),
                None,
                false,
                false,
                "observed the recorded output: 12 passed; 0 failed",
            )
            .expect("outcome"),
            manifest.target_scope().expect("target"),
            EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
            CheckStatus::Pass,
            sequence,
            now(),
        )
        .expect("record");
        if let Some(observer) = observer {
            record = record.with_observer(observer);
        }
        service
            .store_reused(&mut store, record)
            .expect("validated reuse");
    }
    assert_eq!(store.records.len(), 3);

    let human_missing_observer = EvidenceRecord::new(
        fixture.evidence_a,
        fixture.supervision,
        Some(fixture.condition_a),
        Some(fixture.check_a),
        EvidenceAcquirer::Human,
        VerificationOperation::equivalent("fixture observation").expect("operation"),
        EvidenceOutcome::new(Some(0), None, false, false, "observed 12 passed").expect("outcome"),
        manifest.target_scope().expect("target"),
        EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
        CheckStatus::Pass,
        4,
        now(),
    )
    .expect("record");
    assert!(matches!(
        service.store_reused(&mut MemoryEvidenceStore::default(), human_missing_observer),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));

    let bare_child = EvidenceRecord::new(
        EvidenceId::new(project()),
        fixture.supervision,
        Some(fixture.condition_a),
        Some(fixture.check_a),
        EvidenceAcquirer::ChildAgent,
        VerificationOperation::command("cargo test -p fixture-app --locked").expect("command"),
        EvidenceOutcome::new(Some(0), None, false, false, "success").expect("outcome"),
        manifest.target_scope().expect("target"),
        EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
        CheckStatus::Pass,
        5,
        now(),
    )
    .expect("record");
    assert!(matches!(
        service.store_reused(&mut MemoryEvidenceStore::default(), bare_child),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));
}

// ---------------------------------------------------------------------------
// Durable store: CAS, idempotency, rollback, cross-project, reopen
// ---------------------------------------------------------------------------

struct StoreHarness {
    _temp: TempDir,
    config: StoreConfig,
}

impl StoreHarness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let config = StoreConfig::new(temp.path().join("app-data")).expect("config");
        Self {
            _temp: temp,
            config,
        }
    }

    fn open(&self) -> Store {
        Store::open(self.config.clone()).expect("open store")
    }
}

#[test]
fn store_cas_conflicts_duplicate_results_and_cross_project_references_are_rejected() {
    let harness = StoreHarness::new();
    let mut store = harness.open();
    let fixture = ids(project());
    let record = record(project());
    assert_eq!(
        store
            .compare_and_swap(project(), fixture.supervision, None, &record)
            .expect("create"),
        1
    );
    assert!(matches!(
        store.compare_and_swap(project(), fixture.supervision, None, &record),
        Err(SupervisionError::RevisionConflict { .. })
    ));
    assert!(matches!(
        store.compare_and_swap(project(), fixture.supervision, Some(2), &record),
        Err(SupervisionError::RevisionConflict { .. })
    ));

    let request = SupervisionRequest::new(
        fixture.request,
        fixture.supervision,
        SupervisionCommand::Start,
        1,
    )
    .expect("request");
    let run = RunId::new(project());
    let result = execute_command(&mut store, request, |current| {
        let mut next = current.clone();
        next.begin_run(run)?;
        Ok(next)
    })
    .expect("start");
    assert_eq!(result.revision(), 2);
    let duplicate = execute_command(&mut store, request, |_| {
        panic!("duplicate request must not mutate")
    })
    .expect("duplicate");
    assert_eq!(duplicate, result);
    assert_eq!(
        store
            .load(project(), fixture.supervision)
            .expect("load")
            .expect("record")
            .revision(),
        2
    );

    store
        .record_command_result(&result)
        .expect("identical result is idempotent");
    let different = herness_supervision::command::CommandResult::new(
        fixture.request,
        project(),
        fixture.supervision,
        SupervisionCommand::Stop,
        result.revision(),
        result.state(),
        result.reason().clone(),
    )
    .expect("different result");
    assert!(matches!(
        store.record_command_result(&different),
        Err(SupervisionError::DuplicateResultConflict { .. })
    ));

    let other_fixture = ids(other_project());
    assert!(matches!(
        store.load(project(), other_fixture.supervision),
        Err(SupervisionError::CrossProjectReference { .. })
    ));
    assert!(matches!(
        store.list_for_supervision(project(), other_fixture.supervision),
        Err(SupervisionError::CrossProjectReference { .. })
    ));
    assert!(matches!(
        store.get(project(), other_fixture.evidence_a),
        Err(SupervisionError::CrossProjectReference { .. })
    ));
    assert!(matches!(
        store.compare_and_swap(project(), other_fixture.supervision, None, &record,),
        Err(SupervisionError::CrossProjectReference { .. })
    ));
}

#[test]
fn store_fault_rolls_back_evidence_and_state_without_a_half_written_command() {
    let harness = StoreHarness::new();
    let mut store = harness.open();
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);
    let evidence = evidence_for(
        &manifest,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );

    store.set_commit_fault(Some(CommitFault::BeforeCommit));
    assert!(store.append(evidence.clone()).is_err());
    store.set_commit_fault(None);
    assert!(
        store
            .evidence_record(project(), fixture.evidence_a)
            .expect("read")
            .is_none()
    );
    store
        .append(evidence.clone())
        .expect("append after rollback");

    let record = record(project());
    store
        .compare_and_swap(project(), fixture.supervision, None, &record)
        .expect("create");
    let request = SupervisionRequest::new(
        fixture.request,
        fixture.supervision,
        SupervisionCommand::Start,
        1,
    )
    .expect("request");
    let run = RunId::new(project());
    store.set_commit_fault(Some(CommitFault::BeforeCommit));
    assert!(
        execute_command(&mut store, request, |current| {
            let mut next = current.clone();
            next.begin_run(run)?;
            Ok(next)
        })
        .is_err()
    );
    store.set_commit_fault(None);
    assert_eq!(
        store
            .load(project(), fixture.supervision)
            .expect("load")
            .expect("record")
            .state(),
        SupervisionState::Ready
    );
    assert!(
        store
            .command_result(fixture.request)
            .expect("result")
            .is_none()
    );
    execute_command(&mut store, request, |current| {
        let mut next = current.clone();
        next.begin_run(run)?;
        Ok(next)
    })
    .expect("retry after rollback");
    assert_eq!(
        store
            .load(project(), fixture.supervision)
            .expect("load")
            .expect("record")
            .state(),
        SupervisionState::Running
    );
}

#[test]
fn failed_schema_seven_migration_rolls_back_to_schema_six() {
    let harness = StoreHarness::new();
    let schema_six = open_at_schema_version(harness.config.clone(), 6).expect("schema six");
    drop(schema_six);
    let error = open_with_migration_fault(
        harness.config.clone(),
        MigrationFault::AfterStatements {
            version: 7,
            statements: 1,
        },
    )
    .expect_err("migration fault");
    assert!(matches!(
        error,
        herness_store::StoreError::InjectedFault {
            point: "migration-after-statement"
        }
    ));
    // Opening at schema six succeeds only when every 0007 statement, including
    // the version update, rolled back.
    drop(open_at_schema_version(harness.config.clone(), 6).expect("rolled back"));
    drop(harness.open());
}

#[test]
fn store_reopen_reads_evidence_supervision_and_command_results() {
    let harness = StoreHarness::new();
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);
    let evidence = evidence_for(
        &manifest,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );

    let mut store = harness.open();
    store.append(evidence.clone()).expect("append evidence");
    let record = record(project());
    store
        .compare_and_swap(project(), fixture.supervision, None, &record)
        .expect("create record");
    let request = SupervisionRequest::new(
        fixture.request,
        fixture.supervision,
        SupervisionCommand::Start,
        1,
    )
    .expect("request");
    let run = RunId::new(project());
    let result = execute_command(&mut store, request, |current| {
        let mut next = current.clone();
        next.begin_run(run)?;
        Ok(next)
    })
    .expect("start");
    drop(store);

    let store = harness.open();
    assert_eq!(
        store
            .evidence_record(project(), fixture.evidence_a)
            .expect("read evidence"),
        Some(evidence.clone())
    );
    assert_eq!(
        store
            .list_for_supervision(project(), fixture.supervision)
            .expect("list evidence"),
        vec![evidence]
    );
    let reopened = store
        .load(project(), fixture.supervision)
        .expect("load record")
        .expect("record");
    assert_eq!(reopened.revision(), result.revision());
    assert_eq!(reopened.state(), SupervisionState::Running);
    assert_eq!(
        store
            .command_result(fixture.request)
            .expect("command result"),
        Some(result)
    );
}

#[test]
fn store_rejects_a_different_evidence_value_for_the_same_id() {
    let harness = StoreHarness::new();
    let mut store = harness.open();
    let fixture = ids(project());
    let workspace = SharedWorkspace::new(None);
    workspace.track("src/lib.rs", InputOrigin::Tracked, b"source");
    let manifest = capture(&workspace, 1, &["src/lib.rs"]);
    let record = evidence_for(
        &manifest,
        fixture,
        fixture.evidence_a,
        fixture.check_a,
        fixture.condition_a,
        CheckStatus::Pass,
        1,
    );
    store.append(record.clone()).expect("append");
    assert_eq!(store.append(record.clone()).expect("idempotent"), record);
    let different = EvidenceRecord::new(
        fixture.evidence_a,
        fixture.supervision,
        Some(fixture.condition_a),
        Some(fixture.check_a),
        EvidenceAcquirer::ChildAgent,
        VerificationOperation::command("cargo clippy -p fixture-app --locked").expect("command"),
        EvidenceOutcome::new(Some(1), None, false, false, "clippy reported one warning")
            .expect("outcome"),
        manifest.target_scope().expect("target"),
        EvidenceScope::new(vec!["src/lib.rs".to_owned()], vec![]).expect("scope"),
        CheckStatus::Fail,
        1,
        Timestamp::from_unix_millis(NOW_MILLIS + 1),
    )
    .expect("different record");
    assert!(matches!(
        store.append(different),
        Err(SupervisionError::EvidenceContractViolation { .. })
    ));
}
