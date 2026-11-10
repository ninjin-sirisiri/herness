//! Task 24 semantic and visual-quality evaluation set.
//!
//! This test binds hand-authored glossary, ADR, spec and plan baselines to:
//!
//! * per-source-unit expected answers and reading-comprehension tasks;
//! * a deterministic, explicitly **scripted** answer-key judge (never a model);
//! * positive, negative, hold and false-stop classifications;
//! * the existing Common SDD pack structural check, when the read-only pack is
//!   present, for the fixtures whose static expectation is declared;
//! * a human-observation record and an opt-in real-evaluation approval gate.
//!
//! No provider, credential, Keychain item, login, socket or external request is
//! used. "Jev" and "Decisions" rows are scripted labels, not real-model results,
//! and the scripted rows must not be reported as model accuracy or as evidence
//! that documentation understanding improved.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use herness_desktop::html_sync::policy::{CandidateCheck, CandidateDecision, CandidateStage};
use herness_html_sync::SourceUnits;
use serde_json::{Value, json};
use tempfile::TempDir;

use support::{connect_bridge, real_pack_present};

/// Root of the Task 24 evaluation fixtures.
const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/evaluation");

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(FIXTURE_ROOT).join(relative)
}

// ---------------------------------------------------------------------------
// Methods and dispositions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Method {
    NormalLlm,
    Jev,
    Decisions,
}

impl Method {
    const ALL: [Self; 3] = [Self::NormalLlm, Self::Jev, Self::Decisions];

    const fn id(self) -> &'static str {
        match self {
            Self::NormalLlm => "normal_llm",
            Self::Jev => "jev",
            Self::Decisions => "decisions",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::NormalLlm => "Normal LLM",
            Self::Jev => "Jev",
            Self::Decisions => "Decisions",
        }
    }

    const fn scripted_confidence(self) -> Option<f64> {
        match self {
            Self::NormalLlm => None,
            Self::Jev | Self::Decisions => Some(0.99),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Sync,
    Reject,
    Hold,
}

impl Disposition {
    fn parse(value: &str) -> Self {
        match value {
            "sync" => Self::Sync,
            "reject" => Self::Reject,
            "hold" => Self::Hold,
            other => panic!("unknown disposition {other:?}"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Reject => "reject",
            Self::Hold => "hold",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    Right,
    Wrong,
    Hold,
    FalseStop,
}

impl Classification {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Right => "right",
            Self::Wrong => "wrong",
            Self::Hold => "hold",
            Self::FalseStop => "false-stop",
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest model.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Manifest {
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Clone)]
struct Fixture {
    id: String,
    document_kind: String,
    data_kinds: Vec<String>,
    source_path: String,
    pack_path: String,
    positive_path: String,
    alternate_positive_path: Option<String>,
    source_digest: String,
    units: Vec<UnitAnswers>,
    reading_tasks: Vec<ReadingTask>,
    cases: Vec<Case>,
}

#[derive(Debug, Clone)]
struct UnitAnswers {
    id: String,
    kind: String,
    answers: Vec<Answer>,
}

#[derive(Debug, Clone)]
struct Answer {
    text: String,
    scope: String,
}

#[derive(Debug, Clone)]
struct ReadingTask {
    id: String,
    question: String,
    unit: String,
    answer: String,
}

#[derive(Debug, Clone)]
struct Case {
    id: String,
    path: String,
    expected: Disposition,
    kind: String,
    hazard: Option<String>,
    forbidden_visible: Vec<String>,
    forbidden_html: Vec<String>,
    stale: bool,
    injection: bool,
    support_unmet: bool,
    scripted_over_strict: bool,
    pack_expectation: String,
    note: Option<String>,
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("manifest field {key:?} is missing or not a string: {value}"))
}

fn optional_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .unwrap_or_else(|| panic!("{key} contains a non-string"))
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn load_manifest() -> Manifest {
    let text = fs::read_to_string(fixture_path("manifest.json")).expect("evaluation manifest");
    let value: Value = serde_json::from_str(&text).expect("manifest JSON");
    assert_eq!(required_str(&value, "schema"), "h3-evaluation-set-v1");
    assert_eq!(value.get("version").and_then(Value::as_u64), Some(1));

    let fixtures = value
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures")
        .iter()
        .map(|fixture| {
            let units = fixture
                .get("units")
                .and_then(Value::as_array)
                .expect("units")
                .iter()
                .map(|unit| UnitAnswers {
                    id: required_str(unit, "id").to_owned(),
                    kind: required_str(unit, "kind").to_owned(),
                    answers: unit
                        .get("answers")
                        .and_then(Value::as_array)
                        .expect("answers")
                        .iter()
                        .map(|answer| Answer {
                            text: required_str(answer, "text").to_owned(),
                            scope: required_str(answer, "scope").to_owned(),
                        })
                        .collect(),
                })
                .collect();
            let reading_tasks = fixture
                .get("readingTasks")
                .and_then(Value::as_array)
                .expect("readingTasks")
                .iter()
                .map(|task| ReadingTask {
                    id: required_str(task, "id").to_owned(),
                    question: required_str(task, "question").to_owned(),
                    unit: required_str(task, "unit").to_owned(),
                    answer: required_str(task, "answer").to_owned(),
                })
                .collect();
            let cases = fixture
                .get("cases")
                .and_then(Value::as_array)
                .expect("cases")
                .iter()
                .map(|case| Case {
                    id: required_str(case, "id").to_owned(),
                    path: required_str(case, "path").to_owned(),
                    expected: Disposition::parse(required_str(case, "expected")),
                    kind: required_str(case, "kind").to_owned(),
                    hazard: optional_str(case, "hazard"),
                    forbidden_visible: string_array(case, "forbiddenVisible"),
                    forbidden_html: string_array(case, "forbiddenHtml"),
                    stale: bool_field(case, "stale"),
                    injection: bool_field(case, "injection"),
                    support_unmet: bool_field(case, "supportUnmet"),
                    scripted_over_strict: bool_field(case, "scriptedOverStrict"),
                    pack_expectation: required_str(case, "packExpectation").to_owned(),
                    note: optional_str(case, "note"),
                })
                .collect();
            Fixture {
                id: required_str(fixture, "id").to_owned(),
                document_kind: required_str(fixture, "documentKind").to_owned(),
                data_kinds: string_array(fixture, "dataKinds"),
                source_path: required_str(fixture, "sourcePath").to_owned(),
                pack_path: required_str(fixture, "packPath").to_owned(),
                positive_path: required_str(fixture, "positivePath").to_owned(),
                alternate_positive_path: optional_str(fixture, "alternatePositivePath"),
                source_digest: required_str(fixture, "sourceDigest").to_owned(),
                units,
                reading_tasks,
                cases,
            }
        })
        .collect();

    Manifest { fixtures }
}

fn all_cases(manifest: &Manifest) -> impl Iterator<Item = (&Fixture, &Case)> {
    manifest
        .fixtures
        .iter()
        .flat_map(|fixture| fixture.cases.iter().map(move |case| (fixture, case)))
}

// ---------------------------------------------------------------------------
// Visible-text extraction for the scripted answer-key judge.
// ---------------------------------------------------------------------------

/// Removes one named element and its content. Used for template/script/style.
fn strip_named_elements(html: &str, tag: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut output = String::new();
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find(&open) {
        let start = cursor + relative;
        output.push_str(&html[cursor..start]);
        let Some(open_end_relative) = lower[start..].find('>') else {
            output.push_str(&html[start..]);
            return output;
        };
        let open_end = start + open_end_relative + 1;
        let Some(close_relative) = lower[open_end..].find(&close) else {
            output.push_str(&html[start..]);
            return output;
        };
        cursor = open_end + close_relative + close.len();
    }
    output.push_str(&html[cursor..]);
    output
}

/// Removes elements carrying `hidden`, `aria-hidden="true"` or `display:none`.
fn strip_hidden_elements(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut output = String::new();
    let mut cursor = 0;
    while let Some(relative) = html[cursor..].find('<') {
        let start = cursor + relative;
        let Some(gt_relative) = html[start..].find('>') else {
            output.push_str(&html[cursor..]);
            return output;
        };
        let gt = start + gt_relative;
        let tag_text = &html[start + 1..gt];
        if tag_text.starts_with('/') || tag_text.starts_with('!') {
            output.push_str(&html[cursor..=gt]);
            cursor = gt + 1;
            continue;
        }
        let tag_name = tag_text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let attributes = tag_text[tag_name.len()..].to_ascii_lowercase();
        let hidden = attributes.contains("hidden")
            || attributes.contains("aria-hidden=\"true\"")
            || attributes.contains("display:none")
            || attributes.contains("display: none");
        if !hidden || tag_name.is_empty() {
            output.push_str(&html[cursor..=gt]);
            cursor = gt + 1;
            continue;
        }
        if tag_text.trim_end().ends_with('/') {
            cursor = gt + 1;
            continue;
        }
        let close = format!("</{tag_name}>");
        let Some(close_relative) = lower[gt + 1..].find(&close) else {
            cursor = gt + 1;
            continue;
        };
        cursor = gt + 1 + close_relative + close.len();
    }
    output.push_str(&html[cursor..]);
    output
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

fn visible_text(html: &str) -> String {
    let without_template = strip_named_elements(html, "template");
    let without_script = strip_named_elements(&without_template, "script");
    let without_style = strip_named_elements(&without_script, "style");
    let without_hidden = strip_hidden_elements(&without_style);
    let mut text = String::new();
    let mut in_tag = false;
    for character in without_hidden.chars() {
        match character {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    decode_entities(&text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// The scripted answer-key judge.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct JudgeOutcome {
    information: &'static str,
    support: &'static str,
    usability: &'static str,
    render: &'static str,
    disposition: Disposition,
}

fn answer_present(answer: &Answer, html: &str, text: &str) -> bool {
    match answer.scope.as_str() {
        "visible" => text.contains(&answer.text),
        "html" => html.contains(&answer.text),
        other => panic!("unknown answer scope {other:?}"),
    }
}

/// Deterministic answer-key judgment. It reads exact required strings and known
/// contradictions from the fixture; it does not infer paraphrase quality.
fn scripted_judge(fixture: &Fixture, case: &Case, method: Method) -> JudgeOutcome {
    let html = fs::read_to_string(fixture_path(&case.path)).expect("candidate HTML");
    let text = visible_text(&html);

    let information = if case.stale || case.injection {
        "insufficient"
    } else if case.scripted_over_strict {
        "unmet"
    } else {
        let missing = fixture.units.iter().flat_map(|unit| {
            unit.answers
                .iter()
                .filter(|answer| !answer_present(answer, &html, &text))
        });
        let forbidden = case
            .forbidden_visible
            .iter()
            .any(|value| text.contains(value))
            || case.forbidden_html.iter().any(|value| html.contains(value));
        if missing.count() > 0 || forbidden {
            "unmet"
        } else {
            "met"
        }
    };
    let support = if case.support_unmet { "unmet" } else { "met" };
    let usability = "met";
    let render = "met";

    let disposition = if [information, support, usability, render]
        .iter()
        .any(|verdict| *verdict == "unmet")
    {
        Disposition::Reject
    } else if [information, support, usability, render]
        .iter()
        .any(|verdict| *verdict == "insufficient")
    {
        Disposition::Hold
    } else {
        Disposition::Sync
    };

    // Jev/Decisions rows carry a scripted probability only. It never changes
    // the scripted verdict and is not a real provider distribution.
    let _ = method.scripted_confidence();

    JudgeOutcome {
        information,
        support,
        usability,
        render,
        disposition,
    }
}

fn classify(expected: Disposition, actual: Disposition) -> Classification {
    match actual {
        Disposition::Hold => Classification::Hold,
        Disposition::Sync => {
            if expected == Disposition::Sync {
                Classification::Right
            } else {
                Classification::Wrong
            }
        }
        Disposition::Reject => {
            if expected == Disposition::Sync {
                Classification::FalseStop
            } else {
                Classification::Right
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CaseResult {
    fixture_id: String,
    case_id: String,
    case_kind: String,
    method: Method,
    expected: Disposition,
    actual: Disposition,
    classification: Classification,
    outcome: JudgeOutcome,
    note: Option<String>,
}

fn run_scripted_method(manifest: &Manifest, method: Method) -> Vec<CaseResult> {
    all_cases(manifest)
        .map(|(fixture, case)| {
            let outcome = scripted_judge(fixture, case, method);
            CaseResult {
                fixture_id: fixture.id.clone(),
                case_id: case.id.clone(),
                case_kind: case.kind.clone(),
                method,
                expected: case.expected,
                actual: outcome.disposition,
                classification: classify(case.expected, outcome.disposition),
                outcome,
                note: case.note.clone(),
            }
        })
        .collect()
}

fn counts(results: &[CaseResult]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::from([
        ("class.right", 0),
        ("class.wrong", 0),
        ("class.hold", 0),
        ("class.false-stop", 0),
        ("actual.sync", 0),
        ("actual.reject", 0),
        ("actual.hold", 0),
    ]);
    for result in results {
        *counts
            .get_mut(format!("class.{}", result.classification.as_str()).as_str())
            .expect("classification") += 1;
        *counts
            .get_mut(format!("actual.{}", result.actual.as_str()).as_str())
            .expect("disposition") += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Manifest integrity and fixture tests.
// ---------------------------------------------------------------------------

#[test]
fn the_evaluation_set_binds_every_fixture_unit_and_reading_task() {
    let manifest = load_manifest();
    assert_eq!(
        manifest.fixtures.len(),
        4,
        "one glossary, ADR, spec and plan"
    );

    let mut fixture_ids = BTreeSet::new();
    let mut case_ids = BTreeSet::new();
    let mut task_ids = BTreeSet::new();
    let mut hazards = BTreeSet::new();
    let mut document_kinds = BTreeSet::new();

    for fixture in &manifest.fixtures {
        assert!(
            fixture_ids.insert(fixture.id.clone()),
            "duplicate fixture id"
        );
        document_kinds.insert(fixture.document_kind.as_str());
        assert!(
            fixture.id.starts_with("eval-"),
            "fixture ids are stable eval-* values: {}",
            fixture.id
        );
        assert!(!fixture.units.is_empty(), "{} units", fixture.id);
        assert_eq!(
            fixture.data_kinds,
            ["text"],
            "{} is a text-only semantic fixture",
            fixture.id
        );
        assert!(!fixture.reading_tasks.is_empty(), "{} tasks", fixture.id);
        assert!(
            fixture_path(&fixture.source_path).is_file(),
            "{} source exists",
            fixture.source_path
        );
        assert!(
            fixture_path(&fixture.positive_path).is_file(),
            "{} positive exists",
            fixture.positive_path
        );
        let positive =
            fs::read_to_string(fixture_path(&fixture.positive_path)).expect("positive HTML");
        let positive_text = visible_text(&positive);
        for unit in &fixture.units {
            assert!(!unit.answers.is_empty(), "{} has answers", unit.id);
            for answer in &unit.answers {
                assert!(
                    answer_present(answer, &positive, &positive_text),
                    "{} unit {} answer {:?} is missing from the positive",
                    fixture.id,
                    unit.id,
                    answer.text
                );
            }
        }
        let mut positive_cases = 0;
        for case in &fixture.cases {
            assert!(case_ids.insert(case.id.clone()), "duplicate case id");
            assert!(
                case.id.starts_with(&format!("{}/", fixture.id)),
                "case {} belongs to fixture {}",
                case.id,
                fixture.id
            );
            assert!(
                fixture_path(&case.path).is_file(),
                "case path exists: {}",
                case.path
            );
            assert!(
                matches!(case.pack_expectation.as_str(), "allow" | "deny" | "either"),
                "{} pack expectation",
                case.id
            );
            if let Some(hazard) = &case.hazard {
                hazards.insert(hazard.clone());
            }
            if case.kind == "positive" {
                positive_cases += 1;
                assert_eq!(case.expected, Disposition::Sync);
                assert_eq!(case.path, fixture.positive_path);
            } else if case.kind == "false-stop-probe" {
                assert_eq!(case.expected, Disposition::Sync);
                assert_eq!(
                    Some(case.path.clone()),
                    fixture.alternate_positive_path,
                    "false-stop probe uses the alternate correct reconstruction"
                );
            } else {
                assert_ne!(
                    case.expected,
                    Disposition::Sync,
                    "negative case {} must not be expected to sync",
                    case.id
                );
            }
        }
        assert_eq!(positive_cases, 1, "{} has one primary positive", fixture.id);

        for task in &fixture.reading_tasks {
            assert!(task_ids.insert(task.id.clone()), "duplicate task id");
            assert!(
                !task.question.trim().is_empty(),
                "{} has a question",
                task.id
            );
            assert!(
                fixture.units.iter().any(|unit| unit.id == task.unit),
                "task {} references a real source unit",
                task.id
            );
            let source =
                fs::read_to_string(fixture_path(&fixture.source_path)).expect("source Markdown");
            assert!(
                source.contains(&task.answer),
                "task {} answer appears in the baseline: {}",
                task.id,
                task.answer
            );
            assert!(
                positive_text.contains(&task.answer),
                "task {} answer is findable in the positive: {}",
                task.id,
                task.answer
            );
        }
    }

    assert_eq!(
        document_kinds,
        BTreeSet::from(["adr", "glossary", "plan", "spec"]),
        "the four representative document kinds"
    );
    let required_hazards = [
        "caveat",
        "negation",
        "threshold",
        "permission",
        "code",
        "link",
        "fake-edge-value",
        "hidden-information",
        "stale-evidence",
        "injection",
    ];
    for hazard in required_hazards {
        assert!(
            hazards.contains(hazard),
            "the evaluation set must include the {hazard} negative"
        );
    }
}

// ---------------------------------------------------------------------------
// Scripted contract, classification and per-fixture results.
// ---------------------------------------------------------------------------

#[test]
fn scripted_contract_has_no_wrong_sync_and_counts_holds_and_false_stops() {
    let manifest = load_manifest();

    let mut all_wrong = 0;
    for method in Method::ALL {
        let results = run_scripted_method(&manifest, method);
        let counted = counts(&results);
        assert_eq!(
            counted["class.wrong"],
            0,
            "{} has a wrong sync",
            method.id()
        );
        all_wrong += counted["class.wrong"];
        assert!(
            counted["class.right"] > 0,
            "{} has a right result",
            method.id()
        );
        assert!(
            counted["class.hold"] > 0,
            "{} counts holds separately",
            method.id()
        );
        assert!(
            counted["class.false-stop"] > 0,
            "{} counts false stops separately",
            method.id()
        );
        assert_eq!(
            counted["class.right"]
                + counted["class.wrong"]
                + counted["class.hold"]
                + counted["class.false-stop"],
            results.len(),
            "{} classifies every case exactly once",
            method.id()
        );

        // The primary positive must succeed under the scripted contract.
        assert!(
            results.iter().any(|result| {
                result.case_kind == "positive"
                    && result.actual == Disposition::Sync
                    && result.classification == Classification::Right
            }),
            "{} must sync at least one correct reconstruction",
            method.id()
        );
        // Every ordinary positive is treated as correct by this script.
        for result in results
            .iter()
            .filter(|result| result.case_kind == "positive")
        {
            assert_eq!(
                result.actual,
                Disposition::Sync,
                "{} positive {} was not synced",
                method.id(),
                result.case_id
            );
        }
        // A negative or expected-hold case must never be synced.
        for result in results
            .iter()
            .filter(|result| result.expected != Disposition::Sync)
        {
            assert_ne!(
                result.actual,
                Disposition::Sync,
                "{} negative {} was wrongly synced",
                method.id(),
                result.case_id
            );
        }
        // The diagnostic over-strict probe is counted as a false stop.
        let probe = results
            .iter()
            .find(|result| result.case_kind == "false-stop-probe")
            .expect("false-stop probe");
        assert_eq!(probe.actual, Disposition::Reject);
        assert_eq!(probe.classification, Classification::FalseStop);
        // The known stale and injection cases are conservative holds.
        for case_id in [
            "eval-adr-001/stale",
            "eval-glossary-001/injection",
            "eval-plan-001/injection",
        ] {
            let result = results
                .iter()
                .find(|result| result.case_id == case_id)
                .unwrap_or_else(|| panic!("{case_id} exists"));
            assert_eq!(result.actual, Disposition::Hold, "{case_id} must be a hold");
            assert_eq!(result.classification, Classification::Hold);
        }
        assert_eq!(counted["actual.sync"], 4, "{} scripted syncs", method.id());
        assert_eq!(
            counted["actual.reject"],
            20,
            "{} scripted rejects",
            method.id()
        );
        assert_eq!(counted["class.hold"], 3, "{} scripted holds", method.id());
        assert_eq!(
            counted["class.false-stop"],
            1,
            "{} scripted false stops",
            method.id()
        );
        assert_eq!(counted["class.right"], 23, "{} scripted right", method.id());

        println!(
            "scripted-method method={} label={} right={} wrong={} hold={} false-stop={} sync={} reject={} external-requests=0",
            method.id(),
            method.label(),
            counted["class.right"],
            counted["class.wrong"],
            counted["class.hold"],
            counted["class.false-stop"],
            counted["actual.sync"],
            counted["actual.reject"]
        );
        for result in &results {
            println!(
                "scripted-case method={} fixture={} case={} kind={} expected={} actual={} classification={} information={} support={} usability={} render={} note={}",
                result.method.id(),
                result.fixture_id,
                result.case_id,
                result.case_kind,
                result.expected.as_str(),
                result.actual.as_str(),
                result.classification.as_str(),
                result.outcome.information,
                result.outcome.support,
                result.outcome.usability,
                result.outcome.render,
                result.note.as_deref().unwrap_or("")
            );
        }
    }
    assert_eq!(all_wrong, 0, "no method may wrongly sync a negative");

    // The fixture IDs and their expected/actual results are reported above as
    // stable records. A compact lookup catches accidental ID drift.
    let expected_ids = [
        "eval-glossary-001/positive",
        "eval-glossary-001/avoid-term",
        "eval-glossary-001/permission",
        "eval-glossary-001/hidden",
        "eval-glossary-001/injection",
        "eval-adr-001/positive",
        "eval-adr-001/negation",
        "eval-adr-001/caveat",
        "eval-adr-001/threshold",
        "eval-adr-001/code",
        "eval-adr-001/link",
        "eval-adr-001/fake-edge",
        "eval-adr-001/stale",
        "eval-spec-001/positive",
        "eval-spec-001/negation",
        "eval-spec-001/permission",
        "eval-spec-001/viewport",
        "eval-spec-001/code",
        "eval-spec-001/link",
        "eval-spec-001/table",
        "eval-plan-001/positive",
        "eval-plan-001/order",
        "eval-plan-001/hidden",
        "eval-plan-001/threshold",
        "eval-plan-001/fake-value",
        "eval-plan-001/injection",
        "eval-plan-001/false-stop-probe",
    ];
    let actual_ids = all_cases(&manifest)
        .map(|(_, case)| case.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(actual_ids, expected_ids);
}

// ---------------------------------------------------------------------------
// Optional real pack structural checks.
// ---------------------------------------------------------------------------

struct PackProject {
    _temp: TempDir,
    root: PathBuf,
}

fn prepare_pack_project(manifest: &Manifest) -> PackProject {
    let temp = TempDir::new().expect("temporary pack project");
    let root = temp.path().join("project");
    fs::create_dir_all(root.join("docs/sdd/assets")).expect("project directories");
    fs::write(
        root.join("docs/sdd/assets/sdd.css"),
        "body { color: #111; background: #fff; }\n",
    )
    .expect("CSS");
    for fixture in &manifest.fixtures {
        let bytes = fs::read(fixture_path(&fixture.source_path)).expect("source bytes");
        let destination = root.join(&fixture.pack_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).expect("source parent");
        }
        fs::write(destination, bytes).expect("write source");
    }
    PackProject { _temp: temp, root }
}

fn pack_decision_name(check: &CandidateCheck) -> &'static str {
    match check.decision() {
        CandidateDecision::Allow => "allow",
        CandidateDecision::Deny => "deny",
    }
}

#[test]
fn real_pack_and_source_units_bind_the_fixture_expectations() {
    if !real_pack_present() {
        eprintln!(
            "skipped real pack checks: {} has no scripts/html-docs",
            support::REAL_PACK_ROOT
        );
        return;
    }
    let manifest = load_manifest();
    let project = prepare_pack_project(&manifest);
    let bridge = connect_bridge(&project.root);

    for fixture in &manifest.fixtures {
        let source = fs::read(fixture_path(&fixture.source_path)).expect("source bytes");
        let inputs = BTreeMap::from([(fixture.pack_path.clone(), source.clone())]);
        let value = bridge
            .source_units(&fixture.pack_path, &inputs)
            .expect("real source-units");
        let units = SourceUnits::from_policy(&value).expect("parsed source units");
        assert_eq!(units.status(), "complete", "{} complete scan", fixture.id);
        assert_eq!(units.contract(), "semantic-v1");
        assert_eq!(
            format!("sha256:{}", units.source_digest()),
            fixture.source_digest,
            "{} source digest",
            fixture.id
        );
        assert_eq!(
            units
                .units()
                .iter()
                .map(|unit| (unit.id().to_owned(), unit.kind().to_owned()))
                .collect::<Vec<_>>(),
            fixture
                .units
                .iter()
                .map(|unit| (unit.id.clone(), unit.kind.clone()))
                .collect::<Vec<_>>(),
            "{} source-unit ids and kinds",
            fixture.id
        );
        assert!(units.unsupported().is_empty(), "{} unsupported", fixture.id);

        let positive =
            fs::read_to_string(fixture_path(&fixture.positive_path)).expect("positive HTML");
        let positive_text = visible_text(&positive);
        for unit in &fixture.units {
            for answer in &unit.answers {
                assert!(
                    answer_present(answer, &positive, &positive_text),
                    "{} {} {:?}",
                    fixture.id,
                    unit.id,
                    answer.text
                );
            }
        }
        for task in &fixture.reading_tasks {
            assert!(
                fs::read_to_string(fixture_path(&fixture.source_path))
                    .expect("source text")
                    .contains(&task.answer),
                "{} task {} answer is in the baseline",
                fixture.id,
                task.id
            );
            assert!(
                positive_text.contains(&task.answer),
                "{} task {} answer is findable",
                fixture.id,
                task.id
            );
        }

        for case in &fixture.cases {
            let html = fs::read_to_string(fixture_path(&case.path)).expect("candidate HTML");
            let companion = Path::new(&fixture.pack_path)
                .with_extension("html")
                .to_string_lossy()
                .into_owned();
            fs::write(project.root.join(&companion), html.as_bytes()).expect("candidate file");
            let check_inputs = BTreeMap::from([
                (fixture.pack_path.clone(), source.clone()),
                (companion, html.as_bytes().to_vec()),
            ]);
            let check = bridge
                .candidate_check(
                    &fixture.pack_path,
                    CandidateStage::Structural,
                    None,
                    &check_inputs,
                )
                .expect("real structural candidate-check");
            assert_eq!(check.stage(), "structural");
            assert!(!check.final_pass(), "structural is never a final pass");
            match case.pack_expectation.as_str() {
                "allow" => assert_eq!(
                    pack_decision_name(&check),
                    "allow",
                    "{} must be structurally allowed by the real pack; violations: {:?}",
                    case.id,
                    check.violations()
                ),
                "deny" => assert_eq!(
                    pack_decision_name(&check),
                    "deny",
                    "{} must be structurally denied by the real pack",
                    case.id
                ),
                "either" => {}
                other => panic!("unknown pack expectation {other}"),
            }
            println!(
                "pack-case fixture={} case={} expectation={} decision={} violations={:?}",
                fixture.id,
                case.id,
                case.pack_expectation,
                pack_decision_name(&check),
                check
                    .violations()
                    .iter()
                    .map(|finding| finding.code())
                    .collect::<Vec<_>>()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Human observation and real-evaluation approval records.
// ---------------------------------------------------------------------------

#[test]
fn human_observation_and_real_evaluation_are_explicitly_not_run() {
    let manifest = load_manifest();
    let value: Value =
        serde_json::from_str(&fs::read_to_string(fixture_path("manifest.json")).expect("manifest"))
            .expect("manifest JSON");

    let human = value.get("humanObservation").expect("humanObservation");
    assert_eq!(required_str(human, "status"), "not_run");
    let fields = string_array(human, "fields");
    for required in [
        "documentVersion.sourceDigest",
        "observer.name",
        "wrongAnswers",
        "durationSeconds",
        "difficultyNotes",
    ] {
        assert!(
            fields.iter().any(|field| field == required),
            "the human record can store {required}"
        );
    }
    let record = human.get("record").expect("record");
    assert_eq!(required_str(record, "status"), "not_run");
    assert_eq!(required_str(record, "result"), "not_run");
    assert_eq!(required_str(record, "fixtureId"), "");
    assert_eq!(required_str(record, "documentKind"), "");
    assert_eq!(
        required_str(record.get("observer").expect("observer"), "name"),
        ""
    );
    assert_eq!(
        record
            .get("documentVersion")
            .and_then(|version| version.get("fixtureVersion"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(record.get("durationSeconds").is_some_and(Value::is_null));
    assert!(
        record
            .get("wrongAnswers")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert!(
        record
            .get("readingTasks")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(required_str(record, "difficultyNotes"), "");
    let human_file: Value = serde_json::from_str(
        &fs::read_to_string(fixture_path("human-observation.template.json"))
            .expect("human observation template"),
    )
    .expect("human observation JSON");
    assert_eq!(
        human_file, *record,
        "the standalone human record is the explicit not-run template"
    );

    let real = value.get("realEvaluation").expect("realEvaluation");
    assert_eq!(required_str(real, "status"), "not_run");
    assert_eq!(
        real.get("externalRequests").and_then(Value::as_u64),
        Some(0)
    );
    let template = real.get("approvalTemplate").expect("approvalTemplate");
    assert_eq!(required_str(template, "status"), "not_run");
    assert_eq!(required_str(template, "approvedBy"), "");
    assert_eq!(required_str(template, "approvedAt"), "");
    assert!(
        template
            .get("fixtures")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert!(
        template
            .get("dataKinds")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        template
            .get("requestBudget")
            .and_then(|budget| budget.get("maxRequests"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        template
            .get("retryPolicy")
            .and_then(|policy| policy.get("maxAttempts"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert!(
        template
            .get("costApproval")
            .and_then(|cost| cost.get("feeCapUsd"))
            .is_some_and(Value::is_null)
    );
    assert!(
        !template
            .get("costApproval")
            .and_then(|cost| cost.get("quotaConfirmed"))
            .and_then(Value::as_bool)
            .unwrap_or(true)
    );
    let approval_file: Value = serde_json::from_str(
        &fs::read_to_string(fixture_path("real-evaluation.approval.json"))
            .expect("real evaluation approval template"),
    )
    .expect("real evaluation approval JSON");
    assert_eq!(
        approval_file, *template,
        "the standalone approval file is the explicit not-run template"
    );
    assert_eq!(
        approval_file
            .get("externalRequests")
            .and_then(Value::as_u64),
        Some(0)
    );

    let allowed = manifest
        .fixtures
        .iter()
        .map(|fixture| fixture.id.clone())
        .collect::<BTreeSet<_>>();
    let mut transport = RecordingTransport::default();
    let expected_data_kinds = vec!["text".to_owned()];
    let refusal = run_real_evaluation(
        Some(&approval_file),
        &allowed,
        &expected_data_kinds,
        &manifest.fixtures[0..1]
            .iter()
            .map(|fixture| fixture.id.clone())
            .collect::<Vec<_>>(),
        &mut transport,
    )
    .expect_err("the not-run template must be refused");
    assert!(matches!(refusal, RunError::Refused(_)));
    assert_eq!(transport.calls.len(), 0, "no send before approval");
}

// ---------------------------------------------------------------------------
// Opt-in real-evaluation gate and runner.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct RecordingTransport {
    calls: Vec<String>,
    fail_once: BTreeSet<String>,
    failed: BTreeSet<String>,
}

impl EvaluationTransport for RecordingTransport {
    fn send(&mut self, fixture_id: &str) -> Result<(), String> {
        self.calls.push(fixture_id.to_owned());
        if self.fail_once.contains(fixture_id) && self.failed.insert(fixture_id.to_owned()) {
            return Err("scripted transient transport failure".to_owned());
        }
        Ok(())
    }
}

trait EvaluationTransport {
    fn send(&mut self, fixture_id: &str) -> Result<(), String>;
}

#[derive(Debug)]
enum RunError {
    Refused(Vec<String>),
    BudgetExceeded,
    Transport(String),
}

#[derive(Debug, Clone)]
struct Approval {
    approved_by: String,
    approved_at: String,
    connection: ConnectionApproval,
    fixtures: Vec<String>,
    data_kinds: Vec<String>,
    request_budget: RequestBudget,
    retry_policy: RetryPolicy,
    cost_approval: CostApproval,
}

#[derive(Debug, Clone)]
struct ConnectionApproval {
    provider: String,
    connection_id: String,
    endpoint_class: String,
    model: String,
}

#[derive(Debug, Clone, Copy)]
struct RequestBudget {
    max_requests: u64,
    per_fixture_max: u64,
}

#[derive(Debug, Clone)]
struct RetryPolicy {
    max_attempts: u64,
    same_connection_only: bool,
    retry_on: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct CostApproval {
    fee_cap_usd: f64,
    quota_confirmed: bool,
}

fn text_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn object_field(value: &Value, key: &str) -> Value {
    value
        .get(key)
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or(Value::Null)
}

fn validate_approval(
    value: &Value,
    allowed: &BTreeSet<String>,
    expected_data_kinds: &[String],
) -> Result<Approval, Vec<String>> {
    let mut errors = Vec::new();
    let approved_by = text_field(value, "approvedBy");
    let approved_at = text_field(value, "approvedAt");
    if approved_by.is_empty() {
        errors.push("approvedBy is required".to_owned());
    }
    if approved_at.is_empty() {
        errors.push("approvedAt is required".to_owned());
    }
    if text_field(value, "status") != "approved" {
        errors.push("status must be approved".to_owned());
    }

    let connection = object_field(value, "connection");
    let provider = text_field(&connection, "provider");
    let connection_id = text_field(&connection, "connectionId");
    let endpoint_class = text_field(&connection, "endpointClass");
    let model = text_field(&connection, "model");
    for (label, field) in [
        ("connection.provider", &provider),
        ("connection.connectionId", &connection_id),
        ("connection.endpointClass", &endpoint_class),
        ("connection.model", &model),
    ] {
        if field.is_empty() {
            errors.push(format!("{label} is required"));
        }
    }

    let fixtures = string_array(value, "fixtures");
    if fixtures.is_empty() {
        errors.push("fixtures is required".to_owned());
    }
    let mut seen = BTreeSet::new();
    for fixture in &fixtures {
        if !allowed.contains(fixture) {
            errors.push(format!("fixture {fixture:?} is not in the evaluation set"));
        }
        if !seen.insert(fixture.clone()) {
            errors.push(format!("fixture {fixture:?} is duplicated"));
        }
    }
    let data_kinds = string_array(value, "dataKinds");
    if data_kinds.is_empty() {
        errors.push("dataKinds is required".to_owned());
    }
    for kind in &data_kinds {
        if !matches!(kind.as_str(), "text" | "image") {
            errors.push(format!("data kind {kind:?} is not approved"));
        }
    }
    if data_kinds.iter().cloned().collect::<BTreeSet<_>>()
        != expected_data_kinds.iter().cloned().collect::<BTreeSet<_>>()
    {
        errors.push("dataKinds must exactly match the approved fixture data".to_owned());
    }

    let budget = object_field(value, "requestBudget");
    let max_requests = budget
        .get("maxRequests")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let per_fixture_max = budget
        .get("perFixtureMax")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if max_requests == 0 {
        errors.push("requestBudget.maxRequests must be finite and positive".to_owned());
    }
    if per_fixture_max == 0 {
        errors.push("requestBudget.perFixtureMax must be finite and positive".to_owned());
    }
    if max_requests < fixtures.len() as u64 {
        errors.push("requestBudget.maxRequests must cover every fixture".to_owned());
    }

    let retry = object_field(value, "retryPolicy");
    let max_attempts = retry
        .get("maxAttempts")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let same_connection_only = retry
        .get("sameConnectionOnly")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let retry_on = string_array(&retry, "retryOn");
    if !(1..=5).contains(&max_attempts) {
        errors.push("retryPolicy.maxAttempts must be 1..=5".to_owned());
    }
    if !same_connection_only {
        errors.push("retryPolicy must stay on the same connection".to_owned());
    }
    if retry_on.is_empty() {
        errors.push("retryPolicy.retryOn is required".to_owned());
    }

    let cost = object_field(value, "costApproval");
    let fee_cap_usd = cost.get("feeCapUsd").and_then(Value::as_f64);
    let quota_label = text_field(&cost, "quotaLabel");
    let quota_confirmed = cost
        .get("quotaConfirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !fee_cap_usd.is_some_and(|value| value.is_finite() && value >= 0.0) {
        errors.push("costApproval.feeCapUsd must be finite".to_owned());
    }
    if quota_label.is_empty() {
        errors.push("costApproval.quotaLabel is required".to_owned());
    }
    if !quota_confirmed {
        errors.push("costApproval.quotaConfirmed must be true".to_owned());
    }

    if errors.is_empty() {
        Ok(Approval {
            approved_by,
            approved_at,
            connection: ConnectionApproval {
                provider,
                connection_id,
                endpoint_class,
                model,
            },
            fixtures,
            data_kinds,
            request_budget: RequestBudget {
                max_requests,
                per_fixture_max,
            },
            retry_policy: RetryPolicy {
                max_attempts,
                same_connection_only,
                retry_on,
            },
            cost_approval: CostApproval {
                fee_cap_usd: fee_cap_usd.expect("validated fee cap"),
                quota_confirmed,
            },
        })
    } else {
        Err(errors)
    }
}

fn run_real_evaluation(
    approval: Option<&Value>,
    allowed: &BTreeSet<String>,
    expected_data_kinds: &[String],
    fixtures: &[String],
    transport: &mut dyn EvaluationTransport,
) -> Result<u64, RunError> {
    let Some(approval) = approval else {
        return Err(RunError::Refused(vec!["approval is required".to_owned()]));
    };
    let approval =
        validate_approval(approval, allowed, expected_data_kinds).map_err(RunError::Refused)?;
    if approval.fixtures != fixtures {
        return Err(RunError::Refused(vec![
            "approved fixtures do not exactly match the requested fixtures".to_owned(),
        ]));
    }

    let mut sends = 0_u64;
    for fixture in fixtures {
        let mut attempts = 0_u64;
        loop {
            if sends >= approval.request_budget.max_requests {
                return Err(RunError::BudgetExceeded);
            }
            sends += 1;
            match transport.send(fixture) {
                Ok(()) => break,
                Err(error) => {
                    attempts += 1;
                    if attempts >= approval.retry_policy.max_attempts {
                        return Err(RunError::Transport(error));
                    }
                }
            }
        }
        if attempts + 1 > approval.request_budget.per_fixture_max {
            return Err(RunError::BudgetExceeded);
        }
    }
    let _ = (
        &approval.approved_by,
        &approval.approved_at,
        &approval.connection,
        &approval.data_kinds,
        approval.retry_policy.same_connection_only,
        &approval.retry_policy.retry_on,
        approval.cost_approval.fee_cap_usd,
        approval.cost_approval.quota_confirmed,
    );
    Ok(sends)
}

fn valid_approval(fixtures: &[String]) -> Value {
    json!({
        "status": "approved",
        "approvedBy": "fixture-controller",
        "approvedAt": "2026-11-10T00:00:00Z",
        "connection": {
            "provider": "fixture-provider",
            "connectionId": "fixture-connection",
            "endpointClass": "fixture-endpoint",
            "model": "fixture-model"
        },
        "fixtures": fixtures,
        "dataKinds": ["text"],
        "requestBudget": {"maxRequests": 8, "perFixtureMax": 2},
        "retryPolicy": {
            "maxAttempts": 2,
            "sameConnectionOnly": true,
            "retryOn": ["timeout", "connection-reset"]
        },
        "costApproval": {
            "feeCapUsd": 0.5,
            "quotaLabel": "fixture-quota",
            "quotaConfirmed": true
        }
    })
}

fn remove_path(value: &mut Value, path: &[&str]) {
    let mut current = value;
    for segment in &path[..path.len() - 1] {
        current = current.get_mut(*segment).unwrap_or_else(|| {
            panic!("missing path segment {segment} in {path:?}");
        });
    }
    current
        .as_object_mut()
        .unwrap_or_else(|| panic!("not an object at {path:?}"))
        .remove(path[path.len() - 1]);
}

#[test]
fn real_evaluation_gate_refuses_before_sending_without_every_approval() {
    let manifest = load_manifest();
    let allowed = manifest
        .fixtures
        .iter()
        .map(|fixture| fixture.id.clone())
        .collect::<BTreeSet<_>>();
    let fixtures = vec![
        manifest.fixtures[0].id.clone(),
        manifest.fixtures[1].id.clone(),
    ];
    let valid = valid_approval(&fixtures);

    // A fully populated approval validates.
    let expected_data_kinds = vec!["text".to_owned()];
    let validated = validate_approval(&valid, &allowed, &expected_data_kinds)
        .expect("the complete approval is accepted");
    assert_eq!(validated.approved_by, "fixture-controller");
    assert_eq!(validated.approved_at, "2026-11-10T00:00:00Z");
    assert_eq!(validated.connection.provider, "fixture-provider");
    assert_eq!(validated.connection.connection_id, "fixture-connection");
    assert_eq!(validated.connection.endpoint_class, "fixture-endpoint");
    assert_eq!(validated.connection.model, "fixture-model");
    assert_eq!(validated.fixtures, fixtures);
    assert_eq!(validated.data_kinds, ["text"]);
    assert_eq!(validated.request_budget.max_requests, 8);
    assert_eq!(validated.request_budget.per_fixture_max, 2);
    assert_eq!(validated.retry_policy.max_attempts, 2);
    assert!(validated.retry_policy.same_connection_only);
    assert_eq!(
        validated.retry_policy.retry_on,
        ["timeout", "connection-reset"]
    );
    assert_eq!(validated.cost_approval.fee_cap_usd, 0.5);
    assert!(validated.cost_approval.quota_confirmed);

    // No approval, and the not-run template, both refuse with zero sends.
    for value in [None, Some(Value::Null)] {
        let mut transport = RecordingTransport::default();
        let error = run_real_evaluation(
            value.as_ref(),
            &allowed,
            &expected_data_kinds,
            &fixtures,
            &mut transport,
        )
        .expect_err("missing approval must be refused");
        assert!(matches!(error, RunError::Refused(_)));
        assert_eq!(transport.calls.len(), 0);
    }

    let mut missing_paths: Vec<Vec<&str>> = vec![
        vec!["status"],
        vec!["approvedBy"],
        vec!["approvedAt"],
        vec!["connection"],
        vec!["connection", "provider"],
        vec!["connection", "connectionId"],
        vec!["connection", "endpointClass"],
        vec!["connection", "model"],
        vec!["fixtures"],
        vec!["dataKinds"],
        vec!["requestBudget"],
        vec!["requestBudget", "maxRequests"],
        vec!["requestBudget", "perFixtureMax"],
        vec!["retryPolicy"],
        vec!["retryPolicy", "maxAttempts"],
        vec!["retryPolicy", "sameConnectionOnly"],
        vec!["retryPolicy", "retryOn"],
        vec!["costApproval"],
        vec!["costApproval", "feeCapUsd"],
        vec!["costApproval", "quotaLabel"],
        vec!["costApproval", "quotaConfirmed"],
    ];
    for path in missing_paths.drain(..) {
        let mut candidate = valid.clone();
        remove_path(&mut candidate, &path);
        let mut transport = RecordingTransport::default();
        let label = path.join(".");
        let error = run_real_evaluation(
            Some(&candidate),
            &allowed,
            &expected_data_kinds,
            &fixtures,
            &mut transport,
        )
        .expect_err(&label);
        match error {
            RunError::Refused(reasons) => assert!(
                !reasons.is_empty(),
                "missing {} must produce a reason",
                path.join(".")
            ),
            other => panic!("missing {} did not refuse: {other:?}", path.join(".")),
        }
        assert_eq!(transport.calls.len(), 0, "no send before approval");
    }

    // Wrong fixture set and unapproved data kind also refuse before sending.
    let mut wrong_fixtures = valid.clone();
    wrong_fixtures["fixtures"] = json!([manifest.fixtures[2].id.clone()]);
    let mut unknown = RecordingTransport::default();
    assert!(matches!(
        run_real_evaluation(
            Some(&wrong_fixtures),
            &allowed,
            &expected_data_kinds,
            &fixtures,
            &mut unknown,
        ),
        Err(RunError::Refused(_))
    ));
    assert_eq!(unknown.calls.len(), 0);

    let mut bad_kind = valid.clone();
    bad_kind["dataKinds"] = json!(["audio"]);
    let mut bad_kind_transport = RecordingTransport::default();
    assert!(matches!(
        run_real_evaluation(
            Some(&bad_kind),
            &allowed,
            &expected_data_kinds,
            &fixtures,
            &mut bad_kind_transport,
        ),
        Err(RunError::Refused(_))
    ));
    assert_eq!(bad_kind_transport.calls.len(), 0);

    let mut extra_kind = valid.clone();
    extra_kind["dataKinds"] = json!(["text", "image"]);
    let mut extra_kind_transport = RecordingTransport::default();
    assert!(matches!(
        run_real_evaluation(
            Some(&extra_kind),
            &allowed,
            &expected_data_kinds,
            &fixtures,
            &mut extra_kind_transport,
        ),
        Err(RunError::Refused(_))
    ));
    assert_eq!(extra_kind_transport.calls.len(), 0);

    // Budget and retry bounds are finite and enforced.
    let mut over_budget = valid.clone();
    over_budget["requestBudget"]["maxRequests"] = json!(2);
    over_budget["requestBudget"]["perFixtureMax"] = json!(1);
    let mut failing = RecordingTransport::default();
    failing.fail_once.insert(fixtures[0].clone());
    assert!(matches!(
        run_real_evaluation(
            Some(&over_budget),
            &allowed,
            &expected_data_kinds,
            &fixtures,
            &mut failing,
        ),
        Err(RunError::BudgetExceeded)
    ));
    assert_eq!(
        failing.calls.len(),
        2,
        "the finite request budget is enforced"
    );

    struct AlwaysFailingTransport {
        calls: usize,
    }
    impl EvaluationTransport for AlwaysFailingTransport {
        fn send(&mut self, _fixture_id: &str) -> Result<(), String> {
            self.calls += 1;
            Err("scripted permanent failure".to_owned())
        }
    }
    let mut permanent = AlwaysFailingTransport { calls: 0 };
    let error = run_real_evaluation(
        Some(&valid),
        &allowed,
        &expected_data_kinds,
        &fixtures,
        &mut permanent,
    )
    .expect_err("permanent transport failure");
    match error {
        RunError::Transport(detail) => assert_eq!(detail, "scripted permanent failure"),
        other => panic!("unexpected error {other:?}"),
    }
    assert_eq!(permanent.calls, 2, "retry stops at maxAttempts");

    let mut bounded = RecordingTransport::default();
    bounded.fail_once.insert(fixtures[0].clone());
    let sends = run_real_evaluation(
        Some(&valid),
        &allowed,
        &expected_data_kinds,
        &fixtures,
        &mut bounded,
    )
    .expect("approved scripted transport");
    assert_eq!(sends, 3, "one retry stays inside the request budget");
    assert_eq!(bounded.calls.len(), 3);
    assert_eq!(
        bounded
            .calls
            .iter()
            .filter(|id| *id == &fixtures[0])
            .count(),
        2,
        "the transient failure is retried on the same approved connection"
    );
    assert_eq!(
        bounded
            .calls
            .iter()
            .filter(|id| *id == &fixtures[1])
            .count(),
        1
    );
}

#[test]
fn the_scripted_contract_labels_its_limitations() {
    let value: Value =
        serde_json::from_str(&fs::read_to_string(fixture_path("manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    let judge = value.get("judge").expect("judge");
    assert_eq!(required_str(judge, "mode"), "scripted-answer-key");
    let methods = judge
        .get("methods")
        .and_then(Value::as_array)
        .expect("methods");
    assert_eq!(methods.len(), 3);
    for method in methods {
        let id = required_str(method, "id");
        let confidence = method.get("scriptedConfidence").and_then(Value::as_f64);
        match id {
            "normal_llm" => assert!(confidence.is_none()),
            "jev" | "decisions" => assert_eq!(confidence, Some(0.99)),
            other => panic!("unknown method {other}"),
        }
    }
    let limitations = string_array(judge, "limitations").join(" ");
    assert!(limitations.contains("No provider"));
    assert!(limitations.contains("not evaluate paraphrase quality"));
    assert!(
        limitations.contains("must not be reported as real-model accuracy"),
        "scripted rows carry an explicit non-accuracy label"
    );
    assert_eq!(
        required_str(
            judge.get("methods").and_then(|m| m.get(0)).expect("method"),
            "label"
        ),
        "Normal LLM"
    );

    // The pack is the real static check when present; no render is claimed.
    assert!(
        !real_pack_present()
            || Path::new(support::REAL_PACK_ROOT)
                .join("scripts/html-docs")
                .is_file()
    );
}
