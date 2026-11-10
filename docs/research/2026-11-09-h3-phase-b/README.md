# H3 Phase B partial text-only evidence (2026-11-10)

This directory contains the sanitized evidence from the permitted Phase B
partial run. It is **not** a complete Phase B and does not make H3 complete.

## Approval and scope

- Approved by: `h-uma` (human), 2026-11-10.
- Connections: ChatGPT login `gpt-6-luna` (normal LLM, `openai_responses`) and
  CommandCode GOAT `typesafe/jev-1.14.0` (Jev, fixed gateway).
- Data: exact text-only evaluation set, `dataKinds: ["text"]`; no image/PNG
  bytes. Decisions, `support`, `usability`, `render`, and human observation
  were not run.
- Budget: 162 maximum assessment attempts for the run; 108 attempts were used
  (27 Jev + 27 normal-LLM initial + 27 normal-LLM diagnostic + 27 normal-LLM
  after the streaming fix). The ChatGPT catalog checks and one minimal
  `--real-check` request are separate from the assessment count.

## Files

- `initial-full-2026-11-10.json` — first run: 27 Jev assessments succeeded;
  27 normal-LLM requests failed with HTTP 400
  `{"detail":"Stream must be set to true"}`.
- `normal-llm-after-streaming-fix-2026-11-10.json` — normal-LLM-only rerun
  after `b928fb1` added `stream:true` and SSE `response.completed` parsing:
  27/27 assessed; Jev is `not_run` in this file.
- `summary.json` — per-case expected/actual for both methods, counts, and the
  false-sync/false-stop lists.

## Findings

- Positive cases: Jev met 2/5, normal LLM met 4/5.
- Reject cases: both methods returned `unmet` for 18/19; `eval-adr-001/fake-edge`
  returned `met` for both. The common pack's structural check denies that case
  as `number-invented`, so it is not a formal publication in the full pipeline.
- Holds: `eval-glossary-001/injection` returned `met` for both methods;
  `eval-plan-001/injection` returned `met` for Jev. These are semantic false
  positives with no deterministic gate in the current information-only runner.
- False stops: `eval-plan-001/positive` was `unmet` for both; `eval-spec-001/positive`
  and the alternate `eval-plan-001/false-stop-probe` were `unmet` for Jev.
- Usage fields are not available from this runner (`usage=null`).

The full H3 publication path requires the other three conditions and the pack
final check. This run alone is not a `synced` result. H3 remains incomplete
until the injection false positives are addressed and the remaining Phase B
scope or an explicit reduced acceptance scope is agreed.

## Reproduce (requires a new human approval; no credentials are stored here)

```bash
H3_PHASE_B_REAL=1 \
H3_PHASE_B_APPROVAL=/absolute/path/to/filled-phase-b.approval.json \
H3_PHASE_B_REPORT=/absolute/path/to/new-report.json \
HERNESS_APP_DATA_ROOT="$HOME/Library/Application Support/dev.herness.desktop/herness" \
cargo test -p herness-html-sync-tests --test phase_b --locked -- --ignored --nocapture
```

`COMMANDCODE_API_KEY` must be set in the environment (never in the approval,
report, or repository). The approval template is
`tests/html-sync/fixtures/evaluation/phase-b.approval.template.json`.
