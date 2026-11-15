# H4 herness主導sdd-executeの受入証跡（Phase A実行、2026-11-15）

**Status:** Phase A（自動検証・loopback・実pack・実Git・実SQLite・実Pi・実H3/WebKit・実Tauri lifecycle）を実行し、specのTesting and acceptance 1〜8に対応する証拠を確認した。**Phase B（実provider接続）は未実行であり、未確認として保留する。** Task 25もH4全体も完了ではない。H1/H2の受入未完了とH3の限定受入（text-only reduced scope、accepted-with-exceptions）は本記録で免除しない。

- **実行者:** OpenCode subagent（このworktreeのTask 25実装者。shell: zsh、worktree `/Users/h-uma/.local/share/opencode/worktree/b3231b/h4-sdd-execute`、branch `h4-sdd-execute`）。controllerは本subagentをspawnした親sessionで、H4のTask列を順に割り当てた。H4のTask実行経路自体を親モデルのsubagent toolで代行した事実はない（cross-phase fixtureは承認済みplanをloopback childで駆動する）。
- **環境:** macOS 27.2.1（build 26B131）、Apple M5、arm64、16 GiB。`rustc 1.97.1 (8bab26f4f 2026-07-14)`、`cargo 1.97.1 (c980f4866 2026-06-30)`、`uvx` の `pytest 9.2.0`、system `python3` にpytestなし。debug profile。
- **正本spec:** [H4 design](../sdd/specs/2026-11-13-h4-sdd-execute-design.md)のTesting and acceptance（1〜8と実接続・限定受入の段落）、Open items and approval、Integration prerequisites and consuming paths。[H1 design](../sdd/specs/2026-11-07-h1-runtime-design.md)、[H2 design](../sdd/specs/2026-11-08-h2-supervision-design.md)、[H3 design](../sdd/specs/2026-11-09-h3-html-sync-design.md)。
- **手順:** [h4-testing.md](../development/h4-testing.md)（Task 23/24のfixture・gate・実測/scriptedの区別と、Task 25で追加した受入runbook）。

## 対象revision

| 対象 | revision |
| --- | --- |
| herness（このworktree、実行時のHEAD＝Task 4〜24のBASE） | `3d6245cbf1a9422e5324de1c1c0bbca65c814a0c`（`test(h4): add acceptance fixtures and the real-connection opt-in gate`） |
| Common SDD pack（read-only、dirtyなし） | `/Users/h-uma/Documents/sdd/.worktrees/h4-exec` HEAD `b210b3aac3faf84c5ad201aa6502dface8c4cdf2` |
| DB schema | 10（`0010_sdd_execute.sql`、`herness-store`のmigration testで9→10を確認） |

実行時のworking treeはclean（`git status --porcelain` 空）。**したがって下記の失敗・flakeはすべてBASE `3d6245c` のcode treeで観測した。** Task 25のcommitは本記録と`h4-testing.md`のdocsだけを追加し、code treeを変更しない。

packのHEADは`b210b3a`で固定した。packを変更していない（`git -C .../h4-exec status --porcelain` 空）。

## 証拠の分類

| 層 | 種別 | 内容 |
| --- | --- | --- |
| plan inspector / 共通HTML検証 | 実測 | 実packの `scripts/plan-inspect`、`scripts/html-docs` |
| SQLite / approval / journal / recovery | 実測 | 実store、実approval registry、実Git/dispatch/progress journal、実startup reconciliation |
| H1 runtime / tool executor / Git監査 | 実測 | 実 `Runtime`、実 `PiEngine`、実 `DesktopToolExecutor`、実 `HostGitBoundary` |
| H2 supervisor / required check / evidence | 実測 | 実 `SupervisionHost`、実 `HostCheckPort`（`true` を実行）、実 `HostAssessmentPort`（Html purpose含む） |
| H3 barrier / publication / render | 実測 | 実H3 storeの `Synced` 文書と実ファイルbytes、実WKWebView child capture（`--h3-render-test`） |
| Tauri lifecycle | 実測 | 実 `herness-desktop` process の smoke / close-reopen / quit / `--h4-lifecycle-test` / `--h3-lifecycle-test` |
| 子・judgeのmodel応答 | scripted | loopback Responses/Completions mock。実provider・実Keychain・実login・実account なし |
| credentials | scripted | in-processのfake `CredentialPort`。実Keychain itemを読まない |
| crash | 注入 | test modeだけがarmする4境界の `std::process::exit(70)`。SIGKILL/power lossではない |
| 実provider | **なし** | Phase B未実行。`not_executed` / `confirmed=false` |

scriptedなのはmodel応答だけであり、plan取込み・承認・順序・検証・barrier・Git・台帳・復旧・lifecycleは実装である。scripted judgeの品質証拠ではない。

## Phase Aの実行コマンドと結果

すべてworktree root、debug profile、Cargoは `--locked`。

| # | コマンド | 終了code | 実際の結果 |
| ---: | --- | ---: | --- |
| 1 | `cargo fmt --all -- --check` | 0 | format差分なし（出力なし） |
| 2 | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | warning 0件、`Finished dev profile [unoptimized + debuginfo] target(s) in 1m 02s`（初回）、2回目0.45s |
| 3 | `cargo test --workspace --locked` | 101 → 0 | **1回目: 1206 passed / 1 failed / 2 ignored**（既知のH2 loopback flake。cargoは失敗targetで中断するため70 sectionまでの部分実行）。**再実行: 1300 passed, 0 failed, 5 ignored**、78 test target（11 lib unittests + 66 integration test + 1 bin）＋11 doc-test target = 89 section |
| 4 | `cargo build -p herness-desktop --locked` | 0 | `Finished dev profile ... in 8.18s`、`target/debug/herness-desktop` 138,281,776 bytes |
| 5 | `HERNESS_APP_DATA_ROOT=<fresh>/smoke target/debug/herness-desktop --smoke-test` | 0 | `SMOKE_READY: pid=973 startup_ms=308`、`SMOKE_OK: main window is visible and the trusted UI is ready (pid=973 startup_ms=308)`、stderr空 |
| 6 | `HERNESS_APP_DATA_ROOT=<fresh>/close-reopen target/debug/herness-desktop --close-reopen-test` | 0 | `CLOSE_REOPEN_HIDDEN: pid=984 generation=1`、`CLOSE_REOPEN_OK: pid=984 previous_generation=1 generation=2`、stderr空 |
| 7 | `HERNESS_APP_DATA_ROOT=<fresh>/quit target/debug/herness-desktop --quit-test` | 0 | `QUIT_TEST_READY: pid=993`、`QUIT_OK: pid=993 save=confirmed stop=confirmed`、stderr空 |
| 8 | `cargo test -p herness-sdd-execute-tests --test native_lifecycle --locked -- --test-threads=1 --nocapture` | 0 | **2 passed, 0 failed**（`windowless_commit_progress_and_restart_send_nothing`、`each_crash_boundary_is_reconciled_without_a_second_commit_or_dispatch`）、11.32s |
| 9 | `cargo test -p herness-html-sync-tests --test native_lifecycle --locked` | 0 | **1 passed, 0 failed**（`native_lifecycle_startup_quit_and_restore_keep_the_h3_recovery_latch`） |
| 10 | `cargo test -p herness-html-sync-tests --test render --locked` | 0 | **3 passed, 0 failed**（実WKWebView child capture、外部load遮断、timeout/cancelのincomplete manifest） |
| 11 | `SDD_PACK_ROOT=/Users/h-uma/Documents/sdd/.worktrees/h4-exec cargo test -p herness-sdd-execute-tests --test acceptance --locked -- --nocapture` | 0 | **12 passed, 0 failed**、`H4_ACCEPTANCE_PLANS: accepted=2 refused=7 connections=0` |
| 12 | `SDD_PACK_ROOT=... cargo test -p herness-html-sync-tests --test acceptance --locked -- --nocapture` | 0 | **14 passed, 0 failed**、実pack＋実WKWebView＋scripted loopback judgeで正例が `Synced` |
| 13 | `cargo test -p herness-sdd-execute-tests --test cross_phase --locked -- --nocapture` | 0 | **11 passed, 0 failed**、`CROSS_PHASE_EVIDENCE ... commits=4 loopback_requests=4` |
| 14 | pack: `uvx pytest -q`（cwd `/Users/h-uma/Documents/sdd/.worktrees/h4-exec`） | 0 | **620 passed in 12.46s** |
| 15 | pack: `python3 -m pytest -q` | 1 | `No module named pytest`（この環境のsystem Pythonにpytestがない。plan記載の代替手順どおり#14で実行し、失敗を隠さず併記） |
| 16 | `python3 .../h4-exec/scripts/html-docs validate docs/sdd/plans/2026-11-13-h4-sdd-execute.md docs/sdd/specs/2026-11-13-h4-sdd-execute-design.md` | 0 | `decision=allow`、両companion有効（参照用の健全性確認。**変更Targetは0件**なので本来の対象外） |

- 一時rootは実行ごとに新規の絶対パス `/private/var/folders/1l/g5bm30qs6mq6m4zd0hqj2y4r0000gn/T/herness-h4-acceptance.970/{smoke,close-reopen,quit}`。各rootには新規の `herness.sqlite3` とWAL/SHMだけが作られた。
- `--h4-lifecycle-test` を相対 `HERNESS_APP_DATA_ROOT` で起動すると、`HERNESS_APP_DATA_ROOT must be an absolute path` でexit 134（panic）。fresh absolute rootの要求は実行時に強制される。
- native fixtureは `herness-desktop` binaryを要求し、`HERNESS_DESKTOP_BIN` で差し替え可能。binary不在時にfake captureへfallbackしない（`#4` を先に実行）。
- `--smoke-test`/`--close-reopen-test`/`--quit-test` はproviderを選択しない（`tests/runtime/tests/acceptance.rs::normal_window_automation_never_selects_a_real_check` が4 flagでassert）。payload送信の観測計器はこの3 launcherにはなく、外部要求0の主張は「provider/connection未選択・Keychain未読・実check未起動」に基づく。

### test target別の件数（workspace再実行の実測）

| package | passed | ignored |
| --- | ---: | ---: |
| `herness-assessment` lib | 24 | 0 |
| `herness-core`（lib + contracts + ports） | 95 | 0 |
| `herness-desktop`（lib + bin） | 43 | 0 |
| `herness-engine-pi` lib | 36 | 0 |
| `herness-html-sync` lib | 7 | 0 |
| `herness-html-sync-tests`（18 target） | 196 | 1 |
| `herness-runtime-tests`（16 target） | 300 | 1 |
| `herness-sdd-execute` lib | 7 | 0 |
| `herness-sdd-execute-tests`（17 target） | 337 | 0 |
| `herness-store` lib | 9 | 0 |
| `herness-supervision` / `-tests` lib | 0 | 0 |
| `herness-supervision-tests`（16 target） | 246 | 3 |
| doc-tests（11 crate） | 0 | 0 |
| **合計** | **1300** | **5** |

ignored 5件は手動/実接続opt-in fixtureであり、pass数へ加算していない: `herness-html-sync-tests/tests/phase_b.rs` 1（`H3_PHASE_B_REAL=1` と完全なapprovalが必要）、`herness-runtime-tests/tests/desktop.rs` 1（`measure_running_host_rss`）、`herness-supervision-tests/tests/real_connections.rs` 3（`COMMANDCODE_API_KEY` がある場合だけopt-in）。

### H4 target別の件数（`cargo test -p herness-sdd-execute-tests --locked`）

acceptance 12、approvals 24、barrier 13、commit 26、contracts 39、coordinator 32、cross_phase 11、desktop 18、import 21、ledger 22、native_lifecycle 2、packet 28、plan_changes 22、recovery 16、scheduling 6、store 16、workspace 29（合計337）。

## spec受入項目1〜8との対応

| # | specの要求 | 主な証拠（実測） | 結果 |
| ---: | --- | --- | --- |
| 1 | 新形式の正常系と、旧形式・未知版/field・重複JSON key・偽Task heading・欠番・循環依存・参照不足・path escapeを実pack parserで検査。inspectのfile変更・model要求0 | `acceptance::synthetic_plans_are_accepted_or_refused_by_the_real_pack`。実pack `plan-inspect` で `valid-two-task.md`(tasks=2)/`valid-single-task.md`(tasks=1) をaccept、7負例を拒否: `invalid_plan`（unknown field `hostHint` / `/version` unsupported 2 / 閉じないfence / `writePaths[0]` の `..` / `dependsOn` の後方参照 / 見出し `expected Task 2 but found Task 3`）と `unsupported_plan_format`（旧prose）。`import::real_pack_preview_keeps_exact_bytes`、`crlf_japanese_plan_is_byte_exact`、`oversized_plan_is_refused`、`import_starts_only_the_inspector_and_changes_no_repository`。`connections=0` | pass。負例の拒否理由はdiagnostic code・pointer・messageまで一致。取込み前後でcheckout bytes不変、socket接続0 |
| 2 | 取込みだけでは子起動・送信・Git 0。偽owner/registry、H3承認流用、古いplan/pack/profile/consent、別project・古いrevision・重複要求からの無断起動0 | `approvals::every_forbidden_approval_source_is_refused`、`an_h3_approval_is_not_an_h4_start_approval`、`a_new_approval_requires_the_trusted_human_start_confirmation`、`a_duplicate_start_returns_the_stored_result_and_one_child`、`a_second_request_id_for_the_same_task_creates_no_second_child`、`the_same_request_id_with_different_content_is_refused`、`a_dirty_selected_checkout_refuses_the_start`、`unsynced_required_html_refuses_the_start`、`revoked_consent_and_missing_capability_refuse_a_start`、`a_real_store_fault_never_records_a_start`。`cross_phase::a_fake_approval_and_an_injected_report_never_dispatch`、`a_stale_dispatch_request_never_creates_a_second_child`、`an_h3_approval_never_authorizes_an_h4_task`。`desktop::preview_model_and_remote_origins_cannot_invoke_any_sdd_mutation` | pass。誤起動0 |
| 3 | 実Pi＋loopback、実SQLite、実packとH3同期を結び、親dispatchなしで2 Task以上が直列進行。初回・継続へ原文制約とspecが渡る。未達修正・正当完了・TaskとH3の同project併進・禁止scope変更0 | `cross_phase::preview_approval_two_tasks_and_finish_without_a_parent_dispatch`: 実pack preview→人間承認→`approve_and_start`→Task 1/2を直列に実行し、`baseline=58bf418e... task1=58bf418e..d3f1f6c6 task2=d3f1f6c6..fcae5096 commits=4 loopback_requests=4` で `ready_for_finish`。`a_fixable_unmet_check_continues_the_same_child`。`packet::real_pi_first_and_continuation_inputs_carry_the_same_constraints_and_spec`、`the_packet_carries_the_exact_body_and_constraints_but_not_the_plan_or_another_task`。`scheduling::the_host_native_scope_excludes_one_target_not_the_whole_project`、`human_owner_progresses_in_another_project_while_h3_authoring`、`h1_stop_and_deadline_land_while_the_h3_target_is_authoring` | pass。直列2 Task、実commit 4件（baseline準備 + H3 companion + 2 Task）、loopback 4要求、外部要求0 |
| 4 | 必須検証fail・不足/古い証拠・虚偽DONE・注入・未停止process・H3未同期/版不一致/依存漏れ・能力不足で次Taskとcommitを拒否。manifest全体変更、CSS/resource変更、同じbytesへの復帰も扱う | `cross_phase::a_false_done_report_is_never_accepted_as_completion`、`injection_markers_and_stale_evidence_never_complete_a_task`、`an_unsynced_required_document_waits_without_completing_or_committing`、`a_failed_child_stops_the_task_without_a_commit`（実測 `REFUSAL failed_child state=WaitingHuman stop=Some(InternalFailure) dispatched=1 completed=0 commits=0`）。`barrier::*` 13件: `a_changed_document_outside_html_targets_enters_the_required_union`、`a_css_change_invalidates_html_that_did_not_itself_change`、`returning_to_the_same_bytes_never_resurrects_a_stale_synced`、`every_barrier_outcome_maps_to_its_own_hold`、`an_unrelated_unchanged_target_failure_alone_does_not_stop_the_task`、`a_document_without_a_verified_baseline_holds_and_is_never_synthesized`。`packet::done_without_evidence_is_incomplete_and_names_the_gaps`、`injected_instructions_and_a_stray_ruling_are_not_obeyed`、`blocked_and_needs_context_are_human_waits`。`coordinator::an_unknown_child_state_is_refused_and_never_completion`、`a_task_whose_budget_is_exhausted_never_dispatches` | pass。負例はcommit 0・completion 0で停止 |
| 5 | host commitでTask変更と検証済みcompanion/receiptだけが入り共通Git gateを通る。無関係dirty/index、hook変更・失敗、HEAD/branch競合、各journal/commit/DB保存境界のfaultで重複commit 0・完了範囲改変0。no_changeとstacked非互換の表示 | `commit::*` 26件: `only_the_task_change_and_the_verified_companion_are_committed`、`an_unrelated_change_outside_the_write_scope_never_becomes_a_target`、`the_common_staged_html_gate_runs_as_a_repository_hook`、`a_preexisting_staged_change_holds_the_task_and_leaves_the_index_alone`、`an_external_commit_that_moves_head_holds_before_any_attempt`、`a_failing_hook_holds_without_creating_a_commit`、`a_changed_hook_configuration_holds_before_anything_is_staged`、`a_replayed_request_returns_the_stored_result_and_creates_no_second_commit`、`the_journal_boundary_table_creates_at_most_one_commit`、`a_result_write_failure_after_the_commit_is_unknown_and_never_recommitted`、`a_boundary_that_commits_then_loses_its_result_creates_exactly_one_commit`、`the_intent_write_fails_before_any_git_side_effect`、`a_document_that_moved_after_the_commit_invalidates_the_evidence`、`the_recovery_classification_separates_established_not_run_and_unknown`、`a_no_change_task_records_evidence_and_creates_no_commit`。`ledger::no_change_renders_an_empty_range_and_breaks_stacked_prs`、`all_required_tasks_pass_the_real_stacked_pr_preflight` | pass。重複commit 0、記録済み範囲の改変0 |
| 6 | plan本文のみの変更・削除・移動で現在Taskを安全停止。停止未確認では再開せず、新版承認でも予算保持。未着手のみの変更は継承、着手済み・完了済みは自動移行しない | `plan_changes::*` 22件: `atomic_save_with_changed_bytes_engages_the_latch`、`prose_only_change_keeps_the_json_block_and_reports_ranges`、`global_constraints_change_is_never_ignored_when_the_json_is_identical`、`deleted_plan_stops_with_plan_missing`、`moved_plan_reports_the_candidate_path`、`unstable_observation_stops_the_task`、`dropped_notification_is_caught_by_the_periodic_reconcile`、`change_immediately_before_commit_blocks_the_commit_with_zero_commits`、`returning_to_the_same_bytes_does_not_clear_the_latch`、`inheritable_change_is_approved_and_keeps_the_consumed_budget_and_history`、`started_task_modification_is_refused_and_writes_nothing`、`completed_task_modification_is_refused_and_needs_a_new_plan`、`re_approval_before_a_confirmed_stop_is_refused`、`desktop_gate_persists_the_latch_across_a_reopened_store`。`cross_phase::a_plan_change_mid_task_stops_before_any_new_dispatch_or_commit` | pass |
| 7 | 別process復旧、通知欠落、progress出力失敗・改変、window閉鎖・非選択project・quitを実Tauri接続で確認。復元時の外部要求0、消費維持、未確定Gitの照合 | `native_lifecycle` 2件（下記の実測表）。`recovery::*` 16件（`restore_issues_zero_external_requests_and_reads_only_saved_state`、`every_git_boundary_reconciles_and_an_established_commit_waits_for_the_human`、`every_progress_boundary_reconciles`、`an_open_plan_change_latch_blocks_the_resume_after_a_restart`、`an_unresolved_git_result_blocks_the_resume_and_stays_unknown_after_a_restart`、`the_budget_is_preserved_by_a_human_resume_and_an_exhausted_budget_blocks_it`、`a_separate_process_re_reads_the_same_reconciliation`）。`ledger::an_externally_edited_ledger_is_refused`、`a_change_between_plan_and_replace_is_refused`。実launcherのclose-reopen/quit。#5/#6/#7の実行 | pass。再起動後 `request_count=0`、再dispatch/再commit 0 |
| 8 | 最終Taskのfull-suite失敗・正本未反映・古い証拠では `ready_for_finish` にしない。正常時は既存ledger/stack preflight互換とfinish情報、選択前のpush/merge/公開0、他ホストの既存execute/H3回帰 | `ledger::ready_only_with_current_final_evidence_and_spec_reflection`、`stale_full_suite_evidence_is_not_ready`、`a_post_commit_change_makes_the_evidence_stale`、`a_final_check_without_evidence_is_not_ready`、`an_incomplete_evidence_block_is_not_ready`、`a_missing_spec_reflection_with_a_later_phase_is_not_ready`、`a_ledger_failure_at_finish_holds_the_execution_instead_of_finishing`、`the_handoff_carries_every_finish_field_and_no_side_effect`、`all_required_tasks_pass_the_real_stacked_pr_preflight`。`desktop::the_finish_handoff_names_every_durable_input_and_every_blocker`。pack 620 passed（他ホストの既存execute/H3回帰）、`herness-html-sync-tests` 196 passed | pass。push/merge/公開は実行経路にも本Taskにも存在せず0件 |

`ready_for_finish` は本Taskで宣言しない（下記「判定」）。

## 負例の誤進行0

負例の各testは、拒否後に (a) 追加の子dispatch、(b) commit、(c) 完了 — のいずれも0であることを個別にassertする。本runでは全337件がpassし、拒否経路で完了・commitが記録されたtestはない。実測で表示された唯一の負例dispatch数は `a_failed_child_stops_the_task_without_a_commit` の `dispatched=1`（失敗前の正当な1回）で、`completed=0 commits=0`。`acceptance::wrong_results_and_holds_are_counted_separately` は誤完了・誤commit・誤dispatchを別fieldで0として集計し、保留を誤りに加算しないことを確認する。

集計値は上記testのassertとmetrics形に基づく。独立した計器で337件分の負例を横断集計した数値ではない。

## H4 native lifecycle fixture（実測）

`tests/sdd-execute/tests/native_lifecycle.rs`（`--test-threads=1`、static mutexで直列）。各caseは独立したfresh absolute `HERNESS_APP_DATA_ROOT` と一時checkoutを使う。fixtureは実pack・実Git・実SQLite・実Pi(loopback)でseedし、native processは「Task dispatch済み・H2 completed」の保存状態からbarrier capture・H2再読・実host commit・progress出力を行う。

### case 1: window非依存のcommit・progress・quit・再起動

```
H4_NATIVE_EVIDENCE commit root=/private/var/folders/.../checkout app_data=/var/folders/.../.tmp6wAh1E
  exit=Some(0) connections=0 head=8c79b0cacae111d3fe18604115b3472112660ed5
  baseline=ad6c1c3c825a88b0228e3054064836daa76c4a62 commits=3
H4_LIFECYCLE_OK: pid=4772 projects=1 executions=1 tasks=1 tasks_completed=1 commits=1
  progress=present request_count=0 window=absent selected_project=none
  startup_reports=1 startup_failures=0 pump_errors=0
  states=execution:2ce5223c-...:fa3a16fa-...=ReadyForFinish
```

2回目の起動でもexit 0、`request_count=0`、`tasks_completed=1`、HEAD・commit数・範囲・ledger bytesが不変。counting listenerは両起動で接続0。`.sdd/progress.md` は `Worktree: in-place`、full `Branch baseline:`、`Task 1: complete (` を持つ。commit messageは `Task 1:` と `Herness-Task`/`Herness-Execution`/`Herness-Request` trailerを持つ。

### case 2: 4つのcrash境界

| point | crash exit | crash後commits | 再起動exit | connections | 再起動後commits | 再起動後のclass | state |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `before-host-commit` | 70 | 2 | 0 | 0 | 2 | `git=[Unknown]` | `Committing` |
| `after-host-commit` | 70 | 3 | 0 | 0 | 3 | `git=[Established]` | `Committing` |
| `before-db-result` | 70 | 3 | 0 | 0 | 3 | `git=[Established]` | `Committing` |
| `before-progress-replace` | 70 | 3 | 0 | 0 | 3 | `git=[Established] progress=[Unknown]` | `WaitingHuman`（`pump_errors=1`, `tasks_completed=1 commits=1 progress=absent`） |

実測SHA（各case独立、再起動前後で同一）: `507b9dd0bb078c0eb2ce1ed501453959e6592a36`、`aef910af5ede04763b897d0e47e46b8f4f9d35ac`、`03816751224e0995edaabe38b29f5b12fbab14e2`、`c5d79d5a53c6d271f7bcc2807332f46926bd379e`。

`committing` は再起動後のpump対象外であり、成立済みcommitは `pending_link` として人間のresume確認を待つ。再dispatch 0・再commit 0を各caseでassert。

## H3 native lifecycle fixture（実測）

`tests/html-sync/tests/native_lifecycle.rs` は実 `target/debug/herness-desktop` を3回起動する。1) `--h3-lifecycle-test` でpending cycleをseedしたrootを復元（`H3_LIFECYCLE_OK: ... projects=1 failures=0 request_count=0 window=absent selected_project=none`）、2) 同rootで2回目（latch復元、送信0）、3) `--quit-test` で実quit hook。storeは各段階で `WaitingHuman` / `HumanWaitCause::RecoveryReconciliation` を保持することをassert（1 passed）。

H3の実renderと実pack経路は `tests/html-sync/tests/render.rs`（3 passed、`real_hidden_wkwebview_capture_is_complete_and_blocks_every_external_load`）と `tests/html-sync/tests/acceptance.rs`（14 passed、`native_shell_external_edit_reaches_synced_through_the_real_adapter`）で再確認した。assessorはloopbackのscripted judgeである。

## 要求数・usage・費用

| 分類 | 実測 |
| --- | ---: |
| 外部（実provider・実login・実Keychain・実account）要求 | **0** |
| loopback要求（cross-phase 2 Task正例） | 4（`loopback_requests=4`） |
| loopback接続（H4 native 2 case + 4 crash case の各2起動） | 0 |
| loopback接続（H4 acceptance target） | 0（`connections=0`） |
| loopback要求（client model応答、H4全target） | 各fixtureのin-process mockのみ。外部originなし |
| 実provider usage（tokens/credits） | なし（未送信） |
| 費用（USD）・quota消費 | なし。money cap・price版の議論は発生しない（`NoPriceEstimator` はmoney cap付き要求を送信前に拒否） |
| secret・credential | 読み取り・保存・表示なし。fake `CredentialPort` のみ |

## cross-phaseが作ったcommit範囲

`cross_phase::preview_approval_two_tasks_and_finish_without_a_parent_dispatch` が一時repoで生成した実範囲（`CROSS_PHASE_EVIDENCE`）:

- checkout `/private/var/folders/.../.tmpHwMb1l/checkout`、branch `h4-cross-phase`
- `baseline=58bf418eb08a7c16f11a96c1f13d17a365786959`
- `task1=58bf418eb08a7c16f11a96c1f13d17a365786959..d3f1f6c66bb677846e8f6e1701760f0e09314ef0`
- `task2=d3f1f6c66bb677846e8f6e1701760f0e09314ef0..fcae5096b4571f62e49092e9fec32a185786ba65`
- commits=4（baseline準備commit + H3 companion + 2 Task）

H4 native fixtureの一時repo範囲は case 1 で `ad6c1c3c...8c79b0ca`、crash 4 caseで上記のとおり。**いずれも一時repoであり、herness repoの履歴ではない。** herness repoの本Taskの範囲は docs 2ファイルのみ。

## 失敗・flake・保留

| 事象 | 内容 | 単独再実行 | 判定 |
| --- | --- | --- | --- |
| workspace 1回目の失敗 | `herness-supervision-tests/tests/desktop.rs:3911` `permission_composition::html_assessment_uses_its_own_profile_consent_origin_and_the_same_cycle_ledger` が `Unsupported { feature: "assessment request failed: assessment request is invalid" }` | 単独1/1 pass、`--test desktop` を8回実行して7 pass / 1 fail（別run）、package再実行3/3 pass | **既知のloopback flake。BASEのcode treeで発生**（working treeはcleanで、Task 25はcodeを変更しない）。assertは弱めていない |
| 追加観測（同一target反復） | 同じtestを6回単独実行して5 pass / 1 fail | 5/6 pass | 同上。test本体はTask 4以前（`2715069`）のものでH4の新規targetではない |
| 別の20秒timeout flake | `permission_composition::real_pi_uses_the_owner_packet_scope_and_conversation_for_two_runs` が `timed out waiting for 5 requests and 2 runs; requests=1 ... failure=target_unstable`（20.15s）。`task-9/11/19` reportに既記載の既存flake | 単独3/3 pass、直後の単独1回は同じ失敗、その後3/3 pass | **既知の既存flake**。BASEで観測。Task 25はcodeを変更しないため「Task 25の回帰」ではない |
| packの `python3 -m pytest` | system Pythonにpytestなし（exit 1） | `uvx pytest -q` で620 passed | 環境制約。plan記載の代替手順どおり。隠さず併記 |

いずれのflakeも**「fixしない」**。Task 25はdocsのみを変更し、無関係なcodeへ手を入れていない（briefの指示どおり）。

## 未確認の一覧（明示）

以下は**未確認**であり、本受入で確認済みに変えない。

### H1から継承（原文のまま）

- OpenAI APIキー→`openai-responses` と Anthropic APIキー→`anthropic-messages` は **UNVERIFIED**（検証用キーがない）。利用者の判断で未確認のまま残す。
- 実Tauriのclose button人間クリック、macOS dock reopen、quit猶予後のkeep waiting/force quitのGUI操作は自動化していない。
- **H1受入は未完了**であり、H1のH4 integration additionsも未確認。

### H2から継承（原文のまま）

- 通常LLM（OpenAI Responses / Anthropic Messages / OpenAI-compatible）とOpenAI Decisionsの**実endpoint**による条件評価・許可評価は未確認。
- Jevの直接TypeSafe endpoint、画像入力、実TypeSafe APIキー、標準質問文でのpermission auto-allow、Command Code gatewayの実運用は未確認。
- 完了閾値0.95、許可閾値0.99、分布誤差0.001の実model妥当性は未確認。
- 実Tauri監督UIからのtarget作成・profile/consent設定・start/stop/resume/reassess・human confirmation・window閉鎖中の監督進行の手動操作は未確認。
- **H2受入は未完了**であり、H2のH4 integration additionsも未確認。

### H3から継承（限定受入の範囲）

- H3は2026-11-10に **text-only reduced scope で accepted-with-exceptions**。full H3 completeではない。
- Decisions、画像/PNG、`support`/`usability`/`render`、人間の読解観測は `not_run`。
- Jevの実画像上限、production in-process `NativeRenderPort` のGUI手動描画は未確認。
- assessment-onlyのfalse sync 2件（`eval-adr-001/fake-edge`、`eval-plan-001/fake-value`）が残る。どちらも共通packが `number-invented` で拒否するためfull pipelineの正式反映ではない。
- normal LLMのrun間ばらつき（false stopの再現性は限定的）。将来のmodel更新を自動承認しない。

### H4固有（本Taskで新たに明示）

- **Phase B（実provider接続）は未実行**。理由は人間の別途許可がないこと（下記）。
- 実providerでの「実装 → 完了評価 → HTML評価 → render証拠」の一連は未受入。`h4-real-provider-acceptance` は `unconfirmed` のまま。
- H4の人間向け操作（信頼UIからのapprove/start/stop/resume/state確認/finish引継ぎ）を**人間がGUIで**実行した証拠はない。本受入の操作はtest/IPC/launcher経由である。
- crash証拠はtest modeの明示的境界 `std::process::exit(70)` であり、SIGKILL・power loss・filesystem全体の破損を再現しない。
- 子のmodel要求はloopbackであり、実modelの実装品質・完了判断品質の証拠ではない。
- 1 plan＝1 repo・1 checkoutの範囲を超える複数repo planの自己実行は主張しない。`no_change` Taskは空範囲のためstacked PR非互換（表示のみ確認）。
- OS sandboxはなく、シェル許可が任意scriptの副作用を完全に防ぐとは主張しない。
- 3つのwindow launcher（smoke/close-reopen/quit）にはpayload送信の観測計器がない。「外部要求0」はprovider/connection未選択・Keychain未読・実check未起動に基づく。
- 費用・usageの実測はない（送信0）。USD上限・quotaの実運用は未検証。

## Phase B: 未実行（人間の許可なし）

Phase Bは、controllerが次の情報を**送信前に**人間へ提示し、対象・データ・上限・費用について**別途の明示許可**を得た場合だけ実行する。**今回は許可が存在しないため、実provider・実Keychain・実login・実accountへ一切接続せず、送信0のまま `not_executed` / `confirmed=false` で保留する。** 本Taskの実装者はこの許可を自分で発行できない。

人間が判断するために提示すべき開示（未提示・未承認）:

1. **接続identity:** provider、`connectionId`、`endpointClass`、model（version固定）、`purpose=assessment`、`verified=true`、`consentGranted=true`、origin。ChatGPT loginやAPI keyの値をmanifestへ書かない。fallback・自動再選択・別modelへの切替を承認しない。
2. **fixtureと送信bytes種別:** fixture名と、送るbytes種別4種（`plan_packet` / `task_report` / `assessment_prompt` / `h3_render_evidence`）。1種でも欠けるmanifestはgateが拒否する。repositoryの他file・credential・Authorization・Keychain値・login materialを送らない。
3. **有限の要求数とretry:** 総要求数の上限、fixture当たり上限、retry回数（`maxAttempts`）、retry理由（`timeout` / `connection-reset` / `server-error` / `rate-limited`）、同一接続限定。無制限・自動再試行・別接続fallbackを承認しない。
4. **料金または枠:** 有限のUSD上限（priced requestに必須）または確認済みquota reference。現在のdesktop compositionは `NoPriceEstimator` のため、money cap付き要求は見積なしで送信前に `BudgetUnavailable` として拒否される。ダミーestimateを追加しない。
5. **有効期限:** `expiresAtMillis`（同時刻は拒否）。
6. **未確認能力の維持:** H3の `image`/`support`/`usability`/`render`/`humanReadingObservation` と、H1/H2/H3/H4の継承未確認6項目を `unconfirmed` のまま置く。これらを「確認済み」に変える承認はgateが `UnconfirmedCapabilityClaimed` / `InheritedUnconfirmedMissing` として拒否する。
7. **credentialAccess=none:** 承認を実login・credential探索・Keychain読取りへ拡張しない。

補足: 実接続runnerはTask 24にも本Taskにも含まれない。`tests/sdd-execute/tests/acceptance.rs` のtransportはin-memoryの記録用だけで、`H4_ACCEPTANCE_OPT_IN=1` と有効manifestを与えてもnetworkへ出ない（`H4_ACCEPTANCE_DEFAULT_DENY: external_requests=0 socket_connections=0 template_status=not_authorized`）。`tests/sdd-execute/fixtures/acceptance/acceptance.manifest.json` は `status=not_authorized` のテンプレートであり承認ではない。したがってPhase Bを実行するには、(a) 人間の許可記録、(b) 承認manifest、(c) 実接続runner の3つが別途必要である。

## 判定

- **Phase A: PASS。** fmt、clippy `-D warnings`、workspace test 1300 passed（既知flakeの再実行後）、desktop build、実Tauri smoke/close-reopen/quit（fresh absolute root）、H4 native lifecycle 2件（windowless commit/progress/quit/restart + 4 crash境界）、H3 native lifecycle 1件、実WKWebView render 3件、実pack plan受入 12件（2 accept / 7 refuse / connections 0）、実pack＋実WKWebViewのH3 acceptance 14件、cross-phase 11件（commit範囲とloopback 4要求）、pack 620 passed が成功した。
- **Phase B: NOT EXECUTED。** 人間の別途許可がないため `not_executed` / `confirmed=false`。開示項目は上記に列挙した。
- **Task 25は完了宣言しない。H4全体も完了ではない。** 本記録は「Phase Aで何を確認し、何が未確認で保留か」を残すものであり、`ready_for_finish` の宣言でも人間の受入でもない。H1/H2受入の未完了とH3の限定受入は免除していない。H4を完了扱いにするには、Phase Bの許可・実行または人間による受入範囲の明示的な再合意が必要である。
