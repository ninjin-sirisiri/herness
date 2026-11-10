# H3 HTML sync: 実adapter結合と受入テスト手順

H3の正本仕様は [H3 design](../sdd/specs/2026-11-09-h3-html-sync-design.md)、H1/H2の追加契約は [H1 design](../sdd/specs/2026-11-07-h1-runtime-design.md) と [H2 design](../sdd/specs/2026-11-08-h2-supervision-design.md)。この文書はTask 23で追加した実adapter受入の再現手順、実測/scriptedの区別、fixture、既知の未確認範囲を記録する。

## revision

Task 23の受入は次のrevisionで実行した。

- herness: `93d7d6b` をbaseにした作業ツリー（Task 23のcommitはreport参照）
- Common SDD pack: `/Users/h-uma/Documents/sdd` HEAD `601ebed9c02828373d9851cc01ea45b8c097ac7b`（read-only、変更なし）
- Reachableなpack test fixture: `tests/fixtures/adr/0001-queue-choice.md` と `.html`、CSSは `tests/fixtures/docs/sdd/assets/sdd.css`

packのrevisionは実行時に固定されないため、再実行時は `git -C /Users/h-uma/Documents/sdd rev-parse HEAD` をreportへ記録する。

## 実測とscriptedの区別

受入テストは「実adapter」と「scripted judge」を明示的に分ける。

| 層 | 種別 | 内容 |
| --- | --- | --- |
| Common SDD host API | 実測 | 実 `scripts/html-docs host-api` の `source-units`、structural `candidate-check`、final `candidate-check` |
| SQLite / journal / recovery | 実測 | 実store、実publication journal、実startup reconciliation |
| H1 runtime / Pi adapter / candidate tools | 実測 | 実 `Runtime`、実 `PiEngine`、`candidate_read` / `candidate_write` / `candidate_edit` |
| H2 gate / consent / budget / evidence | 実測 | 実 `SupervisionHost`、実 `HostAssessmentPort`、実 `BudgetLedger` |
| WKWebView render | 実測 | Task 17のhidden-window child capture（`--h3-render-test`） |
| publication writer / history archive | 実測 | 実 `PublicationWriter`、実 private archive、2-file journal |
| authoring model | scripted | loopback Responses mock。実provider/Keychain/loginなし |
| Html assessment 3方式 | scripted | loopback normal-LLM judge（met/unmet/insufficient）。`scripted loopback judge` と明記 |
| credentials | scripted | fake `CredentialPort`。実Keychainなし |

scripted judgeは実modelの品質証拠ではない。receipt/評価結果は「実pack・実render・実send gate・scripted判定」の組合せであり、実modelの意味判断を独立評価したとは表示しない。

## fixture

- Target: `docs/adr/0001-queue-choice.md`（real pack ADR fixture）
- Companion: `docs/adr/0001-queue-choice.html`（semantic-v1、`#sdd-provenance` 付き）
- 共通CSS: `docs/sdd/assets/sdd.css`
- render fixture: `tests/html-sync/fixtures/render/`（Task 17のhidden-window capture。受入は別fixtureを生成）
- H2 condition: 4条件をfixture内で生成。condition IDは保存されたplanから取得し、固定IDを捏造しない
- receipt: `docs/sdd/html-evidence/{sha256(target).json}`

## 実adapterの経路

`src-tauri/src/html_sync/pipeline.rs` がTask 16のcandidate intake以降を結ぶ。

1. `load_prepared`: H3 storeのactive generation/candidateと、private `CandidateArtifactStore` の正確なHTML/provenance、現在のMarkdown、CSS/resourceを読む。
2. `verify`: 実packの `source-units` + structural `candidate-check`、Task 17のreal render、8 configurationの完全性を検証する。
3. `assess`: 実 `HtmlAssessmentHost` がH2 send gateを通して3方式を実行する。evidence contentは `html-sync-evidence/evidence-content/{project}-{generation}.json` にversioned JSONで保存し、再起動後のassessment前にrehydrateする。
4. `publication_attempt` + `PublicationOrchestrator`: 実final check、exact version、history archive、2-file writer、receipt、synced commit。
5. 失敗時は `VerificationRejected` / `FixableUnmet` / `WaitingHuman` を返し、formal HTML/receiptを書かない。

`DesktopHost::pump` はworkerのcandidate intake後にこの経路を自動実行する。`DesktopHost::html_sync_advance` はreassessとcompleted generation拒否の明示的な入口でもある。

### CSS/resource dependency

`DesktopHost::discovered_dependencies` は共通CSSに加え、各approved Targetの現在のcompanion HTMLが参照するlocal `src`/`href` resourceをproject-relativeで登録する。絶対URL、fragment、data URL、project外、存在しないpathは登録しない。`composition::enable` はこの集合でobserver/worker/recoveryを再登録する。

### 原文変更時の同意

H2のtarget versionは原文変更のsupersedeで進む。H3の人間range approvalはexact Target setを承認しているため、`SupervisionAuthoringControl::reissue_range_consent` がCompletion/Htmlのconsentを同じtarget set・data kind・originのまま新しいtarget versionへhost-onlyで再発行する。次を満たさない場合はsupersede前に明示エラーにし、同意を広げない。

- 保存済みH3 settingsのfingerprint・enabled・current approval
- 現consentがgranted
- target set、data kind、originが人間承認のdisclosureと完全一致

再発行は `h3.consent.reissue:{project}:{purpose}:{targetVersion}` にversioned JSONで記録する。publication safetyは元のconsent bindingか、この記録に一致する再発行だけを受理する。

## コマンド

worktree rootで実行する。

```sh
cargo build -p herness-desktop --locked
cargo test -p herness-html-sync-tests --locked
cargo test -p herness-runtime-tests --locked
cargo test -p herness-supervision-tests --locked
```

`herness-html-sync-tests` のacceptance/renderは `target/debug/herness-desktop` をchild processとして起動するため、先にdesktop binaryをbuildする。CIでbinaryがない場合はrender/acceptanceが明示的に失敗する（fake captureへfallbackしない）。

pack testは `/Users/h-uma/Documents/sdd` で実行する。

```sh
uvx --from pytest pytest -q
```

`python3 -m pytest -q` はこの環境のsystem Pythonにpytestがないため、`uvx --from pytest pytest` で同じpack test suiteを実行した。packはread-onlyで、変更していない。

## 受入matrix

| 要件 | テスト | 実測結果 |
| --- | --- | --- |
| 正例が `synced` へ到達 | `acceptance::native_shell_external_edit_reaches_synced_through_the_real_adapter` | real pack + real WKWebView + scripted judgeで `Synced`。HTML/receiptが存在し、receiptのsource/html path、`h2.purpose=Html`、全condition `decision=met` を確認 |
| omission / changed code / changed link / changed number / hidden content | `acceptance::every_structural_variant_is_denied_by_the_real_pack_without_writing` | 5 variantすべてreal packが `deny`。証拠packを作らず、formal HTML/receiptはbyte-identical |
| fake / static-only render | Task 18 `assessment::fake_and_native_shaped_render_are_distinguished`、`host_js_accessibility_cannot_be_relabelled_as_native_ax` | fake renderは `test_only` でcompletion不可。受入のrender portは `RenderEvidence::validate()` が `wkwebview-native` を要求するためfakeを通せない |
| stale met | Task 18 `assessment::stale_met_is_never_applied`、`a_stale_assessment_binding_is_waiting_human` | 変更後のmetを適用せずstale/waiting |
| image shortage | `acceptance::image_shortage_waits_for_a_human_and_never_publishes` | text-only profileでsupport等がmissing imageとなり `WaitingHuman`。receiptなし、assessmentはimage条件を送らない |
| consent revoked | `acceptance::revoked_html_consent_blocks_every_assessment_send_and_publication` | assessment request 0、`WaitingHuman`、receiptなし |
| external HTML conflict | `acceptance::an_external_html_edit_becomes_waiting_human_and_is_never_overwritten` | `waiting_human`/`ExternalHtmlConflict`、外部bytesをbyte-exactで保持 |
| stop / latch | `acceptance::a_seeded_latch_holds_the_document_and_never_starts_authoring`、Task 16 `coordinator::persisted_latch_is_not_cleared_by_a_new_source_and_never_starts` / `budget_latch_is_persisted_and_new_notifications_do_not_bypass_it` | authoring request 0、receiptなし。新通知は `Held` |
| duplicate publication | Task 19 `publish::duplicate_publication_returns_the_stored_result_with_zero_extra_writes` | 同一publication ID + 同一fingerprintは保存結果を返し、追加write 0 |
| unknown publication result | Task 19 `publish::a_h1_result_fault_after_the_rename_is_unverifiable_and_never_retried_as_success`、Task 21 separate-process publication boundaries | `ReconciliationRequired`/`Unverifiable`。成功として再試行しない |
| old generation result | Task 16 `coordinator::source_change_supersedes_the_old_generation_and_rejects_a_delayed_candidate`、`acceptance::a_completed_generation_is_never_reverified_or_rewritten` | 旧世代は `StaleCandidate`。completed generationは再検証・再writeしない |
| reassess same candidate | `acceptance::reassess_reuses_the_saved_candidate_through_verification_and_assessment` | 保存済みcandidateを再検証・再assessmentし、requeueではない。receiptなしを維持 |
| multi-project 1 / dirty order | `cross_phase::dirty_documents_keep_notification_order_under_one_app_wide_slot` | B,A通知順を保持しduplicateは位置を変えない。`APP_WIDE_AUTHORING_CONCURRENCY=1`、`DOCUMENT_PUBLICATION_CONCURRENCY=1` |
| quit/restore | `cross_phase::restart_reconciles_without_sending_and_preserves_the_saved_document`、Task 21 `recovery::request_unknown_and_unconfirmed_stop_preserve_budget...` | startup request 0、side effects zero、active workは `waiting_human` latch。budgetはTask 21でexact 12s/31 runsを保持 |
| dependency reconciliation | `acceptance::discovered_dependencies_include_css_and_referenced_resources` | CSSと `docs/adr/assets/logo.svg`（Resource）を登録 |

「誤同期0」は各負例がreceiptを作らないこと、またはexternal conflict/waiting/failedで止まることで確認する。負例がformal HTMLを書いたテストはない。

## 未確認範囲

- 実provider、実Keychain、実login、実ChatGPT accountは使っていない。scripted judgeの品質・実modelのmet/unmet精度は未確認。
- productionのin-process `NativeRenderPort` は `AppHandle` へ配線したが、GUI windowを起動する自動testはない。受入のreal captureはTask 17のchild process経由。
- Jevの実画像上限（Task 18 report）は受入で再確認していない。Jevでimage-required条件を実運用する場合は、実PNGが上限内か別途確認し、不足ならwaiting-humanにする。
- `resolve_conflict` の `adopt_current` は、外部HTMLを新generationとして候補storeへ保存し、real検証・評価・adoption payloadを組み立てる経路が未配線。現状は「validated adoption payloadが必要」という明示エラーで、構造だけのadoptionを受理しない。`replace_with_candidate` は保存済みcandidateのreal再検証・assessment・explicit publicationを通す。
- 原文変更中のautomatic supersede + consent reissueは実装したが、受入testでsource editを競合させて `synced` まで通す連続変更シナリオは未追加。Task 16のscripted host supersession testとTask 23の同意再発行実装が別々の証拠。
- unknown publication resultの受入はfault injectionを使うTask 19/21 testに依存し、Task 23の受入testでは再現していない。
- 複数processの実crashはTask 21のchild exit code 70で境界を再現する。SIGKILL/power lossではない。
- `cargo fmt`/clippyはTask 25のgateではない。`cargo check --workspace --locked` はwarning-free。

## 実行結果（Task 23）

| command | result |
| --- | --- |
| `cargo test -p herness-html-sync-tests --locked` | 172 passed, 0 failed（acceptance 9、assessment 15、conflicts 11、contracts 13、coordinator 10、cross_phase 2、desktop 12、evidence 10、observer 19、policy_bridge 15、publish 18、recovery 20、render 3、store 12、worker 3） |
| `cargo test -p herness-runtime-tests --locked` | 280 passed, 0 failed, 1 ignored（既存manual RSS） |
| `cargo test -p herness-supervision-tests --locked` | 213 passed, 0 failed, 3 ignored（real connection） |
| pack `uvx --from pytest pytest -q` | 372 passed in 23.73s |
| `cargo check --workspace --locked` | success、warningなし |
| `cargo build -p herness-desktop --locked` | success（real render child用） |
