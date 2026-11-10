# H3 HTML sync: 実adapter結合と受入テスト手順

H3の正本仕様は [H3 design](../sdd/specs/2026-11-09-h3-html-sync-design.md)、H1/H2の追加契約は [H1 design](../sdd/specs/2026-11-07-h1-runtime-design.md) と [H2 design](../sdd/specs/2026-11-08-h2-supervision-design.md)。この文書はTask 23で追加した実adapter受入の再現手順、Task 24で追加した意味・視覚品質の評価セット、実測/scriptedの区別、fixture、既知の未確認範囲を記録する。

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

`herness-html-sync-tests` のacceptance/renderは `target/debug/herness-desktop` をchild processとして起動するため、先にdesktop binaryをbuildする。CIでbinaryがない場合はrender/acceptanceが明示的に失敗する（fake captureへfallbackしない）。acceptance testはreal WKWebView childを1本ずつ実行する（test内のstatic mutex）。並列負荷によるchild captureのflakyを避けるためで、test内容は変えない。

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
| reassess same candidate | `acceptance::reassess_reuses_the_saved_candidate_through_verification_and_assessment` | 保存済みcandidateを再検証・再assessmentし、requeueではない。receiptなしを維持 |
| dependency reconciliation | `acceptance::discovered_dependencies_include_css_and_referenced_resources` | CSSと `docs/adr/assets/logo.svg`（Resource）を登録 |
| external HTML adoption (positive) | `acceptance::adopt_current_external_html_reaches_synced_with_a_valid_receipt` | external HTML edit → guarded `AdoptCurrent` → real pack validation + real render + 4条件再評価 → `synced`。new receiptのhtml digestがexternal bytesと一致し、全condition `met` |
| external HTML adoption (negative) | `acceptance::an_adoption_with_a_failing_evaluation_keeps_waiting_without_overwriting` | strict値を壊したexternal HTMLは `WaitingHuman`。external bytesも既存receiptも上書きしない |
| continuous source change → synced | `acceptance::continuous_source_change_supersedes_reissues_consent_and_reaches_synced` | 著作中の原文変更で旧世代 `Superseded`、H1 stop確認、Completion/Html consent再発行、same target/cycleで新世代を著作・検証・評価・公開し `synced`。generation 2件、history 2件、予算消費は非リセット、reissue recordあり |
| consent expansion refusal | `acceptance::consent_reissue_refuses_a_target_expansion_and_never_starts_the_new_generation` | H2 consentのTarget setを追加した状態で原文変更 → reissue前に拒否、新世代/新receiptなし、旧HTML保持 |

「誤同期0」は各負例がreceiptを作らないこと、またはexternal conflict/waiting/failedで止まることで確認する。負例がformal HTMLを書いたテストはない。

## 未確認範囲

- 実provider、実Keychain、実login、実ChatGPT accountは使っていない。scripted judgeの品質・実modelのmet/unmet精度は未確認。
- productionのin-process `NativeRenderPort` は `AppHandle` へ配線したが、GUI windowを起動する自動testはない。受入のreal captureはTask 17のchild process経由。
- Jevの実画像上限（Task 18 report）は受入で再確認していない。Jevでimage-required条件を実運用する場合は、実PNGが上限内か別途確認し、不足ならwaiting-humanにする。
- external HTML adoptionは、外部bytesを新generation/candidateとしてprivate storeへ保存し、real structural/semantic/SVG validation、real render、4条件の再評価、Task 20 `CurrentHtmlAdoption`、Task 19 explicit publicationを通す。構造だけ・stale・fakeの結果はwaiting-humanのまま。
- 連続原文変更は、scripted modelのdelayで旧runをin-flightに保ち、test seamは観測の到着時刻だけを制御する。H1 stop、H2 supersession、consent再発行、owner authority、publicationは実経路。judgeは引き続きscripted loopback。
- unknown publication resultの受入はfault injectionを使うTask 19/21 testに依存し、Task 23の受入testでは再現していない。
- 複数processの実crashはTask 21のchild exit code 70で境界を再現する。SIGKILL/power lossではない。
- `cargo fmt`/clippyはTask 25のgateではない。`cargo check --workspace --locked` はwarning-free。

## 実行結果（Task 23）

| command | result |
| --- | --- |
| `cargo test -p herness-html-sync-tests --locked` | 177 passed, 0 failed（acceptance 14、assessment 15、conflicts 11、contracts 13、coordinator 10、cross_phase 2、desktop 12、evidence 10、observer 19、policy_bridge 15、publish 18、recovery 20、render 3、store 12、worker 3） |
| `cargo test -p herness-runtime-tests --locked` | 280 passed, 0 failed, 1 ignored（既存manual RSS） |
| `cargo test -p herness-supervision-tests --locked` | 213 passed, 0 failed, 3 ignored（real connection） |
| pack `uvx --from pytest pytest -q` | 372 passed in 23.73s |
| `cargo check --workspace --locked` | success、warningなし |
| `cargo build -p herness-desktop --locked` | success（real render child用） |

## 意味・視覚品質の評価セット（Task 24）

Task 24は、用語集・ADR・spec・planの4種について、手著作baseline（Markdown）、再構成正例（semantic-v1 HTML）、source unit別の正解、読解課題、負例、人間観測record、opt-in実評価のapproval gateを追加した。fixtureは評価用のテスト入力であり、Target setのMarkdownや`.html` companionではない。したがって`html-docs validate`/`check`の対象にはならない。

正本manifestは `tests/html-sync/fixtures/evaluation/manifest.json`。評価testは `tests/html-sync/tests/evaluation.rs`。

### fixture ID

| fixture ID | 文書種別 | baseline | 再構成正例 | real packのtarget path |
| --- | --- | --- | --- | --- |
| `eval-glossary-001` | glossary | `docs/glossary/CONTEXT.md` | `positive/glossary-CONTEXT.html` | `CONTEXT.md` |
| `eval-adr-001` | ADR | `docs/adr/0001-queue-choice.md` | `positive/adr-0001-queue-choice.html` | `docs/adr/0001-queue-choice.md` |
| `eval-spec-001` | spec | `docs/sdd/specs/2026-11-01-example-design.md` | `positive/spec-2026-11-01-example-design.html` | `docs/sdd/specs/2026-11-01-example-design.md` |
| `eval-plan-001` | plan | `docs/sdd/plans/2026-11-01-example.md` | `positive/plan-2026-11-01-example.html` | `docs/sdd/plans/2026-11-01-example.md` |

`eval-plan-001` には、同じ情報を別layoutで再構成した `positive/plan-2026-11-01-example-alt.html` もある。これはfalse-stop検出用の正例であり、品質の実測値ではない。

4 fixtureはいずれも `dataKinds: ["text"]` のsemantic評価入力で、承認済み画像bytesや実render画像は含まない。scripted judgeのsupport/usability/render rowはcontract分類用であり、実画像条件の評価ではない。

### source unit別の正解と読解課題

manifestの `fixtures[].units[]` は `source-units` のunit id/kindと一致し、各unitに `answers[]`（`scope: visible` または `scope: html`）を持つ。scripted judgeはvisible text（template/script/style/hiddenを除外）とraw HTMLの両方から、正解の存在と既知の矛盾を検査する。

主な正解:

- glossary: `Backorder` の「Do not accept ... without the owner's approval」、`Order` のAvoid値 `Purchase, transaction`、`Cancellation` のowner permission。
- ADR: `FIFO`、`750 ms`、`at most 2 MiB`、`Do not use LIFO unless the owner approves a migration`、plan link `../plans/2026-11-01-example.md`。
- spec: `must not contain external network requests`、`Only a human owner may approve a new Target`、`1,280×800` と `390×844`、`semantic HTML`、published document link、`Source|Markdown` / `Companion|Authored HTML` のtable値。
- plan: `Do not run Task 2 before Task 1 completes`、`UNIQUE_TASK_ONE` / `UNIQUE_TASK_TWO`、`750 ms`、`2 MiB`。

`fixtures[].readingTasks[]` は同じ情報を探す読解課題で、各課題は対象unit、正解、baseline内の出現、正例内のfindabilityを持つ。Task 24のtestは課題とunitの対応だけを検証し、人間の読解結果は生成しない。

### 負例とpackの範囲

負例には、caveat欠落、否定反転、閾値変更、権限拡大、code変更、link変更、偽edge/値、hidden情報、stale evidence、prompt injectionを含める。pack structural `candidate-check` はstrict値/code/link、数値、source digestなどの静的改変をdenyするが、caveat・否定・権限・実行順序・table値・hidden本文のような意味改変はallowし得る。packのallowを意味保持の証明にせず、その層はscripted judgeの負例として分類する。

Task 24で観測したpack decision（real pack present時）:

| case | pack expectation | 実測decision |
| --- | --- | --- |
| `eval-glossary-001/positive` | allow | allow |
| `eval-glossary-001/avoid-term` | deny | deny (`strict-value-missing`) |
| `eval-glossary-001/permission` / `hidden` / `injection` | either | allow |
| `eval-adr-001/positive` | allow | allow |
| `eval-adr-001/negation` / `caveat` | either | allow |
| `eval-adr-001/threshold` | deny | deny (`unit-mismatch`) |
| `eval-adr-001/code` | deny | deny (`strict-value-missing`) |
| `eval-adr-001/link` | deny | deny (`link-missing`, `strict-missing`, `strict-unknown`) |
| `eval-adr-001/fake-edge` | deny | deny (`number-invented`) |
| `eval-adr-001/stale` | deny | deny (`digest-mismatch`, `source-stale`) |
| `eval-spec-001/positive` | allow | allow |
| `eval-spec-001/negation` / `permission` / `table` | either | allow |
| `eval-spec-001/viewport` | deny | deny (`number-missing`, `number-invented`) |
| `eval-spec-001/code` | deny | deny (`strict-value-missing`) |
| `eval-spec-001/link` | deny | deny (`link-missing`, `strict-missing`, `strict-unknown`) |
| `eval-plan-001/positive` | allow | allow |
| `eval-plan-001/order` / `hidden` / `injection` | either | allow |
| `eval-plan-001/threshold` | deny | deny (`unit-mismatch`) |
| `eval-plan-001/fake-value` | deny | deny (`number-invented`) |
| `eval-plan-001/false-stop-probe` | allow | allow |

### scriptedとrealの区別

| 層 | 種別 | 内容 |
| --- | --- | --- |
| source unit / pack structural | 実測 | 実Common SDD packの `source-units` とstructural `candidate-check`（pack present時） |
| scripted judge | scripted | answer keyとのexact一致・既知の矛盾だけを見る決定的judge。paraphrase品質は評価しない |
| Normal LLM / Jev / Decisions | scripted | 同じanswer keyを使う3 row。Jev/Decisionsは0.99のscripted confidenceを持つがprovider requestは0 |
| real model | 未実施 | 接続・fixture・request数・retry・料金/枠の承認がない |
| human observation | 未実施 | 観測者・文書版・誤答・所要時間・困難点のrecordだけを用意 |

3方式のscripted結果は同一になる。これはjudgeがscriptedだからであり、実modelの精度、3方式の判別力、理解向上の証拠ではない。

### scripted contractの結果

`tests/html-sync/tests/evaluation.rs` の `scripted_contract_has_no_wrong_sync_and_counts_holds_and_false_stops` が、各methodについて次をassertする。

| method | right | wrong | hold | false-stop | sync | reject |
| --- | --- | --- | --- | --- | --- | --- |
| normal_llm | 23 | 0 | 3 | 1 | 4 | 20 |
| jev（scripted） | 23 | 0 | 3 | 1 | 4 | 20 |
| decisions（scripted） | 23 | 0 | 3 | 1 | 4 | 20 |

fixture IDごとの期待/実結果（`normal_llm`。Jev/Decisionsもscriptedでは同じ）:

| fixture / case | expected | actual | classification |
| --- | --- | --- | --- |
| `eval-glossary-001/positive` | sync | sync | right |
| `eval-glossary-001/avoid-term` | reject | reject | right |
| `eval-glossary-001/permission` | reject | reject | right |
| `eval-glossary-001/hidden` | reject | reject | right |
| `eval-glossary-001/injection` | hold | hold | hold |
| `eval-adr-001/positive` | sync | sync | right |
| `eval-adr-001/negation` | reject | reject | right |
| `eval-adr-001/caveat` | reject | reject | right |
| `eval-adr-001/threshold` | reject | reject | right |
| `eval-adr-001/code` | reject | reject | right |
| `eval-adr-001/link` | reject | reject | right |
| `eval-adr-001/fake-edge` | reject | reject | right |
| `eval-adr-001/stale` | hold | hold | hold |
| `eval-spec-001/positive` | sync | sync | right |
| `eval-spec-001/negation` | reject | reject | right |
| `eval-spec-001/permission` | reject | reject | right |
| `eval-spec-001/viewport` | reject | reject | right |
| `eval-spec-001/code` | reject | reject | right |
| `eval-spec-001/link` | reject | reject | right |
| `eval-spec-001/table` | reject | reject | right |
| `eval-plan-001/positive` | sync | sync | right |
| `eval-plan-001/order` | reject | reject | right |
| `eval-plan-001/hidden` | reject | reject | right |
| `eval-plan-001/threshold` | reject | reject | right |
| `eval-plan-001/fake-value` | reject | reject | right |
| `eval-plan-001/injection` | hold | hold | hold |
| `eval-plan-001/false-stop-probe` | sync | reject | false-stop |

false-stopは、正しいalternative reconstructionをscripted judgeが過剰に停止した診断用caseである。誤同期0（negative/expected-holdがsyncにならない）と、hold・false-stopを別々に数えることを確認するためのもので、実modelの誤停止率ではない。

### 人間観測record

`manifest.json` の `humanObservation` と単体file `human-observation.template.json` は `status: not_run`、`result: not_run` で、次を記録できる。

- `documentVersion.sourceDigest` / `documentVersion.fixtureVersion`
- `observer.name` / `observer.role` / `observer.independent`
- `method.provider` / `method.profileId` / `method.model`
- `startedAt` / `durationSeconds`
- `readingTasks[].correct` / `readingTasks[].answer` / `readingTasks[].wrongAnswer`
- `wrongAnswers` / `difficultyNotes` / `assistance`

初期recordはobserver名・所要時間・誤答・困難点を空/nullのままにし、testはsynthetic結果を入れていないことをassertする。

### opt-in実評価のapproval gate

`manifest.json` の `realEvaluation` と単体file `real-evaluation.approval.json` は `status: not_run`、`externalRequests: 0`。runnerは送信前に次をすべて要求し、1つでも欠ければtransportを呼ばずに拒否する。

- `status: approved`、`approvedBy`、`approvedAt`
- `connection.provider` / `connectionId` / `endpointClass` / `model`
- 評価set内のexact `fixtures` とexact `dataKinds`（Task 24のfixtureは`["text"]`。`image`の追加も拒否する）
- `requestBudget.maxRequests` / `perFixtureMax`（正の有限値、fixture数を満たす）
- `retryPolicy.maxAttempts`（1..=5）、`sameConnectionOnly: true`、`retryOn`
- `costApproval.feeCapUsd`（有限値）、`quotaLabel`、`quotaConfirmed: true`

Task 24のtestはin-processの `RecordingTransport` だけを使い、実provider、実credential、Keychain、login、socket、外部networkを使わない。承認済み経路のtestもscripted transportへの送信であり、実評価の成功ではない。実モデル評価はTask 25で、controllerが接続・exact fixture/data kind・有限request数/retry・料金/枠を提示し、別途人間の許可を得た後だけ行う。

### コマンド

```sh
cargo test -p herness-html-sync-tests --test evaluation --locked
```

Task 24実行時は `6 passed, 0 failed`。real pack presentのため `source-units` とstructural `candidate-check` も実行し、全正例がallow、宣言したstatic負例がdenyであることを確認した。外部requestは0。
