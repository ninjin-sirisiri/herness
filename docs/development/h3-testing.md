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

## H3受入（Task 25、Phase A）

受入の詳細な証跡は [H3 acceptance](../research/2026-11-09-h3-acceptance.md) に保存する。この節は再現コマンドと現在の状態だけを記録する。

### revision

- herness: `127f1b1bdb0dbd2224098d669f4ad78a55894e47`（code tree。機能変更は`cc612f6`、formatのみの`127f1b1`）
- Common SDD pack: `/Users/h-uma/Documents/sdd` HEAD `601ebed9c02828373d9851cc01ea45b8c097ac7b`（read-only、clean）
- 環境: macOS 27.2（26B123）、Mac17,3（Apple M5）、arm64、16 GiB、`rustc/cargo 1.97.1`、debug build

### 実行コマンドと結果

worktree rootで実行する。Cargoはすべて`--locked`。

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build -p herness-desktop --locked
cargo test -p herness-html-sync-tests --test native_lifecycle --locked -- --nocapture
```

| command | result |
| --- | --- |
| `cargo fmt --all -- --check` | 0。既存66ファイルのformat差分を`127f1b1`で別commitにした後は差分なし |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0。warningなし |
| `cargo test --workspace --locked` | **875 passed, 0 failed, 4 ignored**（54 test target + 10 doc-test target）。ignoredはmanual RSS 1件と実接続3件 |
| `cargo test -p herness-html-sync-tests --locked` | **184 passed, 0 failed**。native_lifecycle 1件を含む |
| `cargo build -p herness-desktop --locked` | 0。`Finished dev profile` |
| pack `uvx --from pytest pytest -q` | **372 passed in 24.58s**。`python3 -m pytest -q`はsystem Pythonにpytestがないため同じsuiteを`uvx`で実行 |
| `python3 /Users/h-uma/Documents/sdd/scripts/html-docs validate ...` | H3 spec/planとpack ADR 0002が`decision=allow`。Target Markdown/`.html`は両repoとも未変更のため`check --paths`の対象なし |

### H3 native lifecycle fixture

`tests/html-sync/tests/native_lifecycle.rs` は、実SQLiteへpending H3 cycleをseedし、実`target/debug/herness-desktop`を新しい絶対`HERNESS_APP_DATA_ROOT`で起動する。`--h3-lifecycle-test`はmain windowを作らずprojectも選択しない。startup restoreとhost pumpだけを実行し、`H3_LIFECYCLE_OK: ... projects=1 bound=... failures=0 request_count=0 window=absent selected_project=none`を要求する。同じrootで2回目の起動（restore）と`--quit-test`（実quit hook）も行い、`WaitingHuman`/`RecoveryReconciliation` latchとrequest 0をstoreで確認する。fixtureはprocess/lifecycleの証拠であり、provider接続や人間のGUI操作の証拠ではない。

実Tauriのsmoke/close-reopen/quitは、fresh absolute rootで次を確認した。

```sh
HERNESS_APP_DATA_ROOT=<fresh>/smoke target/debug/herness-desktop --smoke-test
HERNESS_APP_DATA_ROOT=<fresh>/close-reopen target/debug/herness-desktop --close-reopen-test
HERNESS_APP_DATA_ROOT=<fresh>/quit target/debug/herness-desktop --quit-test
```

結果は`SMOKE_OK`、`CLOSE_REOPEN_OK`、`QUIT_OK save=confirmed stop=confirmed`。いずれもexit 0、stderr空。H3 stateを含むrootでは`--h3-lifecycle-test`と`--quit-test`をfixtureが実行する。

### 既知のflake

最終workspaceはgreenだが、途中でH2のloopback/parallel-load flakeを2件観測した。`production_permission_profile_runs_the_real_evaluator_and_charges_the_shared_ledger`の`EvaluatorFailure::Unavailable`と、`permission_evaluator_failures_are_sanitized_and_never_allow`のrequest数不足である。どちらも単独再実行と最終workspaceで合格し、assertは変更していない。H3起因ではない。

### Phase B gate and 2026-11-10 partial execution

Phase Bは2026-11-10に**限定実行**した。利用可能な接続はChatGPT login（normal LLM、`gpt-6-luna` → continued runでは`gpt-6.1-sol`）とCommandCode GOAT Jev（`typesafe/jev-1.14.0`）だけで、実行したのはtext-onlyの`information`条件のみ。Decisions、`support`/`usability`/`render`、画像、人間の読解観測は`not_run`である。injectionのfalse positiveとfalse stopが出たためgateを追加し、continued improvementではnormal LLMのfalse stopを0/5にした。2026-11-10に利用者が **text-only reduced scope** を明示的に受入れ、H3は **accepted-with-exceptions** として確定した。Decisions・画像・残条件・人間観測は未確認であり、full H3 completeではない。詳細は[受入証跡](../research/2026-11-09-h3-acceptance.md)のB.9と`docs/research/2026-11-09-h3-phase-b/`。

記入用のexact templateは`tests/html-sync/fixtures/evaluation/phase-b.approval.template.json`。`status: not_run`、`externalRequests: 0`で、credential・承認・実接続を含まない。既存の`real-evaluation.approval.json`はTask 24の汎用not-run gateテンプレートとして残す。

opt-in runnerは`tests/html-sync/tests/phase_b.rs`。normal LLM（ChatGPT login）とJev（Command Code固定gateway）の`information`条件だけを実装し、`support` / `usability` / `render`とDecisionsは`not_run`として記録する。通常のtest runではignoredで、`H3_PHASE_B_REAL=1`と完全な承認ファイルが揃うまで送信しない。実runは別途の人間許可後だけ行う。

```bash
cargo test -p herness-html-sync-tests --test phase_b --locked
```

承認後の実run（2026-11-10に限定実行済み。`COMMANDCODE_API_KEY`は事前に環境へ設定し、command line・approval・reportへ書かない）:

```bash
H3_PHASE_B_REAL=1 \
H3_PHASE_B_APPROVAL=/absolute/path/to/filled-phase-b.approval.json \
H3_PHASE_B_REPORT=/absolute/path/to/phase-b-report.json \
H3_PHASE_B_METHODS=normal_llm \
HERNESS_APP_DATA_ROOT=/absolute/path/to/copied/app-data-root \
cargo test -p herness-html-sync-tests --test phase_b --locked -- --ignored --nocapture
```

`H3_PHASE_B_METHODS`はカンマ区切りの`normal_llm` / `jev`で、未選択methodはprepareもsendもせず`not_run`として記録する。`H3_PHASE_B_CASES=positives`はexpected-syncの5 positivesだけを診断対象にし、`H3_PHASE_B_CASES=<caseId,...>`はexact case filterになる。`H3_PHASE_B_DIAGNOSTIC=1`はpartial診断runの最終completeness panicだけを緩め、approval gate・injection gate・budgetは緩めない。injection caseはcase filterやmethod filterに関係なくheld rowとして記録され、送信されない。

**接続（人間が別々に選択、現在verifiedのものだけ）**

| role | provider/endpoint | model | auth |
| --- | --- | --- | --- |
| normal LLM | OpenAI Responses（実装済みrunnerはChatGPT loginのみ） | 選択model（version固定） | ChatGPT login（Keychain） |
| Jev | 固定Command Code gateway（実装済みrunnerは直接TypeSafeを自動選択しない） | `typesafe/jev-1.14.0` | Command Code API key |
| Decisions | OpenAI `/v1/decisions` | `gpt-6-luna` | 実装済みrunnerでは`not_run` |

各接続は`connectionId`、`endpointClass`、origin、model、`verified=true`、`consentGranted=true`、purpose=assessmentを要求する。fallback・自動切替・API-key substitution・ChatGPT loginのDecisions流用を禁止する。

**fixtureとbytes**

- 4文書（glossary / ADR / spec / plan）、5 positives（4 primary + 1 alternate false-stop probe）、22 negatives、27 cases。
- source 1,527 bytes、candidate HTML 151,484 bytes。`dataKinds`は全case `["text"]`。image/PNG bytesは0。
- fixture IDとsource digestは`eval-glossary-001` `sha256:0e3826...`、`eval-adr-001` `sha256:73373a...`、`eval-spec-001` `sha256:eba573...`、`eval-plan-001` `sha256:eb3059...`。caseごとのcandidate bytes/digestはtemplateに固定。
- `fixtureVersion=1`、`targetVersion=1`（評価用fixtureの版。H2の実Targetではない）。評価fixtureはrepository Targetを変更しない。

**request plan**

- 4条件（information/support/usability/render）×27 cases = **108 requests/method**。
- normal LLM 108 + Jev 108 + Decisions 108 = **324 first attempts**。warm-up/authoring 0。
- retryは同一接続で最大2回（attempts=3）、1秒→2秒+jitter。429/5xx/connection resetだけ。timeout/send unknown/low confidence/auth/invalid responseはretryしない。60秒timeout。実装済みtext-only runner（information条件×normal LLM+Jev）はfirst attempts 54、worst case 162なので、推奨`maxRequests=162` / `perFixtureMax=48`。`H3_PHASE_B_METHODS=normal_llm`の場合はselected first attempts 27（25 sendable + 2 held）、worst case 81、per-fixture worst 24なので、`maxRequests=100` / `perFixtureMax=25`で足りる（2026-11-10 continued runの承認値）。full 3-method/4-conditionのhard upper boundは972のまま。
- 7,200秒累積active、追加run 30回、3回連続停滞の上限を維持し、fixture追加・世代交代・再起動でリセットしない。

**費用・gate**

- `feeCapUsd`/`priceVersion`または承認済みquota path、`quotaLabel`、`quotaConfirmed`が必要。現在のdesktop compositionは`NoPriceEstimator`のため、money cap付き送信はestimateなしで**送信前に拒否**される。ダミーestimateを追加しない。money cap付きで実行するには別途承認されたprice estimatorが必要である。
- 送信前gateはconnection（3 role）、exact fixtures/dataKinds、finite request budget、retry policy、fee/quota、approver/time、scope/期限のすべてを要求し、欠落時は不足fieldを列挙して送信0で拒否する。
- 既存の`tests/html-sync/tests/evaluation.rs::real_evaluation_gate_refuses_before_sending_without_every_approval`が、provider/connectionId/endpointClass/model、fixtures、dataKinds、maxRequests/perFixtureMax、retry、fee/quota、approvedBy/approvedAtの欠落を拒否し、`RecordingTransport.calls.len() == 0`をassertしている。Phase B runnerはこのgateをnormal LLM + Jevのexact接続へ拡張して再利用する。production runnerは`tests/html-sync/tests/phase_b.rs`に実装済み。

**2026-11-10 限定実行結果（gate前）**

| method | requests | assessed | false sync (information) | false stop |
| --- | ---: | ---: | --- | --- |
| Jev | 27 | 27 | `eval-adr-001/fake-edge`, `eval-glossary-001/injection`, `eval-plan-001/injection` | `eval-plan-001/positive`, `eval-spec-001/positive`, `eval-plan-001/false-stop-probe` |
| normal LLM | 27 | 27（SSE修正後） | `eval-adr-001/fake-edge`, `eval-glossary-001/injection` | `eval-plan-001/positive` |

**2026-11-10 injection gate後の再評価**

`herness_html_sync::adversarial_instruction`を追加し、`ignore previous instructions`等の明示的なinstruction overrideを検出したevidenceは、modelへ送らず`waiting_human`/`insufficient`にした。productionの`html_sync_advance`/adoption pathとPhase B runnerの両方に適用する。

| method | requests | assessed | held (injection) | false sync | false stop |
| --- | ---: | ---: | ---: | --- | --- |
| Jev | 25 | 25 | 2 | `eval-adr-001/fake-edge`（pack structuralで拒否） | 0 |
| normal LLM | 25 | 25 | 2 | `eval-adr-001/fake-edge`（pack structuralで拒否） | `eval-glossary-001/positive`, `eval-plan-001/false-stop-probe` |

- heldは`eval-glossary-001/injection`と`eval-plan-001/injection`（両方式、request 0）。injectionのfalse syncは0。
- `eval-adr-001/fake-edge`はassessment-onlyではmetだが、共通packが`number-invented`で拒否するため正式反映されない。full pipelineの負例誤同期は0の範囲。
- normal LLMのfalse stopはmodelの保守性/run間ばらつきによる品質所見で、誤公開ではない。
- 再評価は50 requests + 4 held、gate前108 attemptsと合わせて158 attempts。reports: `gated-summary.json`、`gated-2026-11-10.json`。

**2026-11-10 continued improvement（normal-LLM-only、`gpt-6.1-sol`）**

normal LLMのfalse stop 2件（`eval-glossary-001/positive`、`eval-plan-001/false-stop-probe`）を診断・改善した。Phase B reportはassessed rowにmodelの短い`sanitize`済み`rationale`、`rationaleOrigin`、`uncertainty`を保存し、report rootの`diagnostics`がfalse stop/false syncをrationale付きで列挙する。hidden chain-of-thoughtやraw provider bodyは保存しない。normal-LLM adapter promptには、faithful paraphrase/reorderingとalternate correct reconstructionは`met`、`unmet`はsubstantive contradictionまたはchanged strict valueだけ、`insufficient`はmissing/unresolvable unitsだけ、というverdict semanticsを明記した。H3 rubric textと`H3_RUBRIC_VERSION=h3-html-evaluation-v1`は変更せず、adapter versionだけを`phase-b-normal-llm-2`（production `herness-llm-condition-v2`）へ上げた。

既定app-data rootの一時copyを使い、host-state/connection/vaultAccount/shared Keychain credentialは同一のまま、copyしたnormal-LLM connectionのmodelだけを`gpt-6.1-sol`へ変更した。既定host-stateは`gpt-6-luna`のまま変更していない。共有ChatGPT login tokenが期限切れだったため、probe前にtoken refreshを1回だけ行った（authentication requestでありassessment attemptではない）。Jev fieldsはselected/verifiedのまま保持し、`H3_PHASE_B_METHODS=normal_llm`でJev送信をskipした。injection 2 caseは両methodのheld row（4）として記録し、送信0。

| run | requests | assessed | held | false stop | assessment-only false sync | usage (input/output) |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 5-positive probe | 5 | 5 | 4 | 0 | 0 | 16,111 / 1,318 |
| full normal-LLM | 25 | 25 | 4 | 0 | `eval-adr-001/fake-edge`, `eval-plan-001/fake-value` | 80,934 / 5,956 |

- 承認: `approvedBy=h-uma (continued improvement 2026-11-10)`、`maxRequests=100`、`perFixtureMax=25`、`dataKinds=["text"]`、quota path、retryは既存policy。合計30 assessment attempts、retry 0。上限100以内。
- false stop: probe 5/5 `met`、full 25/25 assessedで**0**。`eval-glossary-001/positive`と`eval-plan-001/false-stop-probe`は`met`。
- injection: held 4 rows（`eval-glossary-001/injection`/`eval-plan-001/injection` × normal_llm/jev、後者は未選択のheld rowでrequest 0）。injection false sync 0。
- 残るassessment-only false sync 2件は、どちらもCommon SDD pack structural `candidate-check`が`number-invented`で拒否する。full pipelineのfalse syncにはならない。
- reports: `docs/research/2026-11-09-h3-phase-b/continued-summary-2026-11-10.json`、`continued-positives-gpt-6.1-sol-2026-11-10.json`、`continued-normal-llm-gpt-6.1-sol-2026-11-10.json`。
- no-send verification: `cargo test -p herness-html-sync-tests --test phase_b --locked`（12 passed / 1 ignored real run）、`cargo test -p herness-html-sync --locked`、`cargo test -p herness-assessment --locked`（24 passed）、`cargo fmt --all -- --check`、`cargo check --workspace --locked`。`herness-supervision-tests`のfull suiteはparallel-loadの既知flakeを2件観測し、各testの単独再実行はgreen。real runは引き続き`H3_PHASE_B_REAL=1`と完全なapprovalがない限り実行されない。
- Jev再評価・Decisions・`support`/`usability`/`render`・画像・人間観測は未実行。H3はtext-only reduced scopeで**accepted-with-exceptions**であり、full H3 completeではない。

- `eval-adr-001/fake-edge`は共通packの`number-invented`で正式反映前に拒否されるが、injectionは決定論的gateがなく、semanticなfalse positiveとして残る。
- normal LLMの初回27件はChatGPT ResponsesのHTTP 400 `Stream must be set to true`で失敗した。`b928fb1`で`stream:true`とSSE `response.completed`解析を追加して再実行し、27/27 assessed。`chatgpt_models`のnested runtime panicも同期コマンド化で修正した。
- reports: `docs/research/2026-11-09-h3-phase-b/summary.json`、`initial-full-2026-11-10.json`、`normal-llm-after-streaming-fix-2026-11-10.json`。合計108 assessment attempts。

**人間観測**

`human-observation.template.json`を使い、4 fixture×1 record（8 reading tasks）を作る。observer/role/independent、documentVersion.sourceDigest/fixtureVersion、method/provider/profile/model、startedAt/durationSeconds、readingTasksのcorrect/answer/wrongAnswer、wrongAnswers、difficultyNotes、assistance、resultをrun後にだけ記入する。合成結果を入れない。

**実行順序（許可後）**

1. 3接続を選択しverified/consent/origin/modelを確認する。
2. templateをコピーし、exact fixtures/dataKinds/bytes、budget、retry、fee/quota、approver/time、期限、観測計画を記入する。
3. preflightが全field・要求数・bytes・費用/枠を表示し、欠落時は送信0で停止する。
4. 承認範囲内で3方式を実行し、retryは同一接続・上限内だけ。
5. 要求数/usage/model/判定/保留/誤停止/失敗/revisionをsanitized evidenceへ保存する。
6. 人間が4文書を読み、4 recordsを記入する。
7. 未完了・失敗・未確認を成功として丸めない。

許可がない限り実Keychain・login・providerへ接続しない。Phase Bの結果をscripted judgeやnative lifecycleで代用しない。Jevの画像上限は未確認で、不足・超過は`WaitingHuman`/`insufficient`にする。

H1/H2の未確認（OpenAI/Anthropic APIキー経路、通常LLM/Decisions実接続、Jev標準permission auto-allow、実Tauri GUI手動操作、閾値の実model妥当性）はH3でも未確認のままである。Phase Aは合格し、Phase Bはtext-only reduced scopeとして人間が明示的に受入れた。full Phase Bと上記未確認は残るため、**H3全体が完全検証済みとは表示しない**。
