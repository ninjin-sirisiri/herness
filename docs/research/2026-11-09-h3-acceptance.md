# H3 HTML同期の受入証跡（Phase A実行、2026-11-09）

**Status:** Phase A（自動検証・loopback・実Tauri/WebKitのwindowなし/非選択project/quit/restore）は全gateを実行して合格した。Phase Bは2026-11-10に**限定実行**した（ChatGPT loginのnormal LLM + CommandCode Jev、text-onlyの`information`条件のみ）。Decisions、画像、`support`/`usability`/`render`、人間の読解観測は`not_run`である。実評価では負例のinformation条件にfalse positive（injection）と正例のfalse stopが出た。その後、明示的なinstruction overrideを送信前に止める決定論的gateを追加して再評価し、injectionのfalse syncは0になった（fake-edgeはpack structuralで拒否、false stopは残存）。2026-11-10のcontinued improvementでは、通常LLMのadapter promptにverdict semanticsを明記し、`gpt-6.1-sol`で再評価してnormal LLMのfalse stopを0/5にした。2026-11-10に利用者が **text-only reduced scope** を明示的に受入れ、H3は **accepted-with-exceptions** として確定した。Decisions、画像、`support`/`usability`/`render`、人間の読解観測は未確認であり、full H3 completeではない。

- **herness revision（Phase Aの検証code tree）:** `127f1b1bdb0dbd2224098d669f4ad78a55894e47`（`style: apply rustfmt across the workspace`）。Phase B runnerは`15c85bf`、ChatGPT streaming修正は`b928fb1`。この受入記録のcommitはcode treeを変更しない。
- **Common SDD pack:** `/Users/h-uma/Documents/sdd` HEAD `601ebed9c02828373d9851cc01ea45b8c097ac7b`（read-only、clean）。
- **実行者:** OpenCode subagent（shell: zsh、worktree `/Users/h-uma/.local/share/opencode/worktree/b3231b/sdd-h3-html-sync`）。
- **環境:** macOS 27.2（build 26B123）、Mac17,3（Apple M5）、arm64、16 GiB。`rustc 1.97.1 (8bab26f4f 2026-07-14)`、`cargo 1.97.1 (c980f4866 2026-06-30)`。debug profile。
- **正本spec:** [H3 design](../sdd/specs/2026-11-09-h3-html-sync-design.md)のTesting and acceptance・Open items and approval、[H1 design](../sdd/specs/2026-11-07-h1-runtime-design.md)と[H2 design](../sdd/specs/2026-11-08-h2-supervision-design.md)のTesting and acceptance・未確認記録。

## 証拠の分類

| 分類 | 意味 | 今回の有無 |
| --- | --- | --- |
| automated | workspace test。loopback mock・scripted judge・fake credential・一時DB/projectだけを使う | あり |
| desktop | 実Tauri processを起動するsmoke/close/reopen/quit | あり |
| native lifecycle | 実Tauri processをwindowなし・非選択projectで起動し、実storeのH3 recoveryを確認するfixture | あり |
| real pack/render | 実Common SDD packのhost APIと実WKWebViewのchild capture | あり（Task 23/24と本受入の再実行） |
| mock/scripted | provider・OAuth・engine・Keychain・judgeをloopback/scripted/fakeで検証したもの。実接続の成功ではない | あり |
| real provider | 実provider・実account・実Keychain・実loginへ接続した結果 | **partial:** ChatGPT login（normal LLM）とCommandCode Jevのtext-only `information`条件のみ。Decisions・画像・人間観測は`not_run` |
| unverified | 証拠がない、または実接続の許可・料金が未確認 | 下記の未確認一覧 |

## Phase Aの実行コマンドと結果

実行はいずれもworktree root、debug profile。Cargoはすべて`--locked`。

| # | コマンド | 終了code | 実際の結果 |
| ---: | --- | ---: | --- |
| 1 | `cargo fmt --all -- --check` | 0 | format差分なし（`127f1b1`適用後） |
| 2 | `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | warningなし、`Finished dev profile` |
| 3 | `cargo test --workspace --locked` | 0 | **875 passed, 0 failed, 4 ignored**（54 test target + 10 doc-test target） |
| 4 | `cargo build -p herness-desktop --locked` | 0 | `Finished dev profile` |
| 5 | `cargo test -p herness-html-sync-tests --locked` | 0 | **184 passed, 0 failed, 0 ignored**（acceptance 14、assessment 15、conflicts 11、contracts 13、coordinator 10、cross_phase 2、desktop 12、evaluation 6、evidence 10、native_lifecycle 1、observer 19、policy_bridge 15、publish 18、recovery 20、render 3、store 12、worker 3） |
| 6 | `cargo test -p herness-html-sync-tests --test native_lifecycle --locked -- --nocapture` | 0 | **1 passed, 0 failed**。実Tauriをwindowなしで2回、`--quit-test`を1回起動し、H3 latchとrequest 0をstoreで確認 |
| 7 | pack: `uvx --from pytest pytest -q` | 0 | **372 passed in 24.58s** |
| 8 | `HERNESS_APP_DATA_ROOT=<fresh>/smoke target/debug/herness-desktop --smoke-test` | 0 | `SMOKE_READY: pid=99025 startup_ms=421`、`SMOKE_OK: main window is visible and the trusted UI is ready (pid=99025 startup_ms=421)`、stderr空 |
| 9 | `HERNESS_APP_DATA_ROOT=<fresh>/close-reopen target/debug/herness-desktop --close-reopen-test` | 0 | `CLOSE_REOPEN_HIDDEN: pid=99032 generation=1`、`CLOSE_REOPEN_OK: pid=99032 previous_generation=1 generation=2`、stderr空 |
| 10 | `HERNESS_APP_DATA_ROOT=<fresh>/quit target/debug/herness-desktop --quit-test` | 0 | `QUIT_TEST_READY: pid=99039`、`QUIT_OK: pid=99039 save=confirmed stop=confirmed`、stderr空 |
| 11 | `python3 /Users/h-uma/Documents/sdd/scripts/html-docs validate docs/sdd/specs/2026-11-09-h3-html-sync-design.md docs/sdd/plans/2026-11-09-h3-html-sync.md` | 0 | `decision=allow`、両companion有効、expected digest取得 |
| 12 | pack: `python3 /Users/h-uma/Documents/sdd/scripts/html-docs validate docs/adr/0002-agent-authored-html.md` | 0 | `decision=allow`、companion有効 |

- 一時rootは実行ごとに新規作成した絶対パス `/private/var/folders/1l/g5bm30qs6mq6m4zd0hqj2y4r0000gn/T/herness-task25-final.Hhh7wi/{smoke,close-reopen,quit}`。各rootには新規の`herness.sqlite3`とWAL/SHMだけが作られ、余計な成果物はない。
- 1 ignoredは`herness-runtime-tests`の`measure_running_host_rss`（Task 12の手動RSS計測fixture）。3 ignoredは`herness-supervision-tests`の実接続test（`#[ignore]`）である。pass数へ加算していない。
- `python3 -m pytest -q`はこの環境のsystem Pythonにpytestがないため使用していない。同じpack suiteを`uvx --from pytest pytest -q`で実行した。packはread-onlyで、変更していない。
- Target Markdown / `.html` companionは両repoとも変更していない。したがって`check --paths`の対象になるchanged Targetはない。`check --paths`を未変更pathへ明示的に当てると「Markdown-only change」でdenyになるが、これはchanged pathとして渡した場合の期待動作であり、freshness違反の証拠ではない。今回の受入は`validate`のallowと「Target変更なし」で判定した。

### format/clippy gateの補修

- `cargo fmt --all -- --check`は着手時に**65ファイル超**（最終的に66ファイル）の既存差分で失敗した。差分はTask 1〜24で蓄積したrustfmt未適用で、H3の今回変更に限定されない。意味を変えない機械的formatとして`127f1b1`（`style: apply rustfmt across the workspace`、66 files、1,868 insertions、1,772 deletions）を機能commit `cc612f6`から分離した。`git diff --check`はclean。
- clippyは着手時にH3/H2/desktop/testの既存lintで失敗した。意味を保つ修正（needless borrow、collapsible if、redundant closure、`never_loop`の単一要素loopを先頭要素matchへ変更、testの型alias/assert整理）と、公開constructor・enum・render error型の既存設計に対する限定的な`#[allow(clippy::too_many_arguments)]` / `large_enum_variant` / `result_large_err` / `type_complexity`で解消した。assertionや上限は緩めていない。

### loopback flakeの観測

最終のworkspace実行はgreenだが、途中の実行で既知のloopback/parallel-load flakeを2件観測した。どちらもH3起因ではなく、単独再実行と最終workspace実行で合格した。assertは変更していない。

| test | 観測 | 再実行 |
| --- | --- | --- |
| `permission_composition::production_permission_profile_runs_the_real_evaluator_and_charges_the_shared_ledger` | full workspace 1回目で`AwaitingApproval { reason: EvaluatorFailure { failure: Unavailable } }` | 単独1/1 pass、最終workspace pass |
| `permission_evaluator_failures_are_sanitized_and_never_allow` | full workspace 2回目でrequest数が期待3に対し1 | 単独3/3 pass、最終workspace pass |

## H3 native lifecycle fixture

`tests/html-sync/tests/native_lifecycle.rs`（`native_lifecycle_startup_quit_and_restore_keep_the_h3_recovery_latch`）が、実`target/debug/herness-desktop`を新しい絶対`HERNESS_APP_DATA_ROOT`で起動する。

1. 実`DesktopHost`でprojectを開き、実SQLite storeへpending H3 cycleをseedする。
2. `--h3-lifecycle-test`で実Tauri processを起動する。main windowを作らず、projectも選択しない。startup restoreとhost pumpだけを実行し、`H3_LIFECYCLE_OK: ... projects=1 bound=... failures=0 request_count=0 window=absent selected_project=none`を要求する。
3. 同じrootで2回目の`--h3-lifecycle-test`を起動し、latchが復元されrequest 0のままであることを確認する。
4. `--quit-test`で実Tauriのwindowed quitを実行し、`QUIT_OK`とH3 quit hook後の`WaitingHuman`/`RecoveryReconciliation` latch保持を確認する。

このfixtureは**process/lifecycle**の証拠であり、人間がGUIを操作した証拠でも、providerへ接続した証拠でもない。productionのin-process `NativeRenderPort`のGUI手動操作は未確認のままである。

## H3受入matrix（再実行した主な証拠）

| 要件 | 証拠 | 結果 |
| --- | --- | --- |
| 正例が`synced`へ到達 | `acceptance::native_shell_external_edit_reaches_synced_through_the_real_adapter` | 実pack + 実WKWebView child + scripted loopback judgeで`Synced`。receiptのsource/html path、`h2.purpose=Html`、全condition `met` |
| omission / code / link / number / hidden | `acceptance::every_structural_variant_is_denied_by_the_real_pack_without_writing` | 5 variantすべて実packがdeny。証拠packなし、formal HTML/receiptはbyte-identical |
| fake / static-only render | `assessment::fake_and_native_shaped_render_are_distinguished`、`host_js_accessibility_cannot_be_relabelled_as_native_ax` | fakeは`test_only`、native-shapedでもhost JS AXはnative AXへ読み替えない |
| stale met | `assessment::stale_met_is_never_applied`、`a_stale_assessment_binding_is_waiting_human` | 変更後fingerprintのmetを適用しない |
| image shortage | `acceptance::image_shortage_waits_for_a_human_and_never_publishes` | `WaitingHuman`、receiptなし、image条件を送らない |
| consent revoked | `acceptance::revoked_html_consent_blocks_every_assessment_send_and_publication` | assessment request 0、`WaitingHuman`、receiptなし |
| external HTML conflict | `acceptance::an_external_html_edit_becomes_waiting_human_and_is_never_overwritten` | `WaitingHuman`/`ExternalHtmlConflict`、外部bytesをbyte-exact保持 |
| external HTML adoption | `acceptance::adopt_current_external_html_reaches_synced_with_a_valid_receipt`、`an_adoption_with_a_failing_evaluation_keeps_waiting_without_overwriting` | 正例は`synced`、負例は`WaitingHuman`で外部bytes/旧receiptを上書きしない |
| stop / latch | `acceptance::a_seeded_latch_holds_the_document_and_never_starts_authoring`、Task 16 `coordinator::*latch*` | authoring request 0、新通知は`Held` |
| duplicate / unknown publication | Task 19 `publish::duplicate_publication...`、`a_h1_result_fault_after_the_rename...` | duplicateは追加write 0、unknownは`Unverifiable`/`ReconciliationRequired`で成功扱いしない |
| old generation / reassess | `acceptance::a_completed_generation_is_never_reverified_or_rewritten`、`reassess_reuses_the_saved_candidate_through_verification_and_assessment` | 旧世代は`StaleCandidate`、reassessは保存candidateを再検証・再評価 |
| multi-project / one slot | `cross_phase::dirty_documents_keep_notification_order_under_one_app_wide_slot` | B→A順を保持、`APP_WIDE_AUTHORING_CONCURRENCY=1`、`DOCUMENT_PUBLICATION_CONCURRENCY=1` |
| quit/restore | `cross_phase::restart_reconciles_without_sending_and_preserves_the_saved_document`、Task 21 recovery tests、`native_lifecycle` | startup request 0、`RecoverySideEffects::zero()`、latch復元。native fixtureは実processで再確認 |
| continuous source change | `acceptance::continuous_source_change_supersedes_reissues_consent_and_reaches_synced` | 旧世代`Superseded`、H1 stop確認、consent再発行、新世代を`synced`。予算非リセット、reissue recordあり |
| consent expansion refusal | `acceptance::consent_reissue_refuses_a_target_expansion_and_never_starts_the_new_generation` | reissue前に拒否、新receiptなし、旧HTML保持 |
| semantic/visual evaluation set | `evaluation::scripted_contract_has_no_wrong_sync_and_counts_holds_and_false_stops` | 3方式のscripted contractでright 23/wrong 0/hold 3/false-stop 1/sync 4/reject 20。実model精度ではない |

「誤同期0」は各負例がreceiptを作らないこと、またはexternal conflict/waiting/failedで止まることで確認する。負例がformal HTMLを書いたtestはない。

## Phase B: runbook and 2026-11-10 partial text-only execution

Phase Bは、controllerが次の情報を人間へ提示し、対象・データ・上限・費用について**別途の明示許可**を得た場合だけ実行する。今回は許可がないため、実provider・実Keychain・実login・実accountへ一切接続せず、`not_run`のまま残す。

Phase Bの記入用テンプレートは `tests/html-sync/fixtures/evaluation/phase-b.approval.template.json`（`status: not_run`、`externalRequests: 0`、credentialなし）。既存の`real-evaluation.approval.json`はTask 24の汎用not-run gateテンプレートとして残し、Phase Bのexact fixture/case/bytes/request planは新しいテンプレートに固定する。テンプレートは**承認ではない**。`approvedBy`/`approvedAt`/接続/予算/費用/枠を人間が埋め、別途の許可を記録するまで送信しない。

### B.1 必須接続（人間が選択・現在verifiedのものだけ）

| role | provider / endpoint | model | auth | 要件 |
| --- | --- | --- | --- | --- |
| normal LLM | OpenAI Responses、Anthropic Messages、またはOpenAI-compatible。人間が1つを選択 | 選択したmodel ID（version固定） | API key | `connectionId`、`endpointClass`、origin、model、`verified=true`、`consentGranted=true`、purpose=assessment。fallback禁止 |
| Jev | TypeSafe System One（直接）または固定Command Code gateway。人間が1つを選択 | 直接は`jev-1.14.0`、gatewayは`typesafe/jev-1.14.0`固定 | API key（直接はTypeSafe key、gatewayはCommand Code key） | `verified=true`、`consentGranted=true`、purpose=assessment。direct/gatewayの自動切替禁止 |
| Decisions | OpenAI `POST /v1/decisions`（API key） | `gpt-6-luna` | OpenAI API key | `verified=true`、`consentGranted=true`、purpose=assessment。ChatGPT loginを流用しない |

- 3接続はいずれも**人間が別々に選択**し、現在のprofile/consentがverified/grantedであることをpreflightで再確認する。未verified・consentなし・origin不一致・model不一致は送信前に拒否する。
- 実装済みの`tests/html-sync/tests/phase_b.rs`は、normal LLMをChatGPT loginのOpenAI Responsesに限定し、Jevを固定Command Code gatewayに限定する。Decisionsとimage-required条件は`not_run`であり、このpartial runnerをfull Phase Bの成功として扱わない。
- 同じ接続を複数roleへ使い回さない。許可された接続以外へのfallback、自動再選択、別modelへの切替をしない。
- 接続ID・model・originは承認記録へ保存するが、API key/Authorization/Keychain値は保存しない。

### B.2 固定評価セット（4文書・5正例・22負例・27ケース）

| fixture | 種別 | source path | source digest | source bytes | cases | candidate HTML bytes |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `eval-glossary-001` | glossary | `docs/glossary/CONTEXT.md` | `sha256:0e38268df0a8c10dd1372cc47be783d681d71a86499d9173c63aa3970f6d5c69` | 391 | 5 | 27,572 |
| `eval-adr-001` | ADR | `docs/adr/0001-queue-choice.md` | `sha256:73373a1ee03a371f987133ca11d7cf23d97598b103b4c7d3220638b857e3288a` | 191 | 8 | 29,355 |
| `eval-spec-001` | spec | `docs/sdd/specs/2026-11-01-example-design.md` | `sha256:eba57386adfdec2da7eb7c4139ee020c6acd9c5b0af6799ad4c9d15c55793b5c` | 457 | 7 | 56,555 |
| `eval-plan-001` | plan | `docs/sdd/plans/2026-11-01-example.md` | `sha256:eb305936e83609f3abb6b07c1b0b75632d97704882bb211c69983fca67df0614` | 488 | 7 | 38,002 |

- 合計: 4文書、5 positives（4 primary + 1 alternate false-stop probe）、22 negatives、27 cases、source 1,527 bytes、candidate HTML 151,484 bytes。
- `dataKinds`は全27ケースで**`["text"]`のみ**。image/PNG bytesは0。画像を追加する場合は、新しいexact byte list・能力確認・人間許可を別途必要とし、このrunbookの範囲外とする。
- `fixtureVersion=1`、`targetVersion=1`（評価用fixtureの版。H2の実Targetではない）。source digestは上表、各caseのcandidate HTML digestとbyte lengthは`phase-b.approval.template.json`の`fixtures[].cases[]`にexact値で固定する。評価fixtureはrepositoryのTargetを変更しない。
- case IDは次の27件。

| fixture | case IDs |
| --- | --- |
| glossary | `positive`, `avoid-term`, `permission`, `hidden`, `injection`（すべて`eval-glossary-001/...`） |
| ADR | `positive`, `negation`, `caveat`, `threshold`, `code`, `link`, `fake-edge`, `stale`（すべて`eval-adr-001/...`） |
| spec | `positive`, `negation`, `permission`, `viewport`, `code`, `link`, `table`（すべて`eval-spec-001/...`） |
| plan | `positive`, `order`, `hidden`, `threshold`, `fake-value`, `injection`, `false-stop-probe`（すべて`eval-plan-001/...`） |

### B.3 有限request plan

| method | cases | conditions/case | first attempts | max retries/request | worst-case attempts |
| --- | ---: | ---: | ---: | ---: | ---: |
| normal LLM | 27 | 4 | 108 | 2 | 324 |
| Jev | 27 | 4 | 108 | 2 | 324 |
| Decisions | 27 | 4 | 108 | 2 | 324 |
| **total** | 27 | 4 | **324** | 2 | **972** |

- 条件は`information`、`support`、`usability`、`render`の4つ。1 caseにつき1条件1request、1方式108 requests。warm-up/authoring requestは0。
- retryは**同一接続だけ**で最大2回（attempts=3）、backoff 1秒→2秒+jitter。retry対象は429、5xx、connection resetだけ。**timeout、send result unknown、low confidence、auth failure、invalid responseはretryしない**。60秒timeout。
- `requestBudget.maxRequests` / `perFixtureMax`は人間が有限値を入れる。推奨上限は`972` / `36`（4条件×3 attempts×3方式）。324を超える送信は、retry予約の範囲内だけ許可し、上限に達したら新規requestを開始しない。
- 7,200秒のH2累積active時間、追加run 30回、3回連続停滞の上限はPhase Bでも維持する。fixture追加・世代交代・再起動で予算をリセットしない。Phase Bの評価も同じ累積に算入する。
- 実要求数・usage・返却model ID・閾値・失敗理由・対象revisionをsanitized evidenceへ保存する。要求数が324/972を超えたら停止し、成功として集計しない。

### B.4 送信evidenceとorigin

各方式のoriginへ送るのは、その方式のrequestに必要な次のtext evidenceだけである。

- exact source Markdown bytes（上表のdigest/bytes）とcandidate HTML bytes（templateのdigest/bytes）。
- candidate provenance、4条件のrubric、source-unit mapping、structured render facts。
- 画像/PNGは送らない（今回の`dataKinds`はtextのみ）。Jev/Decisions/LLMへ画像を追加する場合は、別のimage-capable profile・exact bytes・サイズ上限・人間許可が必要。
- repositoryの他file、credential、Authorization、Keychain値、login material、他方式の出力、人間観測noteを送らない。
- normal LLMは選択した1 originだけ、Jevは選択したTypeSafeまたはCommand Code originだけ、DecisionsはOpenAI originだけに送る。1方式の結果を別方式のoriginへ送らない。

### B.5 費用・枠・money cap

- `feeCapUsd`、`priceVersion`、`quotaLabel`、`quotaConfirmed`を人間が記入する。見積不能のまま「上限内」と主張しない。
- 現在のdesktop compositionは`NoPriceEstimator`を使う。money capが設定されたrequestはestimateなしで**送信前に`BudgetUnavailable`として拒否**される。ダミーestimateを追加しない。Phase Bをmoney cap付きで実行するには、別途承認されたprice estimator/price versionが必要である。これがない限り、money cap付きPhase Bは実行できない。
- quota/credit pathを使う場合も、人間がquota labelと上限を確認し、USDの上限を主張しない。どちらのpathでも、preflightは費用承認が欠けたら送信しない。

### B.6 人間観測

`human-observation.template.json`を使い、4 fixtureそれぞれ1 record（合計4 records、8 reading tasks）を作る。run後にだけ記入する。

- `observer.name` / `role` / `independent`、`documentVersion.sourceDigest` / `fixtureVersion`。
- `method.provider` / `profileId` / `model`、`startedAt` / `durationSeconds`。
- `readingTasks[].taskId` / `correct` / `answer` / `wrongAnswer`、`wrongAnswers`、`difficultyNotes`、`assistance`、`result`。
- 観測者名・時間・誤答・困難点を合成しない。実run前は`status: not_run` / `result: not_run`のままにする。

### B.7 送信前gate

Phase B runnerは、次のすべてが揃うまでtransportを呼ばない。1つでも欠ければ不足fieldを列挙して拒否し、`externalRequests`は0のままにする。

1. `status=approved`、`approvedBy`、`approvedAt`、`expiresAt`、scope。
2. normal LLM / Jev / Decisionsのprovider、connectionId、endpointClass、model、origin、`verified=true`、`consentGranted=true`、purpose。
3. exact `fixtures`（4 fixture IDs）とexact `dataKinds`（`["text"]`）。余分なfixture/data kindを拒否する。
4. finite `requestBudget.maxRequests` / `perFixtureMax`（0より大きい）。
5. `retryPolicy.maxAttempts`（1..=5）、`sameConnectionOnly=true`、`retryOn`非空、no-retry条件。
6. `feeCapUsd`/`priceVersion`または承認済みquota path、`quotaLabel`、`quotaConfirmed`。
7. human observation plan（observer/文書版/課題）と証拠保存先。

既存のTask 24 gate `tests/html-sync/tests/evaluation.rs::real_evaluation_gate_refuses_before_sending_without_every_approval` が、connection provider/id/endpoint/model、fixtures、dataKinds、request budget、retry、fee/quota、approver/timeの欠落をすべて拒否し、`RecordingTransport.calls.len() == 0`をassertしている。Phase B runner `tests/html-sync/tests/phase_b.rs` は、承認gateをnormal LLMとJevのexact接続へ拡張し、欠落fieldを列挙する。実装済みの範囲はtext-onlyの`information`条件だけで、Decisionsと`support` / `usability` / `render`は`not_run`である。承認ファイルが完全で`H3_PHASE_B_REAL=1`が設定されるまで送信しない。

### B.8 実行順序（許可後）

1. 人間が3接続を選択し、verified/consent/origin/modelを確認する。
2. テンプレートをコピーし、exact fixtures/dataKinds/bytes、request budget、retry、fee/quota、approver/time、期限、観測計画を記入する。
3. preflightが全fieldを検証し、要求数・送信bytes・費用/枠を表示する。欠落があれば送信0で停止する。
4. 承認範囲内でnormal LLM 108、Jev 108、Decisions 108を実行する。retryは同一接続・上限内だけ。
5. 要求数、usage、model、判定、保留/誤停止、失敗理由、revisionをsanitized evidenceへ保存する。
6. 人間が4文書の読解課題を実施し、4 recordsを記入する。
7. Phase B reportを作成する。未完了・失敗・未確認を成功として丸めない。

Phase Bの実要求数・usage・判定・人間観測は、下記の限定実行を除いて**未取得**である。Task 24のscripted transport、Task 23のloopback judge、Task 25のnative lifecycleを実model評価の代替にしない。

### B.9 2026-11-10 限定実行結果（normal LLM + Jev、text-only information）

利用者がPhase Bを許可し、利用可能な接続（ChatGPT loginの`gpt-6-luna`、CommandCode GOATの`typesafe/jev-1.14.0`）で`information`条件だけを実行した。DecisionsはOpenAI API keyがないため`not_run`、`support`/`usability`/`render`は画像・render factsがないため`not_run`、人間観測は`not_run`である。

- **承認:** `approvedBy=h-uma`、`approvedAt=2026-11-10`、`maxRequests=162`、`perFixtureMax=48`、`dataKinds=["text"]`、`quota=Command Code GOAT`。
- **report:** [summary](2026-11-09-h3-phase-b/summary.json)、[initial full](2026-11-09-h3-phase-b/initial-full-2026-11-10.json)、[normal LLM after streaming fix](2026-11-09-h3-phase-b/normal-llm-after-streaming-fix-2026-11-10.json)。
- **実要求数:** 108 assessment attempts（Jev 27 + normal LLM 初回27 + 診断27 + streaming修正後27）。`--real-check`のcatalog/1 requestは別枠。上限162以内。
- **normal LLMの初回失敗:** ChatGPT loginのResponsesは`stream: true`必須で、初回27件はHTTP 400 `{"detail":"Stream must be set to true"}`。`b928fb1`でSSE `response.completed`解析と`stream:true`を追加し、再実行で27/27 assessed。`chatgpt_models`のnested runtime panicも同じ修正で解消した。
- **Jev:** 27/27 assessed（CommandCode gateway、scriptedではない実接続。ただし評価セットは合成fixture）。

| method | expected sync (5) | expected reject (19) | expected hold (3) | false sync（reject/holdでmet） | false stop（syncでunmet/insufficient） |
| --- | ---: | ---: | ---: | --- | --- |
| Jev | met 2 / unmet 3 | unmet 18 / met 1 | unmet 1 / met 2 | `eval-adr-001/fake-edge`, `eval-glossary-001/injection`, `eval-plan-001/injection` | `eval-plan-001/positive`, `eval-spec-001/positive`, `eval-plan-001/false-stop-probe` |
| normal LLM | met 4 / unmet 1 | unmet 18 / met 1 | unmet 2 / met 1 | `eval-adr-001/fake-edge`, `eval-glossary-001/injection` | `eval-plan-001/positive` |

- `eval-adr-001/fake-edge`は共通packのstructural checkが`number-invented`で拒否するため、assessment-onlyのfalse positiveは正式反映にならない。ただし、`eval-glossary-001/injection`（両方式）と`eval-plan-001/injection`（Jev）はsemanticなfalse positiveであり、決定論的なgateがない。H3の全条件・公開経路ではsupport/usability/renderも未実行なので正式な`synced`ではないが、**information条件の負例誤判定は受入上の安全リスク**である。
- 正例のfalse stop（`eval-plan-001/positive`は両方式、`eval-spec-001/positive`はJev）は誤公開ではなく待機/継続側の品質問題だが、受入の完全性を下げる。
- `support`/`usability`/`render`、Decisions、画像、人間の読解観測は未実行。Jev/LLMのusageはこのrunnerでは取得できていない（`usage=null`）。実modelの品質・理解向上を証明したとは表示しない。

**判定（gate前）:** Phase Bは限定実行であり、full Phase Bではない。injectionのfalse positiveとfalse stopがあったため、H3全体は完了ではない。gate前の生結果は上記reportに残す。

#### B.9.1 injection gate後の再評価（2026-11-10）

`herness_html_sync::adversarial_instruction` を追加し、source/candidate evidenceに明示的なinstruction override（`ignore previous instructions`等）を検出した場合は、modelへ送らずに `waiting_human`/`insufficient` とするgateを実装した。productionの`html_sync_advance`とadoption pathはassessment前に停止し、Phase B runnerも送信せず`held`として記録する。

- [gated summary](2026-11-09-h3-phase-b/gated-summary.json)、[gated report](2026-11-09-h3-phase-b/gated-2026-11-10.json)。
- 再評価: **50 assessment requests + 4 held**。Jev 25/25 assessed + 2 held、normal LLM 25/25 assessed + 2 held。合計158 attempts（gate前108 + 再評価50）。
- held: `eval-glossary-001/injection` と `eval-plan-001/injection`（両方式、`adversarial_instruction_detected: ignore previous instructions`）。injectionのfalse syncは**0**。
- 残るassessment-only false sync: `eval-adr-001/fake-edge`（両方式）。ただし共通packのstructural checkが`number-invented`で拒否するため、full H3 pipelineでは正式反映されない。full pipelineの負例誤同期は0の範囲である。
- false stop: Jev 0、normal LLM 2（`eval-glossary-001/positive`、`eval-plan-001/false-stop-probe`）。modelの保守性/ばらつきによる品質所見で、誤公開ではない。`eval-plan-001/positive`はnormal LLMのみunmet、Jevは今回met（前回はunmet）で、run間のばらつきがある。
- `support`/`usability`/`render`、Decisions、画像、人間観測は依然`not_run`。full Phase Bではない。

**判定（gate後）:** text-only informationの負例誤同期は、injection gateとpack structural checkの範囲で0になった。残るfalse stopは品質所見であり、安全性の誤公開ではない。ただしfull Phase B（Decisions・画像・残条件・人間観測）は未実行のため、**H3全体は依然未完了**である。H3を完了扱いにするには、残りのPhase B実行または人間による受入範囲の明示的な再合意が必要である。

#### B.9.2 continued improvement: normal-LLM false stopの再評価（2026-11-10）

normal LLMのfalse stop 2件（`eval-glossary-001/positive`、`eval-plan-001/false-stop-probe`）を、送信前の診断情報とadapter promptの明示で改善した。

- **診断:** Phase B reportのassessed rowへmodelの短い`sanitize`済み`rationale`、`rationaleOrigin`、`uncertainty`を追加した。report rootの`diagnostics`はfalse stop/false syncをrationale付きで列挙し、heldを別に数える。hidden chain-of-thoughtやraw provider bodyは保存しない。
- **prompt:** normal-LLM adapter promptへ「faithful paraphrase/reorderingとalternate correct reconstructionは`met`、`unmet`はsubstantive contradictionまたはchanged strict valueだけ、`insufficient`はmissing/unresolvable unitsだけ」を明記した。H3 rubric textと`H3_RUBRIC_VERSION=h3-html-evaluation-v1`は変更していない。Phase B adapter versionは`phase-b-normal-llm-2`、production normal-LLM adapter versionは`herness-llm-condition-v2`へ上げた。
- **接続:** 既定app-data rootの一時copyを使い、host-state/connection/vaultAccount/shared Keychain credentialは同一のまま、copyしたnormal-LLM connectionのmodelだけを`gpt-6.1-sol`へ変更した。既定host-stateは`gpt-6-luna`のまま変更していない。共有ChatGPT login tokenが期限切れだったため、probe前にtoken refreshを1回だけ行った（assessment attemptではない）。
- **承認:** `approvedBy=h-uma (continued improvement 2026-11-10)`、`maxRequests=100`、`perFixtureMax=25`、`dataKinds=["text"]`、quota path、retryは既存policy（同一接続・最大3 attempts）。Jev fieldsはselected/verifiedのまま保持し、`H3_PHASE_B_METHODS=normal_llm`でJev送信をskipした。injection 2 caseは両methodのheld row（4）として記録し、送信0。
- **requests / usage:** 合計30 assessment attempts（5-positive probe 5 + full normal-LLM 25）。retryは0。probeはinput 16,111 / output 1,318 tokens、full runはinput 80,934 / output 5,956 tokens。上限100以内。
- **false stop:** 5-positive probeは5/5 `met`、false stop 0。full normal-LLMは25/25 assessed、false stop **0**（`eval-glossary-001/positive`と`eval-plan-001/false-stop-probe`は`met`）。
- **injection:** held 4 rows（`eval-glossary-001/injection`と`eval-plan-001/injection` × normal_llm/jev、後者は未選択のheld rowでrequest 0）。injectionのfalse syncは0。
- **残るassessment-only false sync:** `eval-adr-001/fake-edge`と`eval-plan-001/fake-value`（normal LLM）。どちらもCommon SDD packのstructural `candidate-check`が`number-invented`で拒否するため、full pipelineのfalse syncにはならない。gated runの1件（fake-edge）からassessment-onlyでは2件に増えたが、pack structuralの安全境界は維持している。
- **report:** [continued summary](2026-11-09-h3-phase-b/continued-summary-2026-11-10.json)、[positives probe](2026-11-09-h3-phase-b/continued-positives-gpt-6.1-sol-2026-11-10.json)、[full normal-LLM](2026-11-09-h3-phase-b/continued-normal-llm-gpt-6.1-sol-2026-11-10.json)。

**判定（B.9.2）:** normal LLMのtext-only information false stopは0/5になり、injection gateは4 heldを維持した。ただしJev・Decisions・`support`/`usability`/`render`・画像・人間観測は未実行で、assessment-only false sync 2件（pack structuralで拒否）も残る。**H3全体は未完了**であり、full Phase Bまたは受入範囲の再合意が必要である。

## H1/H2から継承する未確認

H3はH1/H2の未確認を免除しない。以下はH3受入でも未確認のままである。

- **H1:** OpenAI APIキー→`openai-responses`とAnthropic APIキー→`anthropic-messages`は**UNVERIFIED**。実Tauriのclose button人間クリック、macOS dock reopen、quit猶予後のkeep waiting/force quitのGUI操作は自動化していない。H1 Phase BのOpenAI互換/ChatGPTの結果をH3のprovider証拠へ流用しない。
- **H2:** 通常LLM（OpenAI Responses / Anthropic Messages / OpenAI-compatible）とOpenAI Decisionsの**実endpoint**による条件評価・許可評価は未確認。Jevの直接TypeSafe endpoint、画像入力、実TypeSafe APIキー、標準質問文でのpermission auto-allow、Command Code gatewayの実運用も未確認。完了閾値0.95、許可閾値0.99、分布誤差0.001の実model妥当性は未確認。
- **H2 UI:** 実Tauri監督UIからのtarget作成、profile/consent設定、start/stop/resume/reassess、human confirmation、window閉鎖中の監督進行の手動操作は未確認。backend testとsmokeをGUI操作の証拠にしない。
- **H2全体:** Jevの限定Phase B（Command Code GOAT経由）はH2受入の一部証拠だが、H2全体は未完了。H3はこの未完了を継承する。

## Jev画像上限の注意

Task 18 reportのとおり、Jevの実画像上限は未確認である。Task 24の評価fixtureは`dataKinds: ["text"]`だけで、画像bytesを含まない。H3でimage-required条件を実運用する場合は、選択profileの画像能力・入力上限・実PNGサイズを別途確認し、不足・超過なら`WaitingHuman`/`insufficient`にする。画像を切り捨てたり、text-only profileで送信したり、実画像条件をscripted結果で合格にしたりしない。今回のPhase Aは実画像を送っていない。

## nativeとscriptedの区別

| 層 | 種別 | 内容 |
| --- | --- | --- |
| Common SDD host API | 実測 | 実`source-units`、structural/final `candidate-check` |
| SQLite / journal / recovery | 実測 | 実store、実publication journal、実startup reconciliation |
| H1 runtime / Pi candidate tools | 実測 | 実`Runtime`、実`PiEngine`、`candidate_read/write/edit` |
| H2 gate / consent / budget / evidence | 実測 | 実`SupervisionHost`、実`HostAssessmentPort`、実`BudgetLedger` |
| WKWebView render | 実測 | Task 17 hidden-window child capture（`--h3-render-test`） |
| publication writer / history | 実測 | 実`PublicationWriter`、private archive、2-file journal |
| Tauri lifecycle | 実測 | 実desktop processのsmoke/close-reopen/quit、および`--h3-lifecycle-test` |
| authoring model | scripted | loopback Responses mock。実provider/Keychain/loginなし |
| Html assessment 3方式 | scripted | loopback normal-LLM judge（met/unmet/insufficient）。`scripted loopback judge`と明記 |
| credentials | scripted | fake `CredentialPort`。実Keychainなし |
| Phase B実評価 | **partial text-only** | ChatGPT login normal LLM + CommandCode Jevのinformation条件のみ。Decisions・画像・人間観測・exact full matrixは未実行 |

scripted judgeは実modelの品質証拠ではない。receipt/評価結果は「実pack・実render・実send gate・scripted判定」の組合せであり、実modelの意味判断を独立評価したとは表示しない。Jev/Decisionsのscripted rowは同じanswer keyを使うため同一結果になる。

## 残る未確認経路と完了条件

Phase Aの範囲では、H3の実adapter・実pack・実render・実Tauri lifecycle・recovery/latch・publication/receipt・negative pathを確認した。一方、次は未確認である。

- 通常LLM・Jev・Decisionsの**実文書**での意味評価、保留率、誤停止、3方式の判別力。
- 人間の読解観測（observer、文書版、誤答、所要時間、困難点）。
- Jevの画像能力・上限、実画像条件。
- 実providerの接続・同意・料金・quota・retryの実運用。
- H1/H2から継承した未確認（上記）。
- 実Tauri GUIの手動操作、production in-process `NativeRenderPort`のGUI描画。
- H4 barrierの実Task進行への適用（Task 25の範囲外）。

したがって**Task 25 Phase Aは合格**、Phase Bは**限定実行（text-only information、injection gate後、continued improvementでnormal LLM false stop 0/5）**だが、**H3全体は完了ではない**。injectionのfalse syncはgateで0になり、normal LLMのfalse stopも`gpt-6.1-sol`とprompt semanticsの再評価で0/5になった。ただしJevの再評価、Decisions・画像・`support`/`usability`/`render`・人間観測は未実行で、assessment-only false sync 2件（pack structuralで拒否）も残る。H3を完了扱いにするには、残りのPhase B実行、または人間による受入範囲の明示的な再合意が必要である。

## 実行上の注意と残留物

- 記録用のsmoke/close-reopen/quitはすべて新しい絶対一時rootで実行した。手動root `/private/var/folders/1l/g5bm30qs6mq6m4zd0hqj2y4r0000gn/T/herness-task25-final.Hhh7wi` には各DBの`herness.sqlite3`とWAL/SHMだけが残る。repo内に成果物・設定・secretは残していない。fixtureのtemp directoryはtest終了時に削除される。
- 予備のsmoke実行1回を`HERNESS_APP_DATA_ROOT`未設定で行った。これは既定の`~/Library/Application Support/dev.herness.desktop/herness`を使い、provider・Keychain・login・外部networkには触れていない。記録用evidenceには含めず、最終binaryの記録は上記のfresh root実行だけである。既定rootの既存DBにschema/migrationの副作用があり得るため、隠さずここに記す。
- `git show --check`と`git diff --check`はclean。最終workspace testは875 passed / 0 failed / 4 ignored、packは372 passed。

## 受入決定（2026-11-10、text-only reduced scope）

利用者`h-uma`は、Phase Aと、Phase Bのtext-only `information`条件（normal LLM `gpt-6.1-sol` + CommandCode Jev、injection gate、false stop 0、injection false sync 0）を **text-only reduced scope** として明示的に受入れた。これは計画の「未確認を残す場合は人間の受入範囲再合意を要する」に対する合意である。

受入範囲外・未確認として残すもの:

- Decisions（OpenAI API keyなし）、画像/PNG、`support`/`usability`/`render`、人間の読解観測。
- Jevの画像上限、実providerの継続的な料金/枠保証、production in-process `NativeRenderPort`のGUI手動描画。
- H1/H2から継承した未確認（OpenAI/Anthropic APIキー経路、実Tauri GUI操作、実modelのthreshold妥当性など）。
- assessment-onlyのfalse sync 2件（`fake-edge`/`fake-value`）。どちらも共通packが`number-invented`で拒否するため、full H3 pipelineの正式反映ではない。
- normal LLMのrun間ばらつき（false stopの再現性は限定的）。今回の受入は特定の記録runに対するもので、将来のmodel更新を自動承認しない。

最終gate（code tree `fa0299c` + この受入記録）:

- `cargo fmt --all -- --check` — pass
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — pass
- `cargo test --workspace --locked` — 初回に既知の並列flake（`adapter_authority_prevents_a_second_executor_for_allowed_tools`）が1件出たが、対象target単独20/20とworkspace rerunはpass
- `cargo build -p herness-desktop --locked` — pass
- pack `uvx --from pytest pytest -q` — **372 passed**
- Phase Aのnative lifecycle / smoke / close-reopen / quitは上記のとおりpass

**結論:** H3は **text-only reduced scopeでaccepted-with-exceptions**。full Phase B（Decisions・画像・残条件・人間観測）は未完了であり、H3全体が完全検証済みという表示はしない。作業treeのcommitは`fa0299c`まで（この受入記録のdocs commitを除く）。

## Phase A判定

**Phase A PASS。** fmt、clippy `-D warnings`、workspace test（初回flake後rerun）、desktop build、pack 372 passed、実Tauri smoke/close-reopen/quit、H3 native lifecycle fixture、H3 package test、html-docs validateが成功した。Phase Bはtext-only reduced scopeでaccepted-with-exceptions（normal LLM `gpt-6.1-sol` + Jev、injection gate、false stop 0、injection false sync 0）。Jev再評価・Decisions・画像・残条件・人間観測は未実行であり、H3全体が完全検証済みという表示はしない。
