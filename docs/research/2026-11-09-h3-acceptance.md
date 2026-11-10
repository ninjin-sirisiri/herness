# H3 HTML同期の受入証跡（Phase A実行、2026-11-09）

**Status:** Phase A（自動検証・loopback・実Tauri/WebKitのwindowなし/非選択project/quit/restore）は全gateを実行して合格した。Phase B（通常LLM・Jev・Decisionsの実文書評価と人間の読解観測）は**未許可・未実行（`not_run`）**である。未確認経路を残したままTask 25やH3全体を完了扱いにしない。

- **herness revision（検証したcode tree）:** `127f1b1bdb0dbd2224098d669f4ad78a55894e47`（`style: apply rustfmt across the workspace`）。機能変更は`cc612f6`、既存format差分は`127f1b1`。この受入記録のcommitはcode treeを変更しない。
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
| real provider | 実provider・実account・実Keychain・実loginへ接続した結果 | **H3ではなし（Phase B `not_run`）** |
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

## Phase B: `not_run`（未許可）

Phase Bは、controllerが次の情報を人間へ提示し、対象・データ・上限・費用について**別途の明示許可**を得た場合だけ実行できる。今回は許可がないため、実provider・実Keychain・実login・実accountへ一切接続せず、`not_run`のまま残す。

1. **接続:** provider、endpoint class、connection ID、model ID/version、認証方式、origin、接続の由来。許可された接続だけを列挙し、fallbackを禁止する。
2. **fixtureと送信bytes:** Task 24のexact fixture IDとexact `dataKinds`（text/image）。送信本文の分類、target scope、repository外fixtureであること。imageを追加する場合は実bytesとサイズ上限も提示する。
3. **有限要求:** fixture別・経路別の要求数、attempt上限、同一接続だけのretry、60秒timeout、全体の停止条件。無制限再試行と自動再評価をしない。
4. **費用・枠:** 金額上限（USD）と`PriceVersion`、または課金なしを保証する隔離手段、quota label/確認。見積不能な経路は人間の明示許可がない限り使わない。
5. **許可範囲・期限:** 許可された接続・fixture・要求数・費用・期間を記録し、範囲外は拒否する。secretを含めない。
6. **証拠:** 要求数、usage、返却model ID、閾値結果、失敗理由、対象revision、未確認範囲をsanitized evidenceとして保存する。provider本文・credential・Authorization・生URL・secretを保存しない。
7. **人間観測:** 観測者、独立性、文書版、読解課題、正誤、誤答、所要時間、困難点、assistanceを`human-observation.template.json`へ記録する。観測結果を合成しない。

Phase Bの実要求数・usage・判定・人間観測は**0件/未取得**である。Task 24のscripted transport、Task 23のloopback judge、Task 25のnative lifecycleを実model評価の代替にしない。

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
| Phase B実評価 | **not_run** | 実model・実provider・人間観測 |

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

したがって**Task 25 Phase Aは合格**だが、**H3全体は完了ではない**。H3を完了扱いにするには、人間がPhase Bを許可するか、未確認経路を免除する受入範囲を明示的に再合意する必要がある。どちらもない限り、Phase Bは`not_run`のままである。

## 実行上の注意と残留物

- 記録用のsmoke/close-reopen/quitはすべて新しい絶対一時rootで実行した。手動root `/private/var/folders/1l/g5bm30qs6mq6m4zd0hqj2y4r0000gn/T/herness-task25-final.Hhh7wi` には各DBの`herness.sqlite3`とWAL/SHMだけが残る。repo内に成果物・設定・secretは残していない。fixtureのtemp directoryはtest終了時に削除される。
- 予備のsmoke実行1回を`HERNESS_APP_DATA_ROOT`未設定で行った。これは既定の`~/Library/Application Support/dev.herness.desktop/herness`を使い、provider・Keychain・login・外部networkには触れていない。記録用evidenceには含めず、最終binaryの記録は上記のfresh root実行だけである。既定rootの既存DBにschema/migrationの副作用があり得るため、隠さずここに記す。
- `git show --check`と`git diff --check`はclean。最終workspace testは875 passed / 0 failed / 4 ignored、packは372 passed。

## Phase A判定

**PASS。** fmt、clippy `-D warnings`、workspace test、desktop build、pack test、実Tauri smoke/close-reopen/quit、H3 native lifecycle fixture、H3 package test、html-docs validateがすべて成功した。**Phase Bは`not_run`。H3全体は未完了である。**
