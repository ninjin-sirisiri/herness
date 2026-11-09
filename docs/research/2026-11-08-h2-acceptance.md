# H2監督の受入証跡（Phase A実行、2026-11-09）

**Status:** Phase A（自動検証・loopback・実Tauri lifecycle）は実行して合格した。2026-11-09にPhase Bの限定許可を受け、**Jev System Oneの条件評価だけ**をCommand Code GOAT経由で実接続確認した。通常LLM・OpenAI Decisions・Jevの許可評価は未確認で、Task 18もH2全体も**未完了**である。H1受入は未完了のままであり、[H1受入証跡](2026-11-08-h1-acceptance.md)のOpenAI/Anthropic APIキー経路の**UNVERIFIED**を本記録で上書きしない。

- **対象revision:** `547ac0094612ae077feb4c4d3d9a0ff984a07ff3`（Phase A実行時のHEAD。Task 17とTask 16 follow-upのproduction permission evaluatorを含む）。
- **環境:** macOS 27.2（build 26B123）、Mac17,3（Apple M5）、arm64、16 GiB。`rustc 1.97.1 (8bab26f4f 2026-07-14)`、`cargo 1.97.1 (c980f4866 2026-06-30)`。debug build。
- **正本spec:** [H2 supervision design](../sdd/specs/2026-11-08-h2-supervision-design.md)のTesting and acceptance・Open items and approval、[H1 runtime design](../sdd/specs/2026-11-07-h1-runtime-design.md)のTesting and acceptance・H2 integration additions。
- **手順:** [h2-testing.md](../development/h2-testing.md)のTask 18節。
- **Phase B:** 2026-11-09にJev System Oneの条件評価だけをCommand Code GOAT経由で限定実行した。通常LLM・OpenAI Decisions・Jevの許可評価は未実行。実Keychain項目の探索・login・実TypeSafe APIキーの使用はしていない。使用したのは既存の`COMMANDCODE_API_KEY`（GOAT枠）だけである。

## 証拠の分類

| 分類 | 意味 | 今回の有無 |
| --- | --- | --- |
| automated | 通常のworkspace test。loopback mock・scripted engine・fake credential・一時DB/projectだけを使う | あり |
| desktop | 実Tauri processを起動するsmoke/close/reopen/quit検証 | あり（lifecycleのみ） |
| mock | provider・OAuth・engine・Keychainをloopback/scripted/fakeで検証したもの。実接続の成功ではない | あり |
| real | 実provider・実account・実Keychainへ接続した結果 | **H2ではなし** |
| unverified | 証拠がない、または実接続の許可・料金が未確認 | 下記の未確認一覧 |

## Phase Aの実行コマンドと結果

実行はいずれもworktree `/Users/h-uma/.local/share/opencode/worktree/b3231b/sdd-h2-supervision`、debug profile。

| コマンド | 終了code | 実際の結果 |
| --- | ---: | --- |
| `cargo fmt --all -- --check` | 0 | 差分なし |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | warningなし。`Finished dev profile [unoptimized + debuginfo] target(s) in 0.18s` |
| `cargo test --workspace --locked` | 0 | **615 passed, 0 failed, 1 ignored**（34 test target + 8 doc-test target）。並列既定設定で実行し、既知のTask 14 loopback timing flakeは発生しなかった |
| `cargo build -p herness-desktop --locked` | 0 | `Finished dev profile [unoptimized + debuginfo] target(s) in 17.14s` |
| `HERNESS_APP_DATA_ROOT=<tmp>/smoke target/debug/herness-desktop --smoke-test` | 0 | `SMOKE_READY: pid=12646 startup_ms=662`、`SMOKE_OK: main window is visible and the trusted UI is ready (pid=12646 startup_ms=662)`。stderr空 |
| `HERNESS_APP_DATA_ROOT=<tmp>/close-reopen target/debug/herness-desktop --close-reopen-test` | 0 | `CLOSE_REOPEN_HIDDEN: pid=12661 generation=1`、`CLOSE_REOPEN_OK: pid=12661 previous_generation=1 generation=2`。stderr空 |
| `HERNESS_APP_DATA_ROOT=<tmp>/quit target/debug/herness-desktop --quit-test` | 0 | `QUIT_TEST_READY: pid=12676`、`QUIT_OK: pid=12676 save=confirmed stop=confirmed`。stderr空 |

- 一時rootは実行ごとに新規作成した絶対パス `/var/folders/1l/g5bm30qs6mq6m4zd0hqj2y4r0000gn/T/herness-task18.Dn0g4S/{smoke,close-reopen,quit}`。各rootには新規の`herness.sqlite3`とWAL/SHMだけが作られた。
- 3つのTauri実行はいずれも既存のKeychain項目を探索せず、外部providerへ接続しないPhase A lifecycle検査である。実provider送信・login・有料要求の証拠ではない。
- 既知のflakeは`tests/supervision/tests/permissions.rs`のloopback timing failure（`PermissionEvaluationFailed { failure: Unavailable }`、Task 14/16/17で記録済み）。今回は初回実行で発生しなかったため再実行は不要だった。将来発生した場合は同じコマンドを再実行し、両方の結果を記録してassertを弱めない。
- 1 ignoredは`herness-runtime-tests`の`tests/desktop.rs`にある`measure_running_host_rss`（Task 12の手動RSS計測fixture）。自動testのpass数へ加算しない。

## test target別の件数（実際の実行）

| target | passed | failed | ignored |
| --- | ---: | ---: | ---: |
| `herness-assessment` lib | 21 | 0 | 0 |
| `herness-core` lib | 55 | 0 | 0 |
| `herness-core` `tests/contracts.rs` | 21 | 0 | 0 |
| `herness-core` `tests/ports.rs` | 8 | 0 | 0 |
| `herness-desktop` lib | 26 | 0 | 0 |
| `herness-desktop` bin | 0 | 0 | 0 |
| `herness-engine-pi` lib | 35 | 0 | 0 |
| `herness-runtime-tests` lib | 1 | 0 | 0 |
| `herness-runtime-tests` `tests/acceptance.rs` | 4 | 0 | 0 |
| `herness-runtime-tests` `tests/connections.rs` | 14 | 0 | 0 |
| `herness-runtime-tests` `tests/contract_smoke.rs` | 4 | 0 | 0 |
| `herness-runtime-tests` `tests/cross_phase.rs` | 1 | 0 | 0 |
| `herness-runtime-tests` `tests/desktop.rs` | 20 | 0 | 1 |
| `herness-runtime-tests` `tests/engine.rs` | 57 | 0 | 0 |
| `herness-runtime-tests` `tests/files.rs` | 12 | 0 | 0 |
| `herness-runtime-tests` `tests/host.rs` | 24 | 0 | 0 |
| `herness-runtime-tests` `tests/oauth.rs` | 29 | 0 | 0 |
| `herness-runtime-tests` `tests/permissions.rs` | 42 | 0 | 0 |
| `herness-runtime-tests` `tests/shell.rs` | 14 | 0 | 0 |
| `herness-runtime-tests` `tests/skills.rs` | 12 | 0 | 0 |
| `herness-runtime-tests` `tests/store.rs` | 23 | 0 | 0 |
| `herness-store` lib | 9 | 0 | 0 |
| `herness-supervision` lib | 0 | 0 | 0 |
| `herness-supervision-tests` lib | 0 | 0 | 0 |
| `herness-supervision-tests` `tests/acceptance.rs` | 4 | 0 | 0 |
| `herness-supervision-tests` `tests/adapters.rs` | 62 | 0 | 0 |
| `herness-supervision-tests` `tests/budget.rs` | 18 | 0 | 0 |
| `herness-supervision-tests` `tests/contracts.rs` | 12 | 0 | 0 |
| `herness-supervision-tests` `tests/desktop.rs` | 22 | 0 | 0 |
| `herness-supervision-tests` `tests/evidence.rs` | 16 | 0 | 0 |
| `herness-supervision-tests` `tests/permissions.rs` | 10 | 0 | 0 |
| `herness-supervision-tests` `tests/profiles.rs` | 10 | 0 | 0 |
| `herness-supervision-tests` `tests/recovery.rs` | 13 | 0 | 0 |
| `herness-supervision-tests` `tests/supervisor.rs` | 16 | 0 | 0 |
| doc-tests（8 crates） | 0 | 0 | 0 |
| **合計** | **615** | **0** | **1** |

## H2の証拠分類と主張できる範囲

- **自動検証（automated）:** 上記workspace test。契約・状態遷移・予算・証拠・復旧・許可評価・desktop composition・cross-phase loopback回帰を含む。すべてloopback/scripted/fake credential/一時DBであり、実接続ではない。
- **実Tauri（desktop）:** `--smoke-test`、`--close-reopen-test`、`--quit-test`だけを実processで確認した。監督UIの手動操作、human confirmationのGUI操作、実provider送信は確認していない。
- **mock:** 通常LLM・Jev System One・OpenAI Decisionsのadapter/permission evaluatorはloopback mockで検証済み。mock成功を実接続の受入へ流用しない。
- **scripted-contract fixture:** Task 17の16 fixture（完了10・許可6、3方式で48結果）はすべて`scripted_contract`。誤完了0・誤allow0・誤停止0・保留42を確認した。これは契約の判別力の証拠であり、実モデルの精度・閾値の妥当性の証拠ではない。
- **real:** 2026-11-09の限定Phase Bで、**Jev System Oneの条件評価だけ**をCommand Code GOAT経由で確認した（3 requests、上記）。通常LLM・OpenAI Decisions・Jev許可評価の実接続証拠は存在しない。H1 Phase Bで確認済みのOpenAI互換/ChatGPTの結果はH1の証拠であり、H2の通常LLM/Jev/Decisions評価の受入へ流用しない。
- **未確認（unverified）:** 以下の一覧のとおり。

## 未確認の一覧

- 通常LLM（OpenAI Responses / Anthropic Messages / OpenAI-compatible）とOpenAI Decisionsの**実endpoint**による条件評価。
- 通常LLM・Jev・OpenAI Decisionsの**実endpoint**による許可評価（allow/deny/ask）。Jevの条件評価はCommand Code GOAT経由で確認済み。
- Jevの直接TypeSafe endpoint、画像入力、実TypeSafe APIキー、Command Code接続の実Tauri UIからの設定。
- 実Keychain項目・login・課金/利用枠の厳密な確認（JevのCommand Code経由usageは取得済み）。
- H1のOpenAI APIキー→openai-responses、Anthropic APIキー→anthropic-messagesは**UNVERIFIED**のまま（[H1受入証跡](2026-11-08-h1-acceptance.md)）。
- 完了閾値0.95、許可閾値0.99、分布誤差0.001の実モデルでの妥当性検証。閾値は設計初期値であり、安全性・正答率の保証ではない。
- 実Tauri監督UIからのtarget作成・profile/consent設定・start/stop/resume/reassess、human confirmation、window閉鎖中の監督進行。
- 残る製品compositionの制約: 既存のH1接続追加UI/commandはJev/Decisionsのassessment-only接続を作らない。未検証profileは`verified=false`のままで送信しない。permission evaluatorは検証済みprofileと現在の同意がある場合だけ利用可能。これらは「未実装のまま未確認」であり、成功として扱わない。

## Phase B limited: Jev completion via Command Code GOAT（2026-11-09）

利用者がJevの実接続確認を許可し、Command Code GOATのサブスク枠を使うよう指示した。直接のTypeSafe APIキーは使用せず、Command Code Provider APIの`typesafe/jev-1.14.0`（System One shape）だけを確認した。送信データは合成証拠だけで、repository・会話・secretを含まない。`COMMANDCODE_API_KEY`は環境変数から読み、表示・保存・commitしていない。

- 対象revision: `547ac0094612ae077feb4c4d3d9a0ff984a07ff3` + 本節のreal-checkコード `ea58d9b0450790fde7e27b4d862b7f0ef241ffce`。
- endpoint: `POST https://api.commandcode.ai/provider/v1/systemone`
- model: `typesafe/jev-1.14.0`（固定。aliasへ切り替えない）
- auth: `Authorization: Bearer <Command Code API key>`。GOAT枠に計上。
- timeout: 60秒。transport retryは最大2回だが、実測は全要求1 attempt。追加送信なし。

| # | 実行 | 結果 | usage (input/output) | 採用 |
| ---: | --- | --- | ---: | --- |
| 1 | 事前の1要求（`curl`、合成state/choice） | HTTP 200、model `typesafe/jev-1.14.0`、choice `met`、p=0.99 | 370 / 42 | 参考（adapter外） |
| 2 | herness Jev adapter、正例（evidenceに`herness-ok`を含む） | HTTP 200、`met`、met p=0.99、confidence 0.98、attempts=1 | 640 / 107 | **adopted**（0.95以上） |
| 3 | herness Jev adapter、負例（evidenceは`herness-no`） | HTTP 200、`unmet`、attempts=1 | 638 / 107 | 非met（正例と区別） |

- 実測合計: **3 requests**（事前1 + adapter 2）、retry 0、失敗0。GOAT creditsに計上。USDの厳密な請求額は確認していない。
- adapterの証拠: `tests/supervision/tests/real_connections.rs`の`commandcode_jev_completion_met_and_unmet_are_real`（既定は`#[ignore]`、`COMMANDCODE_API_KEY`がある場合だけopt-in実行）。
- 確認できたこと: Command Code Provider APIのSystem One shape、固定model、Bearer認証、herness Jev adapterのstrict parse、met/unmetの区別、usage取得、0.95採用。
- 確認していないこと: Jevの許可評価、直接TypeSafe endpoint、画像入力、実Tauri UIからのCommand Code接続設定、通常LLM/Decisions。
- この結果は**Jev completionの1経路だけ**の証拠である。H2全体の実接続受入へ流用しない。

### 実接続後の未確認一覧の更新

- 確認済み: Jev System Oneの**条件評価**（Command Code GOAT経由、合成証拠、3 requests）。
- 未確認のまま: Jev System Oneの**許可評価**、直接TypeSafe endpoint、Jev画像入力、通常LLMの条件/許可評価、OpenAI Decisionsの条件/許可評価、実Tauri UIからのprofile/consent/connection設定、実TypeSafe APIキー。
- H2受入は未完了。Jev以外の経路とJev許可評価の証拠が揃うまで完了扱いにしない。

## Phase B runbook（未承認・未実行のひな形）

Phase Bは、controllerが次の情報を人間へ提示し、対象・データ・上限・費用を明示した許可を得た場合だけ実行する。許可がない要求は拒否し、実provider・Keychain・loginへ触れない。

1. **対象接続:** purpose（completion/permission）、provider、endpoint class、connection ID、model ID/version、認証方式、接続の由来。許可された接続だけを列挙し、未許可接続へのfallbackを禁止する。
2. **fixtureと送信データ:** Task 17のfixture ID（`completion-*`/`permission-*`）と合成証拠だけを使う。実repository内容・会話・secretを含めない。送信本文の分類（text/code/diff/log/image）とtarget scopeを提示する。
3. **有限の要求数・retry上限:** 経路ごとの要求数、attempt上限、transportの追加retry最大2回、60秒timeout、全体の停止条件を提示する。無制限の再試行や自動再評価をしない。
4. **費用・利用枠:** 金額上限（USD）と`PriceVersion`、または「課金なし」を保証する隔離手段を提示する。ChatGPT loginのように見積不能な経路は、人間が明示的に許可した場合だけ使い、費用を主張しない。
5. **許可の範囲と期限:** 許可された接続・fixture・要求数・費用・期間を記録し、範囲外は拒否する。許可証跡にはsecretを含めない。
6. **証拠:** 要求数、usage、返却model ID、閾値結果、失敗理由、対象revision、未確認範囲をsanitized evidenceとして保存する。provider本文・credential・Authorization・生URL・secretは保存しない。
7. **判定:** 許可された経路がすべて確認でき、失敗profileを利用不可にできるまでTask 18/H2を完了にしない。許可がない経路が残る場合は、人間と受入範囲を再合意しない限り未確認のままとする。

## Phase Bの状態

**PARTIALLY AUTHORIZED / JEV COMPLETION VERIFIED, H2 INCOMPLETE。** 2026-11-09に利用者がJevの実接続確認を許可し、Command Code GOAT経由の条件評価だけを実行した（3 requests）。実Keychain項目の探索・login・実TypeSafe APIキーの使用はしていない。通常LLM、OpenAI Decisions、Jevの許可評価、実Tauri UIからの設定は未確認である。Task 18はPhase AとJev completionの限定Phase Bのみで、H2受入全体は未完了である。
