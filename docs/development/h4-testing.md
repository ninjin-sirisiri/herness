# H4 SDD execution: 実Tauri lifecycle テスト手順

H4の正本仕様は [H4 design](../sdd/specs/2026-11-13-h4-sdd-execute-design.md)、H1/H2の追加契約は [H1 design](../sdd/specs/2026-11-07-h1-runtime-design.md) と [H2 design](../sdd/specs/2026-11-08-h2-supervision-design.md)。この文書はTask 23で追加した、実 `herness-desktop` processによるwindow非依存進行・実quit・再起動・host commit境界crashの再現手順を記録する。

## 結論

- windowを開かず、projectも選択しない実Tauri processで、保存済みH4 executionがTask完了・実HTML barrier・実host commit・`.sdd/progress.md`出力まで進む。
- 同じ実行を実quit pathで終了し、同じrootで再起動すると外部要求0で照合し、再dispatch・再commitしない。
- host commit直前/直後、H4完了snapshot保存前、progress置換前の4境界で実processをexit 70させ、再起動後の照合classを確認する。
- 成立済みcommitは人間の再開確認前に台帳へ結び付けない。`committing`は再起動後のpumpで進めない。
- 実Keychain、実login、実provider、既存app dataへ触れない。provider/assessment endpointはloopbackのみ。

## 対象revision

- herness worktree: `c0a5446a0ded170aed48b54c0d6a51c65f6d692b`（branch `h4-sdd-execute`、Task 23のcommit前）
- Common SDD pack: `/Users/h-uma/Documents/sdd/.worktrees/h4-exec` HEAD `b210b3aac3faf84c5ad201aa6502dface8c4cdf2`（read-only、変更なし）
- toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`、macOS arm64

pack revisionは実行時に固定されない。再実行時は `git -C /Users/h-uma/Documents/sdd/.worktrees/h4-exec rev-parse HEAD` を記録する。

## 実測とscriptedの区別

| 層 | 種別 | 内容 |
| --- | --- | --- |
| plan inspector | 実測 | 実packの `scripts/plan-inspect` |
| SQLite / approval / journal / recovery | 実測 | 実store、実approval、実Git/dispatch/progress journal、実startup reconciliation |
| H2 supervisor / required check | 実測 | 実 `SupervisionHost`、実 `HostCheckPort` が `true` を実行 |
| H1 runtime / tool executor | 実測 | 実 `Runtime`、実 `DesktopToolExecutor` |
| HTML barrier | 実測 | 実H3 storeの `Synced` 文書と実ファイルbytes |
| host commit | 実測 | 実 `HostGitBoundary`（明示path stage → 共通gate → commit → 再観測） |
| quit / restart | 実測 | 実 `request_quit`、実 `restore_sdd_execute` |
| 子のmodel | scripted | loopback Responses mock。実provider/Keychain/loginなし |
| 条件評価 | 実測のchecks | 計画の条件は `mode: "checks"`。LLM assessmentは呼ばれない |
| crash | 注入 | test modeだけがarmする4境界。SIGKILL/power lossではない |

scriptedなのは子modelの応答だけであり、H4/H3/H2の保存・検証・commit経路は実装である。scripted judgeの品質証拠ではない。

## 新しいnative test mode

`src-tauri/src/app.rs` の `LaunchMode::H4Lifecycle(H4LifecycleLaunch)` が明示modeで、通常の `Normal` とは別variantである。

| flag | 意味 |
| --- | --- |
| `--h4-lifecycle-test` | windowを作らず、projectを選択せず、app-lifetime pumpを駆動する |
| `--h4-crash-point <name>` | `before-host-commit` / `after-host-commit` / `before-db-result` / `before-progress-replace` の1つでexit 70 |
| `--h4-lifecycle-no-quit` | 事実を出力して直接exitする。crash後の照合状態をquit hookで上書きしない観測用 |

`--h4-crash-point` と `--h4-lifecycle-no-quit` は `--h4-lifecycle-test` なしではparse errorになる。`--h4-lifecycle-test` はwindow/render系launcherと併用できない。crash hook（`src-tauri/src/sdd_execute/crash.rs`）はprocess-global atomicだけを読み、環境変数を読まず、通常のdesktop processでは一度もarmされない。

launcherは次を要求する。

| 環境変数 | 用途 |
| --- | --- |
| `HERNESS_APP_DATA_ROOT` | fresh absolute app data root。未設定/相対は起動失敗 |
| `SDD_PACK_ROOT` | absolute Common SDD pack root（共通staged HTML gate） |
| `HERNESS_H4_TEST_ENDPOINT` | loopback provider/assessment base（例 `http://127.0.0.1:PORT`） |

credentialはin-processのfake `CredentialPort`で、`open_with_html_sync_test_boundaries` に渡す。`AppState.credential_admin` は同じ型を満たすために構築するが、windowもIPCもないため参照されずKeychain itemを読まない。

## fixture

`tests/sdd-execute/tests/native_fixture/mod.rs` が1つの実行をseedする。

1. 一時app data rootと一時checkoutを作り、plan/spec/CSS/sourceを実Gitへcommitする。
2. 実packでH3 settingsを作り、plan/specの `Synced` 文書と公開journalを保存する。公開journalがないと実H3 startup reconciliationが `waiting_human` に落とすため、fixtureは `Published` journalを併せて保存する。
3. 実Pi engineをloopback Responses mockへ向け、Configured permission rulesを設定する。
4. preview → 人間確認 → `approve_and_start` で承認を保存する（子はまだ作られない）。
5. H4 pumpを1回だけ実行してTaskをdispatchする。H4の2回目は実行しない。
6. H1 runtime pumpとH2 pumpだけを回し、子が `src/task-one.txt` を書き、実required check `true` が通り、保存H2 targetが `completed` になるまで進める。
7. hostをdropする。checkoutには未commitの成果物が残り、H4 snapshotは `running`（Task active）、H2は `completed` である。

native processはこの状態から、barrierのpre-Task capture、H2 completedの再読、実host commit、progress出力を行う。子のmodel要求はseed時のloopbackだけで、native processは外部要求を送らない。

## ビルドと実行

```sh
cargo build -p herness-desktop --locked
cargo test -p herness-sdd-execute-tests --test native_lifecycle --locked -- --test-threads=1
cargo test -p herness-html-sync-tests --test native_lifecycle --locked
```

`native_lifecycle` は `#![cfg(target_os = "macos")]` で、macOS以外では空のtargetになる。`target/debug/herness-desktop` が必要で、`HERNESS_DESKTOP_BIN` で差し替えられる。CIでbinaryがない場合はfake captureへfallbackせず明示的に失敗する。

testはprocessを直列実行する（static mutex）。各caseは独立したfresh rootを使う。

## case 1: window非依存のcommit、progress、quit、再起動

test: `windowless_commit_progress_and_restart_send_nothing`

1. seedしたrootで実binaryを `--h4-lifecycle-test` で起動する。
2. `H4_LIFECYCLE_OK:` に `window=absent selected_project=none request_count=0 tasks_completed=1 commits=1 progress=present` が出ることを確認する。
3. 実quit pathの `QUIT_OK:` とexit 0を確認する。
4. storeで実行state `ready_for_finish`、Task `complete`、commit範囲 `baseline..HEAD` を確認する。
5. `git diff-tree` が成果物1件だけ、commit messageが `Task 1:` と `Herness-Task` / `Herness-Execution` / `Herness-Request` trailerを持つことを確認する。
6. `.sdd/progress.md` が `Worktree: in-place`、full `Branch baseline:`、`Task 1: complete (` を持つことを確認する。
7. 同じrootで2回目を起動し、exit 0、`request_count=0`、HEAD/commit数/範囲/ledger bytesが不変であることを確認する。

loopbackのcounting listenerは両起動で接続0だった。

代表的な実測（2026-11-15、このworktree）:

```
H4_NATIVE_EVIDENCE commit root=/private/var/folders/.../checkout app_data=/var/folders/.../tmprUhoRh
  exit=Some(0) connections=0 head=421279a526f915c52256a6cfe8011000dfdf3810
  baseline=eeb6b93a721fac97073a984bbf3ba20f360cf799 commits=3
H4_LIFECYCLE_OK: pid=4512 projects=1 executions=1 tasks=1 tasks_completed=1 commits=1
  progress=present request_count=0 window=absent selected_project=none
  startup_reports=1 startup_failures=0 pump_errors=0 states=...=ReadyForFinish
```

## case 2: 4つのcrash境界

test: `each_crash_boundary_is_reconciled_without_a_second_commit_or_dispatch`

各境界でfresh seed → 実binaryをcrash point付きで起動 → exit 70と `H4_LIFECYCLE_CRASH: point=...` を確認 → `--h4-lifecycle-test --h4-lifecycle-no-quit` で再起動 → 外部要求0、再dispatch 0、再commit 0を確認する。

| point | 注入位置 | crash後の実Git | 再起動後の照合 |
| --- | --- | --- | --- |
| `before-host-commit` | `HostGitCommitBoundary::commit` が実boundaryを呼ぶ直前。intentは保存済み | commitなし | Git item `unknown`、pending linkなし、state `committing` |
| `after-host-commit` | 実boundaryがcommitを返した直後。H4 journal resultは未保存 | commit 1件成立 | Git item `established`、`pending_link` あり、state `committing` |
| `before-db-result` | `LaneCompletion::complete` が `Complete` を受けた後、H4 snapshot保存前。journal resultは保存済み | commit 1件成立 | Git item `established`、`pending_link` あり、state `committing` |
| `before-progress-replace` | `DesktopProgressLedger::write_document` の `rename` 直前。progress intentは保存済み、destination未置換 | Task commit 1件成立 | progress item `unknown`、state `waiting_human`、`.sdd/progress.md` なし |

`committing` は再起動後のpumpで進めない。H4 pumpのeligible stateから `committing` を除いてあり、host commit境界で落ちた実行は人間のresume確認なしに再dispatchも再commitもしない。成立済みcommitは `pending_link` として報告され、`confirm_resume` を伴う人間のresumeだけが台帳へ結び付ける。

progress境界だけは、H4 Task完了snapshotが既に `ready_for_finish` で保存されている。再起動時のledger照合はintentとdocument digestを比較し、destinationが無いため `unknown` としてdurableな `waiting_human` を書く。次Taskは開始しない。

代表的な実測（各case独立root、commit数はfixture baseline + H3 companions + Task）:

| point | crash exit | crash後のcommits | 再起動exit | connections | 再起動後のcommits | Git / progress class |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| before-host-commit | 70 | 2 | 0 | 0 | 2 | `git=[unknown]` |
| after-host-commit | 70 | 3 | 0 | 0 | 3 | `git=[established]` |
| before-db-result | 70 | 3 | 0 | 0 | 3 | `git=[established]` |
| before-progress-replace | 70 | 3 | 0 | 0 | 3 | `git=[established] progress=[unknown]` |

実測のcommit SHA例（各caseで独立。再起動前後で同一）:

- before-host-commit: `be23bdf4e036893e61c7784bcacc8390512c938a`
- after-host-commit: `0894a936b9cdad10621c86e6b4d01aff24b8f6cd`
- before-db-result: `800eccf5529b6322e4fea41c40bdd24a846aec69`
- before-progress-replace: `59665d67e3b946988a69642ca73c2ebf9bb3ccf0`

progress境界の再起動factsは `tasks_completed=1 commits=1 progress=absent request_count=0 ... states=...=WaitingHuman pump_errors=1`。`pump_errors=1` は未確認ledgerをerror行として報告し、進捗として扱わないことを示す。

## 変更点

- `src-tauri/src/sdd_execute/crash.rs`: test-onlyの4境界hook。armはH4 launcherだけ。
- `src-tauri/src/sdd_execute/finalize.rs`: commit直前/直後のhook。
- `src-tauri/src/sdd_execute/pump.rs`: completion前のhook、完了後のprogress出力、`committing` をpump対象から除外。
- `src-tauri/src/sdd_execute/ledger.rs`: progress rename直前のhookと、pumpから呼ぶ `write_compatibility_ledger`。
- `src-tauri/src/sdd_execute/host_commit.rs`: `.sdd/` 配下をcommit対象のchange/untracked列挙から除外（互換出力をTask成果物と誤認しない）。
- `src-tauri/src/lifecycle/h4.rs`: windowless launcher、fake credential、facts出力、実quit。
- `src-tauri/src/app.rs`: `LaunchMode::H4Lifecycle` とflag parse。
- `tests/sdd-execute/tests/native_lifecycle.rs` と `native_fixture/`: 実process fixture。

既存 `tests/sdd-execute/tests/support/mod.rs`（store fixture）は変更していない。

## 実行結果（Task 23）

| command | result |
| --- | --- |
| `cargo build -p herness-desktop --locked` | success |
| `cargo test -p herness-sdd-execute-tests --test native_lifecycle --locked -- --test-threads=1` | 2 passed, 0 failed |
| `cargo test -p herness-sdd-execute-tests --test cross_phase --locked` | 11 passed, 0 failed |
| `cargo test -p herness-html-sync-tests --test native_lifecycle --locked` | 1 passed, 0 failed |
| `cargo check --workspace --locked` | success、warningなし |
| `cargo clippy --workspace --all-targets --locked` | warningなし |

## 未確認範囲

- crashはtest modeの明示的境界での `std::process::exit(70)` であり、SIGKILL、power loss、filesystem全体の破損を再現しない。
- native processはseed済みの「Task dispatch済み・H2 completed」状態から開始する。子のmodel要求そのものは実providerではなくloopbackで、実model品質の証拠ではない。freshな子dispatchからhost commitまでの全経路はTask 22のcross-phase targetが担う。
- 実Keychain、実login、実ChatGPT/OpenAI account、実provider接続は使っていない。
- progress出力の外部改変は、このtargetではcrash境界（replace前）だけを実processで扱う。改変そのものの拒否はTask 18のledger targetが担う。
- GUI windowの表示・人間操作・macOSのCmd+Qは確認していない。実quitはRustの `request_quit` pathをwindowlessで駆動した。
- crash後の人間resume（`confirm_resume` を伴う `resume_sdd_execute`）はこのtargetでは実行しない。成立済みcommitが `pending_link` として残り、resumeなしに結び付かないことだけを確認する。
