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

## 評価fixtureと実接続opt-in gate（Task 24）

Task 24は、将来の「実providerでの実装・完了評価・HTML評価」を再現するための合成fixtureと、接続・送信bytes・要求数・料金/枠が明示許可されるまで送信前に拒否するgateを追加した。**このTask自身は実送信を行わない。** 既定の外部要求数は0である。

### fixtureの配置

| path | 内容 |
| --- | --- |
| `tests/sdd-execute/fixtures/acceptance/plans/valid-two-task.md` | 2 Task・依存ありの正常系。実packがacceptする |
| `tests/sdd-execute/fixtures/acceptance/plans/valid-single-task.md` | 1 Taskの正常系。実packがacceptする |
| `.../plans/invalid-unknown-field.md` | 未知root field |
| `.../plans/invalid-unknown-version.md` | 未知schema version |
| `.../plans/invalid-broken-fence.md` | 閉じない `sdd-execution-v1` fence |
| `.../plans/invalid-path-escape.md` | `..` を含むwrite path |
| `.../plans/invalid-forward-dependency.md` | 後続Taskへの依存 |
| `.../plans/invalid-non-contiguous-numbering.md` | 欠番のTask heading |
| `.../plans/legacy-prose.md` | 旧free-prose形式 |
| `.../spec.md` | 正常系planが参照するfixture spec |
| `.../acceptance.manifest.json` | 実接続受入manifestの**not_authorizedテンプレート**。承認ではない |
| `.../metrics.template.json` | 誤完了・誤commit・誤dispatch・保留・継承未確認の出力形 |

targetは `tests/sdd-execute/tests/acceptance.rs` と、その中のtest-only module `acceptance_gate/mod.rs` である。planは各caseでfreshな一時checkout（`docs/sdd/plans/`、`docs/sdd/specs/`、`src/lib.rs`）へ書き、実pack inspector（`scripts/plan-inspect`）でimportする。正常系2件のaccept、負例7件の拒否理由（diagnostic code、pointer、message）、import前後のcheckout bytes不変、socket接続0をassertする。

```sh
SDD_PACK_ROOT=/Users/h-uma/Documents/sdd/.worktrees/h4-exec \
  cargo test -p herness-sdd-execute-tests --test acceptance --locked -- --nocapture
```

`SDD_PACK_ROOT` を省略すると `/Users/h-uma/Documents/sdd/.worktrees/h4-exec` を使う。packがない場合はfallbackせず明示的に失敗する。`--nocapture` を付けると、どのfixtureがどの理由で拒否されたか（`H4_ACCEPTANCE_PLAN_REFUSED:` 行）と、計画・gateの証拠行が表示される。

### 既定拒否（default deny）

`AcceptanceGate::authorize(opt_in, manifest, now_millis, request)` は、次のすべてが揃わなければ `GateRefusal` を返す。runの入口 `run_acceptance` はgateを最初に評価し、拒否時はtransportを一度も呼ばない。

| 条件 | 拒否 |
| --- | --- |
| `H4_ACCEPTANCE_OPT_IN` が厳密に `"1"` | 未設定は `OptInMissing`、`"0"`/`"true"`/`"yes"`/空/`" 1"` は `OptInNotExplicit` |
| `H4_ACCEPTANCE_MANIFEST` が読めるmanifestを指す | `ManifestMissing` / `ManifestUnreadable` |
| `schema=h4-real-connection-acceptance-v1`、`status=approved`、`approvedBy`/`approvedAt` が非空 | `UnsupportedManifestSchema` / `NotAuthorized` / `ManifestFieldMissing` |
| `expiresAtMillis` が観測時刻より未来（同時刻は拒否） | `Expired` |
| `credentialAccess=none` で、manifest全体にcredential様keyがない | `CredentialAccessWidened` / `CredentialMaterialPresent` |
| 接続の `provider`/`connectionId`/`endpointClass`/`model`/`purpose=assessment` が要求と一致 | `ConnectionMismatch` |
| 要求fixtureが承認fixtureの部分集合 | `FixtureOutOfScope` |
| `sendByteKinds` が4種（`plan_packet` / `task_report` / `assessment_prompt` / `h3_render_evidence`）をすべて含み、要求と完全一致 | `RequiredSendByteKindMissing` / `UnknownSendByteKind` / `SendByteKindsMismatch` |
| 要求数・fixture当たり要求数・retryが正の有限値で承認以内 | `RequestCountNotFinite` / `RequestCountOverrun` / `PerFixtureOverrun` / `RetryOverrun` |
| retry理由が `timeout` / `connection-reset` / `server-error` / `rate-limited` の範囲 | `RetryReasonNotApproved` |
| 料金上限（有限・非負）または確認済みquota referenceがある | `PricedRequestWithoutMoneyCap` / `CostOrQuotaMissing` / `CostNotFinite` |
| H3の `image`/`support`/`usability`/`render`/`humanReadingObservation` が `unconfirmed` | `UnconfirmedCapabilityClaimed` |
| H1/H2/H3/H4の継承未確認6項目がすべて `unconfirmed` で存在 | `InheritedUnconfirmedMissing` / `InheritedUnconfirmedClaimed` |

run中も承認済みの総要求数・fixture当たり要求数・retry数を数え、超える前に停止する（`RequestBudgetExceeded` / `PerFixtureOverrun` / `RetryBudgetExceeded`）。retryは同じ接続・同じ申請範囲だけで、別接続・別modelへのfallbackはgateにもrunnerにも存在しない。

`authorize` は環境を読まない。環境を読むのは `from_environment` だけで、opt-inとmanifest pathを一箇所に閉じ込める。testは環境変数を書き換えない。

### 人間が実接続runを許可する手順

このTaskのmanifestはテンプレートであり、承認ではない。実接続runを行う前に、controllerは人間へ次を**送信前に**提示し、別途の明示許可を得る。

1. 接続identity: provider、connectionId、endpointClass、model、purpose=assessment。現在 `verified` でconsent済みであること。ChatGPT loginやAPI keyの値をmanifestへ書かない。
2. fixture名と、送信するbytes種別（plan packet / Task report / assessment prompt / H3 render evidence）。1種でも欠けるmanifestは拒否する。
3. 有限の総要求数、fixture当たり要求数、retry回数、retry理由。無制限・自動再試行・別接続fallbackを承認しない。
4. 料金上限（USD、有限）またはquota reference。priced requestに金額上限がなければ拒否する。
5. 有効期限。
6. H1/H2受入未完了、H3の画像・support/usability/render・人間読解観測が未確認であること。これらを「確認済み」に変える承認はgateが拒否する。
7. `credentialAccess=none`。承認を実login・credential探索・Keychain読取りへ拡張しない。

手順は、テンプレートを複製し、`status=approved`、`approvedBy`、`approvedAt`、`expiresAtMillis`、connection、fixtures、sendByteKinds、requestBudget、retryPolicy、costを人間の判断で埋め、別途の許可記録を残すこと。そのうえで

```sh
H4_ACCEPTANCE_OPT_IN=1 \
H4_ACCEPTANCE_MANIFEST=/absolute/path/to/approved.manifest.json \
  <実接続runner>
```

を実行する。実接続runnerはこのTaskには含まれない。このTaskのtestが持つtransportはin-memoryの記録用だけで、`H4_ACCEPTANCE_OPT_IN=1` と有効manifestを与えてもnetworkへは出ない。したがって**real provider欄は `not_executed` / 未確認**である。

### 集計の分離

`AcceptanceMetrics` は次を別fieldで持つ。

| 分類 | field |
| --- | --- |
| 誤完了 | `counts.wrongCompletion` |
| 誤commit | `counts.wrongCommit` |
| 誤dispatch | `counts.wrongDispatch` |
| 保留（pending） | `holds.pending` |
| 人間待ち | `holds.humanWait` |
| 外部要求 | `externalRequests` |
| 実provider | `realProvider.status` / `realProvider.confirmed` |

保留は誤りとして数えない。誤完了・誤commit・誤dispatchは相互に合算しない。`metrics.template.json` はこの形のnot_run出力で、`wrong_results_and_holds_are_counted_separately` が分離を、`the_metrics_template_keeps_defects_holds_and_inherited_items_apart` がtemplateの形を確認する。

### 継承する未確認項目

次の6項目は `inheritedUnconfirmed` としてmanifestとmetricsの両方に明示され、`status=unconfirmed` / `confirmed=false` のまま継承する。gateは欠落も「confirmed」への書換えも拒否する。

| id | 内容 |
| --- | --- |
| `h1-acceptance` | H1 runtime受入は未完了。H4 integration additionsも未確認 |
| `h2-acceptance` | H2 supervision受入は未完了。H4 integration additionsも未確認 |
| `h3-image` | H3の画像条件は限定text-only受入で未実行 |
| `h3-residual-conditions` | H3のsupport/usability/render条件は未実行 |
| `h3-human-reading-observation` | H3の人間読解観測は未実行 |
| `h4-real-provider-acceptance` | 実providerの実装・完了評価・HTML評価・render証拠は未受入 |

限定受入は実行時gateの迂回ではない。必要能力を確認できなければ実運用の受入は保留する。

## 変更点

- `src-tauri/src/sdd_execute/crash.rs`: test-onlyの4境界hook。armはH4 launcherだけ。
- `src-tauri/src/sdd_execute/finalize.rs`: commit直前/直後のhook。
- `src-tauri/src/sdd_execute/pump.rs`: completion前のhook、完了後のprogress出力、`committing` をpump対象から除外。
- `src-tauri/src/sdd_execute/ledger.rs`: progress rename直前のhookと、pumpから呼ぶ `write_compatibility_ledger`。
- `src-tauri/src/sdd_execute/host_commit.rs`: `.sdd/` 配下をcommit対象のchange/untracked列挙から除外（互換出力をTask成果物と誤認しない）。
- `src-tauri/src/lifecycle/h4.rs`: windowless launcher、fake credential、facts出力、実quit。
- `src-tauri/src/app.rs`: `LaunchMode::H4Lifecycle` とflag parse。
- `tests/sdd-execute/tests/native_lifecycle.rs` と `native_fixture/`: 実process fixture。
- `tests/sdd-execute/fixtures/acceptance/`: 新形式planの正負fixture、spec、not_authorizedのmanifestテンプレート、metricsテンプレート（Task 24）。
- `tests/sdd-execute/tests/acceptance.rs` と `acceptance_gate/mod.rs`: 実packによるplan受入と、既定拒否の実接続gate・runner・metrics（Task 24、test-only）。

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

## 実行結果（Task 24）

| command | result |
| --- | --- |
| `cargo test -p herness-sdd-execute-tests --test acceptance --locked` | 12 passed, 0 failed |
| `cargo test -p herness-sdd-execute-tests --locked` | 全target pass |
| `cargo check --workspace --locked` | success、warningなし |
| `cargo fmt --all -- --check` | format差分なし |
| `cargo clippy --workspace --all-targets --locked` | warningなし |

`acceptance` の既定実行は外部要求0、socket接続0。期限切れ、範囲外、要求/retry上限、料金/枠欠落、credential拡張、継承未確認の改変は送信前に拒否する。実provider欄は `not_executed` / `confirmed=false` である。

## 未確認範囲

- crashはtest modeの明示的境界での `std::process::exit(70)` であり、SIGKILL、power loss、filesystem全体の破損を再現しない。
- native processはseed済みの「Task dispatch済み・H2 completed」状態から開始する。子のmodel要求そのものは実providerではなくloopbackで、実model品質の証拠ではない。freshな子dispatchからhost commitまでの全経路はTask 22のcross-phase targetが担う。
- 実Keychain、実login、実ChatGPT/OpenAI account、実provider接続は使っていない。
- progress出力の外部改変は、このtargetではcrash境界（replace前）だけを実processで扱う。改変そのものの拒否はTask 18のledger targetが担う。
- GUI windowの表示・人間操作・macOSのCmd+Qは確認していない。実quitはRustの `request_quit` pathをwindowlessで駆動した。
- crash後の人間resume（`confirm_resume` を伴う `resume_sdd_execute`）はこのtargetでは実行しない。成立済みcommitが `pending_link` として残り、resumeなしに結び付かないことだけを確認する。
- Task 24の実接続受入は**未実行**である。gateとrunnerはtest-onlyで、transportはin-memory記録用だけ。実provider、実account、実Keychain、実login、実model送信の証拠はない。
- Task 24のplan fixtureは合成planであり、実planの意味・品質・仕様適合を証明しない。実pack inspectorの構文・schema受入だけを確認する。
- Task 24の変換は、gateが受入可能なmanifestを作るための形式と拒否条件を定めるが、実接続の人間承認そのものではない。`acceptance.manifest.json` はテンプレートのまま保持する。
- 有限要求数・retry・料金/枠の表示はmanifestのfieldで表すが、実provider request数・実料金は未計測である。
