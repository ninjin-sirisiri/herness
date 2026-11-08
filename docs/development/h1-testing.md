# H1 runtime: 依存方針とテスト手順

H1のRust workspaceにおけるtoolchain、依存方針、テストコマンド、Task 1で固定した契約の検証範囲を記録する。正本仕様は [H1 runtime design](../sdd/specs/2026-11-07-h1-runtime-design.md)、計画は [H1 plan](../sdd/plans/2026-11-08-h1-runtime.md)。

## Toolchain

- `rust-toolchain.toml` は `1.97.1-aarch64-apple-darwin` を固定する。このworktreeを作成したmacOS arm64環境に導入済みのstable toolchainであり、`rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)` と一致する。
- workspaceはedition 2024、resolver 3、`rust-version = "1.97.1"` を使う。
- `Cargo.lock` を追跡する。依存更新時はlock差分とadapter互換テストを同じ変更で確認する。

## 依存方針

`herness-core` の依存は次の5つに限定する。

| crate | 用途 | 理由 |
| --- | --- | --- |
| `serde` (`derive`) | 公開契約のJSON表現 | version付きevent・error・引数schemaの安定した直列化 |
| `serde_json` | event payload | payloadを型付きenvelope内の構造化JSONとして保持 |
| `sha2` | 最終tool引数のSHA-256 digest | 承認を人間が確認した最終引数へ束縛する。I/O・network・秘密の保存には使わない |
| `uuid` (`v4`) | project・scoped ID・connection ID | 再起動をまたいで衝突しない安定ID |
| `libc` (`0.2.191`) | managed process groupのsignal | `killpg`・signal定数のみ。`unsafe`は `tools/process.rs` の局所的な `#[allow(unsafe_code)]` に閉じ込める |

- async runtime、HTTP client、DB、Tauri、pi crate、時刻整形crateはTask 1のcoreへ入れない。checkpointはadapter所有のversion付きopaque bytesとして運び、coreは解釈しない。
- workspace lintは `unsafe_code = "deny"` とし、`forbid` を外した。`tools/process.rs` のlibc呼出しだけがmodule内の明示的な `#[allow(unsafe_code)]` を持つ。他のcrate・moduleはdenyのまま。
- `tests/runtime` は `herness-core` にだけ依存するlibrary crate。black-box test用に `serde_json` をdev-dependencyとする。
- 依存追加は、そのTaskのreportで用途とcoreの依存方向（store・engine・Tauriへ依存しない）への影響を説明する。
- secretは `SecretString` / `ResolvedCredential` に閉じ込め、`Serialize`・`Display` を実装しない。`Debug` は `[REDACTED]` を返す。event・error・checkpoint・connection情報へtokenやproviderの生errorを入れない。
- 合成fixtureだけを使い、実APIキー、実OAuth token、既存Keychain項目、外部serviceを通常テストから参照しない。

### Git対象外

`.gitignore` は `.sdd/` の行を維持したまま、Rust build成果物（`/target/`）、一時DB（`*.db`, `*.sqlite`, journal/WAL/SHM）、ローカル資格情報（`*.credentials`, `credentials.local.json`, `.env*`, `.secrets/`）を除外する。

## テストコマンド

Task 1の受入で実行するコマンド:

```sh
cargo test -p herness-core
cargo test -p herness-runtime-tests
cargo test -p herness-runtime-tests --test permissions
cargo test -p herness-runtime-tests --test files --locked
cargo test -p herness-runtime-tests --test shell --locked
cargo fmt --all -- --check
```

追加の静的検査:

```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

- testはnetwork・外部service・実資格情報を必要としない。依存取得後の通常実行はofflineで完結する。
- `tests/runtime` のlibrary部は `herness-core` にだけ依存する。black-box test targetは `herness-store`（`test-support` feature付き）、`serde_json`、`tempfile`、`rusqlite`、`sha2` をdev-dependencyとして使う。storeのfault injectionとfile toolの実ファイル操作は一時project・一時DBだけで行う。
- 後続Taskでstore・engine・Tauriを追加しても、`herness-core` からそれらへの依存を追加しない。workspace全体のtestは `cargo test --workspace --locked` で実行する。
- 実接続・実Keychain・実Tauriの確認はTask 13の別途許可まで行わない。mock成功を実接続成功として扱わない。

## Task 4で固定したnative file toolの契約

実装は `crates/herness-core/src/tools/{path,read,search,write,edit,files}.rs`、testは `tests/runtime/tests/files.rs`。

- **rootと実パス:** すべてのfile toolはfrozen cwdに対してpathを解決し、lexicalに `.`/`..` を畳んだ後に、既存部分をcanonicalizeする。project rootは起動時にcanonicalizeした実パスで、root外、`..` escape、root配下のsymlink component（target fileと未作成fileのparentを含む）を拒否する。read・searchもwrite・editと同じ検査とpermission境界を通る。absolute引数はcanonical rootの配下にlexicalに一致する必要がある。hard linkはpathから判別しない。これは信頼するprojectの境界であり、OS sandboxではない。
- **writeはcreate-only:** 既存file・directory・symlinkへのwriteは `AlreadyExists`/`SymlinkNotAllowed` で失敗し、上書きしない。既存fileの変更は `edit` だけが行う。
- **edit:** 既存regular fileが必須。`oldText` は空でなく、非overlapでちょうど1回出現する必要がある（0回と複数回は別error）。`expectedVersion` が指定された場合は現在のhashと一致しなければならず、未指定でも `oldText` の一致が内容の前提になる。
- **版:** native fileの `FileVersion` はfile bytesのSHA-256 hex（64文字）。作成時のbeforeは `None`、editはbefore/afterを記録する。
- **順序:** freeze済み引数 → gatewayのpermission authorize → lock取得 → before版とdiff確定 → checkpoint + `OperationIntent` + `file.change.intended` eventを1 transactionで保存 → 実パス/版を再確認 → 同一directory内のtemp file + renameでatomicに書く（editは既存permissionを維持）→ 変更後hashを確認 → `Applied` result + `file.change` eventを1 transactionで保存 → 成功を返す。
- **保存失敗:** 事前保存失敗はfileを変更せず `NotExecutable`。書き込み後のresult保存失敗はrollbackもretryもせず `Unverifiable` として照合待ちにし、intentだけが残る。duplicate operation IDは `DuplicateOperation` を返し、再適用しない。
- **直列化:** process内のcanonical path単位のlock registryでwrite/editを直列化する。別processや外部editorが最終再確認とrenameの間に変更するraceは排除しない。Task 10以降、同一processの複数executorで書き込みを直列化する場合は、1つの `Arc<FileLockRegistry>` を共有して構築する。executorごとの既定registryはそのexecutor内だけを直列化する。
- **read:** UTF-8のみ。1-based `offset`（既定1）、`limit`（既定2,000、上限10,000）行を返し、`totalLines` と `truncated` を返す。file全体のversionも返す。
- **search:** ripgrep不要。case-sensitiveなliteral substringを各行で探し、project-relativeでglob filterする。globは `*`（`/`以外）、`**`（`/`も含む）、`?`（`/`以外の1文字）で、それ以外はliteral。結果はpath・1-based line・1-based Unicode scalar column・bounded preview。traversalはfile名sortのdepth-firstで、symlinkを辿らず、regular file以外・4 MiB超・非UTF-8をskipする。既定100件、上限1,000件、scan上限20,000 fileで `truncated` を立てる。
- **diff:** common prefix/suffix + 3行contextのunified-style。32 KiBを超える場合は `[diff truncated: ...]` を末尾に明示する。
- **永続通知:** `file.change` のpayloadは `path`（absolute）、`operationId`、`tool`、`created`、`beforeVersion`、`afterVersion`、`diff`、`diffTruncated`、`rationale`。`rationale` はmodelの説明であり、権限や事実の証明ではない。watcher・HTML著作・外部編集者のactor推測は実装しない。
- **checkpoint:** 現時点のfile toolは `herness.file-operation`（format 1、stage `intent`）のhost監査用opaque checkpointをintent transactionで書く。engineの会話checkpointはTask 9が供給する。result + `file.change` は同じtransactionで保存するがcheckpointの `lastSequence` はintent時点のままなので、checkpointからの再購読で通知が再配送され得る。再配送を操作の再実行として扱わない。
- **fault injection:** storeの `CommitFault::{BeforeRows,BeforeCommit}` はintent transactionに、`ResultFault::BeforeUpdate` はresult記録に使う。どちらも `test-support` feature限定で、production hostは有効にしない。


## Task 5で固定したbashとmanaged process groupの契約

実装は `crates/herness-core/src/tools/{bash,process}.rs`、testは `tests/runtime/tests/shell.rs`。

- **起動:** frozen cwdで `/bin/sh -c <command>` を実行する。stdinはnull、stdout/stderrはpipe、環境変数はhostから継承し、`PATH` を書き換えない（Finderの最小PATH検出はTask 6）。`CommandExt::process_group(0)` で子を自分のprocess groupのleaderにする（`setpgid(0,0)` と同じ意味）。pidとpgidは等しく、`shell.spawned` eventとobservationへ記録する。
- **順序:** schema/purpose検証 → 重複operation ID拒否 → cwd確認 → checkpoint + `OperationIntent` + `shell.started` eventを1 transactionで保存 → spawn拒否判定 → spawn → `shell.spawned` eventとpid/pgidを保存 → stdout/stderr capture → wait/stop/timeout → `Applied`または`Unverifiable` result + `ShellObservation` + `shell.finished` eventを1 transactionで保存 → 成功または構造化errorを返す。
- **事前失敗:** cwd不正、intent保存失敗（`CommitFault::{BeforeRows,BeforeCommit}`）、権限拒否・未承認、空白purposeはspawnしない。spawn試行回数は `ProcessLauncher` のtest wrapperで0を確認する。production IPCへcounterを追加しない。
- **出力:** stdout/stderrは各自の専用threadで読み、head 64 KiB + tail 64 KiBだけ保持する。切詰め時は `truncated: true`、`originalBytes`（観測した全byte数）、本文中の `[herness output truncated: ...]` markerを残す。groupを停止・killするとpipeが閉じてreaderが戻る。group外のprocessがpipeを保持してEOFにならない場合は、bounded待機後に `[herness output capture incomplete: ...]` を付けて `truncated: true` とし、全量保存済みとは表示しない。
- **stop制御:** `ProcessSupervisor::begin_stop` は以後の新規spawnを拒否し、登録済み全groupへSIGTERMを送る。spawnとstop開始は同じgateで直列化し、stop開始後にprocessを作らない。`stop_all(grace)` は全groupをまとめてgrace待機し、残存groupへSIGKILLを送り、`DEFAULT_CONFIRM_TIMEOUT` までgroup消滅を待つ。executorは直接の子をreapし、groupが空になったことを確認できたときだけ `stop_requested`、できなければ `unconfirmed` を記録する。host stopではexecutorが勝手にSIGKILLしない。10秒後の人間への待機継続・強制終了の確認はTask 12が `begin_stop` / `stop_all` を使って実装する。`stop_all(Duration::ZERO)` は即時強制停止に使える。supervisorのstopはterminalで、同じsupervisorで新規runを再開しない（runごとにsupervisorを作る）。
- **timeout:** `timeoutMs` は同じgroup終了経路を使い、既定2秒の猶予後にSIGKILLする。observationは `stopStatus: timeout`、exit codeまたはsignalを記録し、resultは `Unverifiable`、呼出し側には `TimedOut` errorを返す。timeoutを成功として返さない。
- **停止不能:** groupが消えたことを確認できない場合は `stopStatus: unconfirmed`、`shellOutcomeUnknown: true`、result `Unverifiable` とし、成功・停止済みと表示しない。意図的な `setsid`・double forkは管理group外であり、捕捉を保証しない。testはdetached processが生き残り、observationが管理groupだけを記述することを確認する。
- **永続失敗:** intent保存前の失敗はspawnしない。実行後のresult保存失敗はcommandを再実行せず、rollbackもせず、`Unverifiable` を返してintentをpendingのまま残す。`shellOutcomeUnknown` を保存できない場合は、reconciliationがpendingを不確実として扱う。
- **event:** `shell.started` はcommand・purpose・cwd・timeoutMs・startedAt、`shell.spawned` はoperationId・pid・pgid・spawnedAt、`shell.finished` は停止結果・exit code・signal・stdout/stderrのbyte数と切詰めflag・observation summaryを持つ。出力本文はresult evidenceだけに保存し、historyを肥大化させない。purposeと出力は別fieldで、bashは `file.change` / `file.change.intended` eventを出さず、file別rationaleやactorを捏造しない。
- **再起動:** `reconcile_shell_operation(record, events)` はcommand・purpose・cwd・timeoutMs・pid/pgid（result observationまたは `shell.spawned` eventから）・startedAt・outcome・stopStatus・不確実flagを返す。pending intentは `shellOutcomeUnknown: true`、outcomeなしのまま。native fileのhash一致をshell成功の証拠にしない。restart後の再実行は `DuplicateOperation` でspawnしない。
- **test:** `tests/runtime/tests/shell.rs` は実store・一時project・実processで、子/孫の停止、SIGTERM無視時のSIGKILL、output floodと切詰め永続化、停止後のresult保存失敗、拒否・未承認・空白purpose・事前保存失敗のspawn回数0、file変更理由の非捏造、timeout、再起動非再送、detached子の非保証を確認する。
- **fault injection:** storeの `CommitFault::{BeforeRows,BeforeCommit}` はintent transactionに、`ResultFault::BeforeUpdate` はresult記録に使う。どちらも `test-support` feature限定で、production hostは有効にしない。

## Task 1で固定した契約と検証

`herness-core` のtestは次を確認する。

- **contract version:** 1のみ受付。0・2は `UnknownContractVersion`、非数値は `InvalidContractVersion`。event JSONの `contractVersion: 2` はdeserialize時に拒否する。
- **ID:** project・agent・session・run・operationはtypedかつproject-scoped。別projectのIDは `CrossProjectReference` で拒否する。kindの異なるprefixや不正UUIDも拒否する。
- **run状態:** `running`, `awaiting_approval`, `paused`, `interrupted`, `idle`, `failed` の6つ。`idle` は「engineに未完了の応答・tool callがない」状態として文書化し、Task/goal完了を表す状態や `completed` 状態を持たない。
- **rationale / purpose:** trim後に非空、最大1,000 Unicode scalar values。空、空白のみ、1,000、1,001、非ASCII（`あ`）、astral plane（`😀`、UTF-16では2,000 code units）で境界を検証する。byte長・UTF-16長は使わない。
- **tool schema:** read・search・write・edit・bash。offset/limit/maxResults/timeoutMsの0、空path/query、未知field、空のrationale/purpose、1,001文字のpurposeを拒否する。
- **frozen operation:** 最終引数・cwd・policy版・許可モードをprivate fieldへ固定し、deserialize時も再検証する。別projectのoperation IDとtool/引数の不一致を拒否する。
- **event:** `contractVersion`、project/agent/session/run、任意のoperation、sequence、kind、時刻、payloadを持つ。sequence 0とproject混在を拒否する。
- **checkpoint:** `formatVersion` 付きopaque bytes。0を拒否し、任意bytesのround-tripとDebugのredactionを確認する。coreは内容を解釈しない。
- **history:** 既定100件、上限500件。0件・501件、cursor 0を拒否する。
- **connection:** 公開JSONはconnection ID・provider・model・認証方式・状態だけを含み、token/secret/authorization fieldを持たない。
- **ports:** engine・store・credential・permission evaluatorはtrait objectとして利用可能。fake実装でcommit、checkpoint、history、secret redaction、configured/automatic modeの可用性を確認する。
