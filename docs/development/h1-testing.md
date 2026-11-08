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
cargo test -p herness-engine-pi
cargo test -p herness-runtime-tests
cargo test -p herness-runtime-tests --test permissions
cargo test -p herness-runtime-tests --test files --locked
cargo test -p herness-runtime-tests --test shell --locked
cargo test -p herness-runtime-tests --test skills --locked
cargo test -p herness-runtime-tests --test connections --locked
cargo test -p herness-runtime-tests --test oauth --locked
cargo test -p herness-runtime-tests --test engine --locked
cargo test -p herness-runtime-tests --test host --locked
cargo test -p herness-desktop --lib --locked
cargo fmt --all -- --check
```

追加の静的検査:

```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

- testはnetwork・外部service・実資格情報を必要としない。依存取得後の通常実行はofflineで完結する。`skills` testは存在する場合に `/Users/h-uma/Documents/sdd` をread-onlyで読み、fingerprintとtoolchainを報告するが、packを変更しない。
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

## Task 6で固定したSDD pack・skill指紋・toolchain検出の契約

実装は `crates/herness-core/src/skills/{pack,digest,overlay,capability,context,toolchain}.rs`、fixtureは `tests/runtime/fixtures/skills/`、testは `tests/runtime/tests/skills.rs`。新しいcrate依存は追加せず、`sha2` をdigestに再利用する。

- **pack root:** hostが明示する絶対パスだけを受け付け、`SkillPack::open` でcanonicalizeする。暗黙の `../sdd` 探索やpackのコピーは行わない。`SkillId` は `<pack-root>/skills/<id>/SKILL.md` の1 path componentで、個別にコピーした `SKILL.md` を正本にしない。
- **原文digest:** `SkillDocument` は `skillId`・canonicalな `skillPath`・pack root・`SKILL.md` 原文bytesのSHA-256 lowercase hexを記録する。digestは改行やrendered textの正規化前のbytesに対して計算する。
- **相対参照:** skill内のMarkdown link `](target)` と、load時に明示した参照（例: 散文でだけ言及される `implementer-prompt.md`）を、skillのあるdirectory基準で解決する。解決先はpack内にcanonicalizeできなければ拒否し、pack外escapeは `OutsidePack` とする。cwd・project・コピー先は基準にしない。存在しない自動linkは無視し、明示参照の不在は `NotFound` とする。fingerprintの `relativePath` はpack root基準の `/` 区切りで記録する。参照先は `references[]` に絶対path・digest・byte数を持つ。
- **複合fingerprint:** `combined` は `herness.skill.fingerprint.v1\0`、長さprefix付きdocument digest、参照件数、各参照の長さprefix付きpack-relative pathとdigestのSHA-256。参照はpack-relative path順で、同一pathは1回だけ含む。
- **run途中の変更:** `SkillDocument::revalidate()` は元のexplicit参照を保ったまま再読込みし、`DocumentChanged` / `ReferenceChanged` / `ReferenceAdded` / `ReferenceRemoved` と新旧fingerprintを返す。`ensure_current()` と `SkillRunContext::ensure_current()` は変更時に `SkillFailure::ChangedDuringRun` を返す。古いfingerprintを同一視して再利用しない。`SkillRunContext::revalidate()` は全skillの変更を報告する。
- **host overlay:** `HostOverlay` は `skillId`・`provenance: "host"`・`addedText`・任意の `removedText` を持つ。`apply` はpack本文に削除と追加をin-memoryで適用するだけで、packを書き換えない。`removedText` はtrim後に非空ならちょうど1回出現する必要があり、不在・複数回は構造化errorにする。overlayはrun contextのsource fingerprintと並べて記録する。
- **run context:** `SkillRunContext::build(packRoot, documents, overlays, flows, capabilities)` は同一pack root・重複なしを検証し、skill id順のentryに原文・fingerprint・overlay・flowを保持する。読み込み（`ReadOnly`）とworker flowの実行を区別する。
- **capability:** `HostCapabilities::h1()` は `SkillRead` を `Available`、`HtmlWorker` と `SddTaskController` を `Unavailable { reason: NotImplementedInH1 }` とする。`require_execution` は利用不能なworker flowに `SkillFailure::CapabilityUnavailable` を返し、親モデルdispatchや別validatorへのfallbackをしない。skill本文の読み込み自体は継続できる。
- **toolchain:** `ToolchainConfig` は明示的な実行パス、設定search directory、capture済み `PATH` snapshotを持つ。明示pathがあるtoolはその候補だけを使い、別の実行ファイルで黙って置換しない。明示pathがなければ設定directory→`PATH` の順で探す。Gitは `--version`、Pythonは `--version` をparseし、最小3.11.0と比較する。`html-docs` は実行可能なscriptと3.11+のPython interpreterの両方を必要とし、`python -B <script>` を引数なしでprobeして終了codeと応答有無を記録する。probeの終了codeはvalidator成功の主張ではない。PATHが `/usr/bin:/bin:/usr/sbin:/sbin` のFinder相当でも、明示pathのtoolは検出できる。
- **不足時:** 不在は `Missing`、非実行fileは `NotExecutable`、旧Pythonは `InsufficientVersion { found, minimum }`、interpreter不在のvalidatorは `InterpreterMissing` を返す。`ToolchainReport::deficiencies()` / `require()` がcapability不足結果を返し、自動install・別validatorへの置換・成功扱いをしない。`pip install` 等は実行しない。
- **実pack:** `/Users/h-uma/Documents/sdd` はread-onlyでだけ開く。testは `skills/sdd-execute`（`implementer-prompt.md` を明示参照）と `skills/sdd` の実fingerprint、`SkillRead` と `SddTaskController` の可用性、実toolchainの検出結果を出力し、packを変更しない。packが存在しない場合は理由を明示してskipする。

## Task 7で固定した接続設定とKeychainのcredential境界

実装は `crates/herness-core/src/connections/`、`src-tauri/src/credentials/`、testは `tests/runtime/tests/connections.rs` と `src-tauri` のadapter unit test。`src-tauri` はTask 7では `herness-desktop` というlibrary packageだけで、Tauri設定・window・IPC・binaryはTask 11が追加する。

- **依存:** coreの依存はTask 1の5 crateから増やさない。`herness-desktop` はmacOSでのみ `security-framework` 3.7.0と `security-framework-sys` 2.17.0を使い、Keychain adapterのOSStatus変換に限定する。HTTP client・async runtime・TauriはTask 7へ追加しない。
- **接続の種類:** OpenAI APIキー、Anthropic APIキー、OpenAI互換APIキー、ChatGPT OAuth（`Provider::OpenAi` + `AuthMethod::ChatGptLogin`）。OpenAI互換だけがcustom endpointを持ち、他のproviderへendpointを付けると構造化errorになる。ChatGPTの認可flow自体はTask 8。
- **URL:** `Endpoint` は `http`/`https` のみを受け付け、`https` は常に許可する。`http` は `127.0.0.0/8`・`::1`・`localhost` だけ自動許可し、remote `http` は `InsecureRemoteHttp::Acknowledged` を設定へ記録しなければ拒否する。空host・userinfo・制御文字・空白・非HTTP scheme・query・fragmentを拒否し、scheme/hostを小文字化、default portと末尾slashを正規化する。
- **redirect:** `redirect_auth_decision` はscheme・host・portが完全一致するsame-originだけ `AttachAuthorization` を返す。scheme downgrade、port変更、別host、不正targetではheaderをdropし、`requires_re_resolution: true` を返す。実際のHTTP redirectはTask 7では送らない。
- **設定registry:** `ConnectionAdmin`（人間設定専用のwriter）と `ConnectionDirectory`（tool・engine向けのread-only view）を分ける。settingsはprovider・model・authMethod・endpoint・opaqueな `CredentialRef`・remote HTTP acknowledgmentだけで、secretを含まない。Task 7ではin-memoryで保持し、非secret settingsの永続化はTask 10/11が既存storeへ追加する。
- **credential保存:** `CredentialWriter`（`CredentialAdmin`）はwrite-onlyで、`save_api_key` / `save_oauth_token_set` / `remove` だけを持つ。UI向けのread-back APIはない。`CredentialBroker` はengine用で、`CredentialPort::resolve` と非secret statusだけを提供する。
- **vault:** `CredentialVault::{set,get,delete}` はbytesだけを扱い、`VaultFailure` を返す。macOS adapterはgeneric passwordをservice `com.herness.credentials`、account `connection/<connectionId>/<authMethod>` に保存する。denial・locked・unavailable・update failure・duplicate・missing・invalid dataは `CredentialFailureKind::{KeychainDenied,KeychainLocked,KeychainUnavailable,KeychainWriteFailed,KeychainDuplicateItem,KeychainItemMissing,InvalidCredentialData}` へ変換する。plaintext file・env・DBへのfallbackは実装しない。
- **解決:** 選択された `ConnectionId` だけをregistryで引き、vaultの該当accountだけを読む。credentialが無い場合は `AuthenticationRequired`、期限切れ・refresh不能は `CredentialUnavailable`、vault失敗は対応する `CredentialFailureKind` で停止する。別provider・別connectionへのfallbackは行わない。
- **refresh直列化:** connectionごとに独立したgateを持ち、同一connectionの同時resolveは最大1回だけrefreshする。別connectionは独立して進む。refresh失敗はfailureを返し、期限切れの旧tokenをfreshとして返さず、vaultのbytesも置き換えない。成功した新token setは使用前にvaultへ保存する。
- **status:** `ConnectionStatus` に `AuthRequired` を追加した。`Available` / `LoginRequired` / `AuthRequired` / `Unavailable` を公開し、`ConnectionState::Unavailable { failure }` はsanitized `CredentialFailureKind` だけを持つ。`ConnectionInfo` の既存field（connectionId, provider, model, authMethod, status）は変えない。
- **redaction:** `redact_url` はuserinfo・query・fragmentを落とし、不正URLはechoしない。`redact_header(s)` はAuthorization・Proxy-Authorization・Cookie・Set-Cookie・API key headerを `[REDACTED]` にする。`redact_known_secrets` / `redact_error` は合成errorのdetailに混入した既知secretを除去する。
- **test:** `tests/runtime/tests/connections.rs` はfake vaultだけを使い、real Keychain・network・real credentialを参照しない。canaryがDB・checkpoint・event・fake vault以外のfileへ出ないこと、keychain denial/lock/update failureでfileが作られないこと、2接続間の非fallback、同一・別接続のrefresh分離、期限切れtokenの非公開、redirect origin表を確認する。`herness-desktop` のunit testはbackend fakeでOSStatus変換とround-tripを確認する。実KeychainはTask 13の許可された検証まで実行しない。

## Task 8で固定したChatGPT OAuthと利用条件gate

実装は `crates/herness-engine-pi/src/auth/`、testは `tests/runtime/tests/oauth.rs`、確認記録は [ChatGPT auth research](../research/2026-11-08-h1-chatgpt-auth.md)。`herness-engine-pi` はTask 8でworkspace memberへ追加し、Task 9でpi crateとasync/HTTP依存を加えた。

- **確認とgate:** 2026-11-08に公式overview・sign-in・accounts/sessions・models/inferenceを再確認した。公式はChatGPT plan usageをopen-source / locally hosted app向けとし、paid/remotely hostedはinterest formへ案内する。hernessはlocally hosted・未公開・非商用だがlicense未決定なので、許可するのは`TermsGate::LocalUnpublishedUse`だけ。`ChatGptAuthConfig::new`の既定gateは`Closed(ConditionsUnconfirmed)`で、hostが研究記録を確認してlocal unpublished useを明示した場合だけ開く。公開・配布・license選択・商用提供・remote hosting・申請は行わず、`TermsGate::Closed`ではlogin attemptを開始しない。実login・実model接続・実credential作成は未確認で、Task 13の別途許可まで行わない。
- **依存:** engine crateのauth依存は`herness-core`、`base64`、`ring`、`serde`、`serde_json`、`sha2`、`uuid`だけ。HTTP client・async runtime・pi crateはTask 9まで追加しない。`ring`はID tokenのRS256/ES256署名検証とPKCE用乱数・合成RSA/EC署名鍵のtestにだけ使う。`unsafe`は自crateに書かない。
- **endpoint:** authorizeは`https://auth.openai.com/api/accounts/authorize`、tokenは`https://auth.openai.com/api/accounts/oauth/token`、issuerは`https://auth.openai.com`、resourceは`https://api.openai.com/v1`。JWKSとrevocation endpointはTask 8では取得しない（注入境界のみ）。実URL・key rotation・discoveryはTask 9/13で確認する。
- **host ID:** 初回sign-in前に`urn:uuid:<UUIDv4>`を生成し、injectable `HostIdStore`へ保存する。`FileHostIdStore`はapp-data fileへ`0600`・temp file + renameで書く。値はsecretではなく、同じstoreで再起動しても再利用し、別storeでは別値になる。公式推奨のJWK thumbprint URIはoptionalかつprivate key possession未検証のため採用しない。
- **client registration:** 初回は`client_id=dynamic_agent_client`、`agent_name_hint`、`ext_agent_host_id`を送る。callbackのissued `client_id`（例 `oaiapp_...`）を保存し、以降はissued client IDだけを使う。`dynamic_agent_client`を保存・exchangeせず、callbackで返っても`InvalidIssuedClientId`にする。再認可は`agent_name_hint`を省略し、保持ID tokenを`id_token_hint`、検証済みemailを`login_hint`に使える。callbackのclient IDが選択中と違えば`ClientMismatch`で拒否し、既存accountを置換しない。
- **listenerとattempt:** `CallbackListener`はbrowserを開く前に`127.0.0.1`へbindする。scheme/host/pathは`http://127.0.0.1:<port>/auth/callback`で固定し、portだけが変わる。`localhost`を使わず、port競合時はephemeral portへfallbackする。attemptごとにfresh state・nonce・PKCE verifier（S256 challenge）を作り、一つのcallbackだけを受け付ける。同じattemptの再完了は`CallbackReplay`、cancelはlistenerを閉じて`Cancelled`を返し、codeをexchangeしない。stateはcallback処理の最初に検証する。
- **token exchange:** `TokenTransport::exchange`へissued client ID、code、verifier、authorizeと同一のredirect URI、resourceを渡す。form-encoded `authorization_code` grantでclient secretは送らない（実transportはTask 9）。`invalid_grant`は`Transport` failureとして保存せず停止する。
- **ID token:** `JwkSet`のRSA（RS256）またはEC P-256（ES256）keyで署名を検証する。issuer、issued client IDと一致するaudience、expiry（60秒skew）、attemptのnonce、非空`sub`を検証する。`sub`をaccount identityとし、emailをworkspace identifierにしない。署名・issuer・audience・expiry・nonceの各拒否testは保存・選択が0件のまま終わる。
- **scope gate:** token responseのgranted scopeを保存し、`chatgpt.tokens.use.direct`がある場合だけplan usageを有効にする。scopeが無い/欠ける場合はID tokenが有効でも`AuthenticatedWithoutPlan`とし、connectionを選択せず`LoginRequired`のままにする。`OAuthTokenSet`の`plan_usage: Option<bool>`が明示されたgateで、scope stringが空でもplan使用可と誤判定しない。
- **credential分離:** `VaultAccount`は`connection/<connectionId>/chatgpt_login/<issuedClientId>/<subjectのSHA-256>`でaccountごとに分かれる。`ConnectionSettings`は非secretの`vaultAccount`選択を持ち、`select_chatgpt_account`は同じconnectionのChatGPT account keyだけを受け付ける。新しいloginはID token検証・token保存が成功した後だけ選択し、失敗時は既存accountのmaterialと選択を保つ。二つのaccountは同じconnectionでも別vault itemになり、上書きしない。
- **保存形式:** `CREDENTIAL_FORMAT_VERSION`を2へ上げ、`OAuthTokenSet`へ`id_token`、granted scopes、plan_usage、verified subject、issued client ID、emailを追加した。v1 payloadは引き続き読めるがv2 account fieldを持てない。secretは`SecretString`のままで、Debugはaccess/refresh/ID token・subject・emailを`[REDACTED]`にする。Keychain以外の平文保存は行わない。
- **refresh:** Task 7のconnection別gateと`CredentialBroker`を使う。`ChatGptRefresher`はissued client ID（`dynamic_agent_client`不可）・refresh token・resourceで`refresh_token` grantを送り、返却されたaccess、expiry、scope、回転refresh tokenを一つの`OAuthTokenSet`へまとめる。ID tokenが返ればnonceなしで署名・issuer・audience・expiryを再検証し、subjectが変われば失敗する。plan scopeを失うrefreshは`PlanScopeMissing`で停止し、旧materialを置き換えない。同一connectionの同時resolveは最大1回だけrefreshする。
- **sign-out:** refresh tokenがあれば`TokenTransport::revoke`を呼ぶが、OIDC discoveryはTask 8では未取得なので結果は`NotAttempted` / `RequestAcceptedUnverified` / `FailedUnverified`のいずれかで、provider側のrevokeをconfirmedと表示しない。vault上のaccess/refresh/ID tokenを削除し、選択中なら`vaultAccount`をclearする。issued client ID・host ID・非secret account mappingは次回sign-in用に保持する。削除失敗は`Vault` errorで成功と表示しない。
- **redaction:** `AuthorizationUrl`のDebugはscheme/host/pathだけを残しquery（state・nonce・PKCE・`id_token_hint`）を落とす。`PendingAuthorization`、`TokenExchangeRequest`、`RefreshRequest`、`RevokeRequest`、`TokenResponse`、`OAuthTokenSet`のDebugはcode・verifier・tokenを出さない。canary testでauthorization URL、Debug、errorにsecretが現れないことを確認する。
- **test:** `cargo test -p herness-runtime-tests --test oauth --locked`。loopback listenerと合成RSA/EC署名鍵だけを使い、正常系、state/nonce/署名/issuer/audience/expiry拒否、plan scope欠落、callback再送、issued client ID欠落、`dynamic_agent_client`拒否、client不一致、port競合、cancel、2 account分離、同時refreshと回転、refresh失敗、保存失敗、sign-out/revoke未確認、canary redaction、host ID再利用を確認する。実OpenAI hostへのrequestは0件。

## Task 9で固定したpi engine adapterとprovider経路

実装は `crates/herness-engine-pi/src/{adapter,session_store,stream,events,error}.rs`、testは `crates/herness-engine-pi` のunit testと `tests/runtime/tests/engine.rs`。`herness-engine-pi` は `herness-core` にだけ依存し、coreからengineへの依存は追加しない。

- **固定dependency:** `pi-agent`・`pi-ai`・`pi-embedded` を `https://github.com/yannelli/pi-rust` の `rev = "4294dba7ac3646477912cc778536fdff0a912d6e"`（v0.12.11）へ固定する。`Cargo.lock` を追跡し、branch追従・fork・vendoringは行わない。async bridge用に `tokio`（multi-thread、2 worker）、`tokio-util`、`futures`、`async-trait`、`anyhow`、host HTTP用に `reqwest`（rustls、redirect無効client）を使う。piの型・JSON・errorは公開しない。
- **session分離:** engine runごとに独立した `EmbeddedRuntime`・`EmbeddedSession`・`SessionStore`・`ToolGateway`・`ProcessSupervisor` を作る。同期`EnginePort`とasync SDKの間はadapter所有のtokio runtimeで橋渡しし、`poll_events`はrun別queueをdrainするだけにする。複数sessionで会話・tool・process状態を共有しない。一方、同一engine内のsessionは1つの`FileLockRegistry`を共有し、同一canonical fileへのwrite/editを直列化する。
- **checkpoint:** `CheckpointFormatVersion(1)` のadapter所有envelope（`format`・`engine: "pi-embedded"`・run/agent/session/connection/cwd/instructions・SDK `snapshot`）をcoreのopaque bytesとして保存する。未知のcheckpoint形式・envelope形式・SDK snapshot形式は破棄せず読み込みを拒否する。`resume`は保存済み最新checkpointと一致する場合だけ復元し、古いsnapshotを上書きしない。復元はSDKの`recover`だけで、model request・tool再送を開始しない。
- **intentとcheckpointの同一transaction:** write/edit/bashの`OperationIntent`は既存`NativeFileTools`/`BashExecutor`がside effect前に保存する。adapterの`EngineStore`はそのcommit内のaudit checkpointを現在のengine snapshotへ置換し、`engine.tool.intent` eventを先頭に加えて同じ`commit_checkpoint`で保存する。重複した同一intentはcoalesceし、異なる引数の同じoperation IDは`DuplicateOperation`で拒否する。read/searchは副作用がないためintentを作らない。resultはexecutorがside effect後に別transactionで記録する。
- **5 tool限定:** pi-embeddedへ登録するのはhost所有のread・search・write・edit・bashの`FnTool`だけ。SDK宣言は`effect: Read`・`approval: false`とし、SDK内蔵のfile/shell toolやSDK-local approvalでhost gatewayを迂回させない。tool handlerは最終引数をhost schemaで再検証し、`ToolGateway`のauthorize→intent/checkpoint→execute→resultの順を守る。deny・awaiting approvalではside effectを実行せず、`engine.tool.denied` / `engine.tool.awaiting_approval` eventを保存してmodelへ構造化failureを返す。完全でない引数はSDKがtool handlerへ渡す前に拒否する。
- **operation ID:** SDKのtool-call IDとrun IDからSHA-256で決定的に導出する。同じrun・同じtool-call IDは同じoperation IDになり、storeのunique制約で二重適用しない。providerが同じtool-call IDを再利用した場合はSDKがrunを失敗させる。
- **stop:** `request_stop`は新規spawnを拒否し、`ProcessSupervisor::begin_stop`で管理groupへSIGTERMを送ってからSDKの`cancel`を待つ。停止を確認できなければ`Unconfirmed`を返す。途中停止後のcheckpointは`interrupted`で、再起動時にpending/uncertainなtoolを再送しない。
- **stream:** host所有の`StreamFn`が要求ごとに`CredentialPort::resolve`で選択connectionのcredentialを解決し、`max_retries = 0`でpi-aiのproviderを呼ぶ。OpenAI APIキーは`openai-responses`、Anthropicは`anthropic-messages`、OpenAI互換は`openai-completions`。`create_openai_stream`（completions専用）で全providerを対応済みとは扱わない。
- **ChatGPT:** `GET https://api.openai.com/v1/models` の`models`配列から`visibility == "list"`だけをserver順で取得し、`slug`を選択modelとして使う。選択modelがcatalogに無ければrunを開始せず、別model・別providerへfallbackしない。Responsesはpublic `POST https://api.openai.com/v1/responses`へ`store: false`・`stream: true`で送る。`response.completed`前の切断、`response.incomplete`、`response.failed`（usage-limit codeを含む）、明示errorは失敗とし、`length`終端もengine errorへ変換する。`backend-api` endpointは使わない。catalogはhost所有の狭いHTTP GETで、redirectは`redirect_auth_decision`で判定する。restore時はcatalog GETも含めnetwork requestを送らない。
- **secret:** credentialは各requestで解決し、SDKのmodel・provider error文、diagnostics、snapshotの`error`は保存前にsanitizeする。canary testでAPIキーがcheckpoint・event・DB・WALへ出ないことを確認する。tokenはprovider streamのheaderだけに使い、event・checkpoint・logへ出さない。
- **test:** `cargo test -p herness-engine-pi` はenvelope/unknown version/duplicate save、audit checkpoint置換、intent+checkpoint同一transaction、operation ID、event変換と再配送dedupe、catalog filter、provider mappingを確認する。`cargo test -p herness-runtime-tests --test engine --locked` はloopback mockだけで、OpenAI・Anthropic・OpenAI互換・ChatGPTのtext/tool往復、request形状、terminal、cancel、auth失敗、ChatGPTのcatalog・`response.completed`必須・incomplete/failed/early disconnect・backend-api非使用・model非fallback、複数session非混入、SQLiteのintent先行とengine checkpoint、event/history再配送の非再実行、tool ID重複、途中停止とrestore非再送、未知checkpoint形式の拒否と保持、secret canary、requestごとのcredential解決を確認する。実provider・実Keychain・実loginはTask 13の許可まで実行しない。

## Task 10で固定したhost runtimeの契約

実装は `crates/herness-core/src/runtime/`、testは `tests/runtime/tests/host.rs`。`Runtime<S, E, T>` はstore・engine・credential・evaluator・tool実装を外側から注入され、`herness-core` から `herness-store` / `herness-engine-pi` / Tauriへの依存を追加しない。

- **project:** `open_project` は実パスをcanonicalizeし、読めるdirectoryだけを受け付ける。同一のcanonical real pathは同じ `ProjectId` に戻り、別pathは別projectになる。返す `ProjectView` は接続の非secret状態、`HostCapabilities::h1()`、toolchain検出結果（不足を含む）を持つ。読めないpath・directoryでないpathは拒否し、capability不足を隠さない。
- **agent / run:** agentはhostが作り、独立した `AgentId`/`SessionId` を持つ。runは既存agentに紐づく別の `RunId`。`start_run` は選択接続の現在status、`PermissionMode`（automaticは利用可能なevaluator必須）、agentの要求capabilityを `EnginePort::start` より前に確認する。run stateと `run.started` eventは同じtransactionで永続化してからengineをstartする。拒否時はengine request 0件。
- **run state:** `running` / `awaiting_approval` / `paused` / `interrupted` / `idle` / `failed` を区別する。`idle` はengineがquiescentである事実だけで、Task/goal完了や新runの自動開始を意味しない。`stop_run` は `Stopped`/`NotRunning` を `paused`、`Unconfirmed` を `interrupted` に写像してcheckpointを保存し、`failed` とは区別する。`resume_run` は明示的な人間操作で、現在のcredential・connection・mode・run grantを再確認し、保存checkpointからのみ復元する。model inputの自動再送はしない。`idle` runはresumeできず、追加実行は新runにする。
- **approval:** `PermissionOutcome::AwaitingApproval` ではfrozen operationと承認待ちをhost stateへ永続化し、runを `awaiting_approval` にしてから戻る。executorは呼ばない。`approve(operation_id)` は保存済みoperation・project・policy version・mode・args/cwd bindingを再確認し、現在のpolicy・credential・connectionを再確認してから、gatewayのsingle-use authorizationを消費してexecutorを一度だけ呼ぶ。結果とaudit eventを保存し、host作成のcontinuation inputでengineへ結果を伝える（SDKのtool-result frameを捏造しない）。2回目、deny後、引数変更、policy/mode変更、run resume、restart後の承認はexecutorに到達しない。`deny` はeventだけを保存し、executorを呼ばない。`pending_approvals` はrestored/reusable flag付きでUIへ返す。
- **child agent:** hostだけがagentを作れ、親model向けのdispatch toolは登録しない。`AgentSpec::child_of` は親のgrantから `GrantScope::derive_child` でsubsetだけを受け付け、広いscopeは `GrantWidening` で拒否する。
- **restore:** `Runtime::restore` はhost stateを読み、running/awaiting_approvalを `interrupted` にし、既存の承認を `restored` かつ再利用不可にする。`unresolved_operations` を読み、native fileは現在内容と意図の比較で `applied`/`not_applied`/`unverifiable`、bashは `shell uncertainty`、read/searchは副作用なしとして照合する。engine start・model request・tool実行・承認再利用は行わない（testはrequest 0件を確認）。`resume_run` は照合後の明示的な人間操作としてのみ提供する。
- **subscription:** `subscribe(project, cursor, limit)` はproject-bound `SubscriptionCursor` のsequenceより後のcommit済みeventだけを昇順で返し、`last_sequence` を返す。`snapshot` はrun状態・pending approval・last sequenceを返す。storeにcommitされる前のeventは返さない。再配送は購読の読み直しであり、操作を再実行しない。別projectのcursorは `CrossProject` で拒否する。
- **永続化:** storeのschema 3で `host_state (key TEXT PRIMARY KEY, value BLOB)` を追加した。値はformat 1のversioned JSONで、project path、agent/session/run metadata、run state、child grant mirror、pending approvalのfrozen operation/reason/restored flagだけを持ち、secret・token・checkpoint・provider raw errorを含めない。未知format/未知fieldは黙って解釈せず `CorruptState` にする。既存schema 1/2からのmigrationはadditiveで、既存table・event・operation・checkpointを変更しない。
- **test:** `cargo test -p herness-runtime-tests --test host --locked`。実SQLite store、一時project、scripted `EnginePort`、fake credential、実 `NativeFileTools` のcounting wrapperを使い、2 project・複数agent分離、start拒否、承認前side effect 0、approve 1回、deny 0回、stale approval、停止・再開、idleとfailed/interruptedの区別、restore request 0、照合分類、購読再接続の重複・欠落なし、再配送非再実行、cross-project拒否を確認する。network・実Keychain・実provider・Tauriは使わない。

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

## Tauri 2.12.5 command ACLと最小画面（Task 11）

2026-11-08にTauri 2の現行ドキュメント（Capabilities、Permissions、Calling Rust from the Frontend、Configuration、CSP）を確認した。固定する依存は `tauri = 2.12.5`、`tauri-build = 2.7.4`。`src-tauri/build.rs` は `tauri_build::AppManifest::new().commands(...)` で全custom commandの `allow-<command>` / `deny-<command>` ACLを生成し、`src-tauri/capabilities/main.json` はそれを `windows: ["main"]`、`local: true`、`remote` なしでmainだけへ許可する。

command layerは設定だけに依存せず、window label `main`、webview label `main`、document origin `tauri://localhost`（rootまたは`/index.html`）を毎回検証する。`tauri.conf.json` のCSPは `default-src`/`script-src`/`style-src` を `'self'`、`connect-src` を `ipc: http://ipc.localhost` に限定し、`object-src`/`frame-src`/`base-uri`/`form-action` を禁止する。navigationはlocal originだけを許可し、外部HTTP(S)はsystem browserへ渡さずWebView内で開かない（Task 11では`/usr/bin/open -u`へ渡す）。

最小画面は `ui/` の静的assetで、Node runtime・bundler・sidecarを含まない。project・tool・eventのtextは `textContent` で描画し、APIキーはwrite-only入力からKeychainへ保存後にDOMから消去する。ChatGPT loginはhostのloopback listenerとsystem browserを使い、WebViewへauthorization URLやtokenを渡さない。実token transportはTask 13まで接続せず、UIは未接続を明示する。

Task 11の検証コマンド:

```sh
cargo test -p herness-runtime-tests --test desktop --locked
cargo test -p herness-desktop --locked
cargo build -p herness-desktop --locked
HERNESS_APP_DATA_ROOT=<absolute-temp-dir> target/debug/herness-desktop --smoke-test
```

`--smoke-test` は実Tauriアプリを起動し、main windowの表示と、信頼されたUIからの `frontend_state` → `ui_ready` IPC往復を確認して0で終了する。GUI操作の人間による全確認やmacOSのclose/reopen/quitの実動作はTask 12・13の範囲とする。

## Task 12で固定した明示quit・別プロセス復旧・製品計測

実装は `src-tauri/src/lifecycle/`（`mod.rs` と `quit.rs`）、runtimeの `crates/herness-core/src/runtime/{host,shutdown,state,reconcile}.rs`、`src-tauri/src/{app,commands,host}.rs`、testは `tests/runtime/tests/desktop.rs` と `tests/runtime/tests/host.rs`。

### 明示quitの契約

- **ウィンドウ閉鎖とquitを分ける。** `CloseRequested` は従来どおり `prevent_close` + `hide` で、Rust hostをdisposeしない。macOS Reopenは同じwindowを表示し、`window.location.reload()` でページ状態を捨てる。明示quitは `quit_app` command、Cmd+Q等の `RunEvent::ExitRequested { code: None }`、`--quit-test` の3経路が同じ `QuitCoordinator` に入る。
- **受付停止。** `Runtime::begin_shutdown` は以後の `start_run` / `submit_input` / `resume_run` / `approve` / `deny` / `create_agent` を `RuntimeError::ShuttingDown` で拒否し、`host_state` に `shutdown.outcome = in_progress` を保存する。保存に失敗した場合は成功として扱わない。
- **協調停止。** `Runtime::stop_all_for_shutdown` は active（`running` / `awaiting_approval`）の全runに `StopReason::ApplicationQuit` を送り、SDKのcancelに任せる。`stop_run` と同じく `Stopped`/`NotRunning` は `paused`、`Unconfirmed` は `interrupted` に写像し、engine checkpointを取得できた場合だけ `checkpointSaved: true` とする。SDKのdisposeを保存可能な停止の代用にしない。PiEngineの `request_stop` は `ProcessSupervisor::begin_stop` の後に `stop_all(DEFAULT_STOP_GRACE)` を実行し、SIGTERMを無視する管理groupもSIGKILLまで進め、groupを確認できなければ `Unconfirmed` を返す。`explicit_shutdown_stops_a_managed_shell_group` は allowed `bash sleep` 中にquitし、管理groupの消滅と `shell.finished` の非成功記録を確認する。
- **猶予と人間の選択。** productionは10秒（`DEFAULT_QUIT_GRACE`）。`QuitCoordinator` は注入可能な `QuitClock` を持ち、testはmanual clockと短いgraceを使う。10秒を超えてactive runが残る場合、main windowを表示し、`quit_state` が `awaiting_choice` と残run・unconfirmed・save失敗・「keep waiting」可否を返す。`quit_choice` の `keep_waiting` は新しいgraceを開始し、`force_quit` は明示的に `force_quitting` へ遷移する。10秒後に黙って強制終了しない。
- **強制終了。** `Runtime::force_shutdown` は残runを `interrupted` にし、checkpoint保存・停止成功を主張しない。結果未記録の操作はresolve・rollback・再実行しない。`quit_choice(force_quit)` は最大300msだけ `force_shutdown` の永続化を試み、host lockが取れなくてもexitする。この場合shutdown recordは `in_progress` のまま残り、次回起動で「前回のquitが完了していない」として照合される。
- **終了code（証拠用）。** `0`: 全active runが停止し、checkpoint保存も確認。`3`: 停止はterminalだが `Unconfirmed` またはcheckpoint保存失敗がある（成功と表示しない）。`2`: 人間が強制終了を選んだ。`4`: `--quit-test` の待機がtimeoutした。product UIはcodeを表示しないが、reportはこれを記録する。
- **deferred host-result messages。** 承認・拒否後のhost結果がまだengine turn中のため送れなかった場合のin-memory queueは、quit時に再送せず破棄する。破棄件数を `shutdown.discardedDeferredMessages` と `ReconciliationReport.discardedDeferredMessages` / `previousShutdown.discardedDeferredMessages` に残す。再起動後に古いtool結果をengineへ再投入しない。
- **test-only注入。** `QuitClock` と短いgraceはRustのconstructor引数でだけ注入でき、IPC commandは受け付けない。`--quit-test` は実TauriプロセスでUI ready後に同じproduction quit controllerを起動するautomation launcherで、production IPCではない。

### 永続化と照合

- **host state format 2。** 既存の `projects` に加え、非secretの `connections`（`ConnectionSettings` 全体、ChatGPTの `vaultAccount` 選択を含む）と `shutdown` recordを保存する。format 1は引き続き読めるが、format 2 fieldを持てば拒否する。未知format・未知fieldは `CorruptState` で拒否する。常にformat 2で書き出す。secretは引き続きKeychainだけで、`ConnectionSettings` にtoken/API key fieldはない。
- **接続設定の復元。** `DesktopHost::open` は永続化済み設定を `ConnectionAdmin` へ戻し、registryと保存値が同じIDで食い違えばerrorにする。in-memoryだけの設定はopen時、`add_connection` 時、ChatGPT login状態確認時、quit時に保存する。復元reportのconnection statusも再計算する。実ChatGPT token exchangeは未接続のままで、選択accountの非secret mappingだけを保持する。
- **照合report。** `ReconciliationReport` は `previousShutdown`（outcome・started/finished・stopped run数・unconfirmed/remaining run ID・破棄message数・save失敗数）を持つ。各projectはrunのprevious/current state、未解決操作の `applied` / `not_applied` / `unverifiable` と証拠source、復元承認の `restored` / `reusable=false` を返す。UIはこのreportをtextとして表示する。
- **file適用直後crash。** 新しいprocessはintentだけを読み、native fileの現在内容とfrozen intentを比較して `applied` + `NativeFileContent` と分類する。これは証拠であり、storeへresultを捏造しない。shellは `ShellUncertain` / `Unverifiable` のまま人間の照合に残す。
- **起動時の非実行。** restoreはmodel request・tool実行・approval再利用・engine resumeをしない。人間の `resume_run` が現在のcredentialとpolicyを再確認してから保存checkpointを使う。

### 別プロセスfixture

`tests/runtime/tests/desktop.rs` の統合test binaryは、環境変数 `HERNESS_TASK12_WORKER=<mode>` を設定して `--exact task12_worker_entrypoint` で自分自身を再実行する。test-only process fixtureであり、production binary・IPC・featureではない。real SQLite fileと実project directoryを共有する。

| mode | 内容 | 期待exit |
| --- | --- | --- |
| `normal-quit` | 実 `DesktopHost` + 実 `PiEngine` + loopback mockでapproval待ちを作り、`begin_shutdown` → `stop_all_for_shutdown` → `finish_shutdown`。PID・run state・checkpoint有無・sequenceを出力 | 0 |
| `unconfirmed-quit` | scripted engineが `StopReport::Unconfirmed` を返す。runは `interrupted`、保存成功を主張しない | 3 |
| `force-quit` | 実storeにshell intentを残したまま `force_shutdown`。resultなし・run interrupted | 2 |
| `crash-after-apply` | 実 `NativeFileTools` でfile write intentを保存・applyした直後、result記録の直前に `std::process::exit(70)`。resultは書かない | 70 |

各parent testはworkerのPID・exit code・sequenceをassertし、別プロセスでstoreを開き直して、`previousShutdown`、run state、未解決操作、file内容、起動時request数0を確認する。`normal-quit` はさらに、credential unavailableでは `resume_run` が `ConnectionUnavailable`、credential availableでは保存checkpointからresumeでき、その間のmodel requestが0であることを確認する。

### 検証コマンド

```sh
cargo test -p herness-runtime-tests --test desktop --locked
cargo test -p herness-runtime-tests --test host --locked
cargo test -p herness-desktop --lib --locked
cargo build -p herness-desktop --locked
HERNESS_APP_DATA_ROOT=<absolute-temp-dir> target/debug/herness-desktop --smoke-test
HERNESS_APP_DATA_ROOT=<absolute-temp-dir> target/debug/herness-desktop --close-reopen-test
HERNESS_APP_DATA_ROOT=<absolute-temp-dir> target/debug/herness-desktop --quit-test
```

`--smoke-test` は既存の起動確認に加えて `SMOKE_READY: pid=... startup_ms=...` を出力する。`HERNESS_SMOKE_HOLD_MS` はready後もprocessを保持し、外部からのRSS samplingを可能にするmeasurement専用envで、productionの挙動を変えない。`--close-reopen-test` は実際の `WebviewWindow::close`（close buttonと同じ `CloseRequested`）→ `prevent_close` + hide → show + reload → 新しい `ui_ready` を確認し、`CLOSE_REOPEN_HIDDEN` / `CLOSE_REOPEN_OK` を出力する。`--quit-test` はUI ready後にproduction quit controllerを起動し、`QUIT_TEST_READY`、`QUIT_OK` / `QUIT_INCOMPLETE` / `QUIT_FORCED` を出力する。

### 計測結果（2026-11-08、現在の開発機）

- **環境:** macOS 27.2 (build 26B123), Apple M5, arm64, 16 GiB。toolchainは `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)`。
- **build mode:** `cargo build -p herness-desktop --locked` のdebug build（unoptimized、debuginfoあり）。release build・署名・配布は未検証。
- **起動時間:** `--smoke-test` を3回実行し、`app::run` 開始から信頼UIの `ui_ready` 完了までの `startup_ms` は 394、333、337 ms（中央値337 ms）。プロセスexec前のdyld・binary loadは含まない。性能目標・product promiseではない。
- **idle RSS:** `--smoke-test` + `HERNESS_SMOKE_HOLD_MS=5000` で起動し、`ps -o rss=` を2回sample。app processは135,040 KB、137,632 KB（約131.9–134.4 MiB）で、sample間に約2.5 MBの変動があった。同時に新規出現したsystem-managed WebKit XPC processは GPU 24,288 KB、WebContent 39,168 KB、Networking 8,336 KB、合計71,792 KB（約70.1 MiB）。2回目sample時点のapp + WebKit合計は209,424 KB（約204.5 MiB）。WebKit processはappの直接childではなく、起動前後のPID差分で対応付けた。
- **running RSS:** 実Tauri appで実model runを動かすには実接続の許可が必要なため、Task 12では測っていない。代わりに別processのhost composition fixture（`measure_running_host_rss`、実store・実PiEngine・loopback mock・fake credential・allowed `bash sleep 20`）で、host process 25,696 KB（約25.1 MiB、2 sampleで安定）、管理下 `sleep` child 960 KBを記録した。これはWebViewを含まないhost runtimeの値であり、上のTauri app値と同一視しない。spikeのheadless値も流用しない。
- **未確認:** 実model実行中のTauri app + WebView RSS、release build、署名・配布、Intel Mac・古いmacOS、実ChatGPT login/token exchange。

### GUI・未確認事項

- `--quit-test` は実Tauri processで「UI ready → 明示quit → 保存確認 → exit 0」を確認した。active runが10秒を超えた場合のGUI上の「keep waiting / force quit」操作そのものは自動化していない。controllerのgrace・keep waiting・force選択はmanual clockのunit testで、unconfirmed停止・強制終了・crash復旧は別process fixtureで確認する。
- `--close-reopen-test` は実際の `WebviewWindow::close` で `CloseRequested` を発火し、windowがhideされ、process/hostが生存し、show + reload後に信頼UIが再度readyになることを確認した。close buttonの人間クリックやmacOS dock reopenのOS操作そのものは自動化していない。window非依存でrun・auditが進み、reopen相当のsnapshot/historyが最新を返すことはruntime testで確認する。実際の人間操作はTask 13の受入で確認する。
- `--quit-test` はactive runがない場合だけ自動完了する。active workがある状態でhuman choiceが必要になれば `QUIT_TEST_NEEDS_HUMAN` を出してexit 4にし、成功を装わない。
- 計測値はdebug build・現在のarm64開発機の記録であり、H5の配布・軽さの目標値ではない。secret・実token・実provider errorは計測artifactに含めていない。

## Task 13 Phase Aで固定した実接続境界・実ChatGPT transport・受入手順

Task 13 Phase Aは、現在のherness実装で自動検証・実Tauri検証を実行し、実接続だけをPhase Bの明示的な許可へ残す。Phase AではOpenAI・Anthropic・OpenAI互換・ChatGPTのいずれの実hostへも接続せず、既存Keychain項目も読まず、実Keychain項目も作成・削除しない。実接続の結果はすべて**UNVERIFIED**であり、H1受入は完了していない。

### 依存とtransport

- `herness-engine-pi` の `reqwest` 0.12.28（`Cargo.lock`で固定）へ `blocking` featureを追加した。既存の `rustls-tls` とwebpki rootsを使い、独自CA・OS trust store・proxyへのfallbackはしない。
- `HttpsTokenTransport` は `https://auth.openai.com/api/accounts/oauth/token` へform-encoded `authorization_code` / `refresh_token` grantを送る。client secretは送らない。`scope` はrefreshで送らず、granted scopeを維持する。
- `DiscoveryJwksSource` は `https://auth.openai.com/.well-known/openid-configuration` を取得し、issuer一致・`jwks_uri` のHTTPS性を検証してからJWKSを取得する。`Cache-Control: max-age` を尊重し、既定300秒・上限3,600秒でcacheする。`no-store` はcacheしない。
- token・discovery・JWKSのHTTP clientはredirectを無効化し、3xxを失敗として扱う。token requestのform bodyを別originへ転送しない。`Authorization` headerをJWKS/discoveryへ付けない。
- sign-outはdiscoveryの `revocation_endpoint` へ `token`・`token_type_hint=refresh_token`・issued `client_id` をform-encoded POSTする。**空のHTTP 200だけ**を `RemoteRevokeStatus::Confirmed` とし、200以外の2xx・空でない200・network失敗はconfirmedにしない。endpointが取得できない場合もunverified。
- `LoginManager` はcallback待機とtoken exchangeを専用のhost worker threadで行う。WebViewへtoken・code・authorization URLを渡さない。完了状態は `chatgpt_login_status` のpollingで `available` / `auth_required` / 失敗理由（sanitized）として表示する。
- `ChatGptAuth::credential_port()` をdesktop hostのengineへ共有し、期限切れChatGPT tokenのrefreshをTask 7のconnection別gateで行う。APIキー接続とChatGPT接続のどちらも、別provider・別modelへのfallbackはしない。
- 信頼UIへ `chatgpt_models`（catalog GET）と `set_connection_model`（model名だけの更新）を追加した。どちらもmain window限定ACLとcommand guardを通り、provider・endpoint・auth method・credentialを変更しない。`set_connection_model` はmodelがcatalogにない場合でも接続を壊さず、run開始時/real-check時にcatalog照合で拒否する。
- `LoginManager::force_refresh` と `ChatGptAuth::sign_out_selected` は、再起動後のcontroller processでもin-memory account directoryに依存せず、保存済みの非secret settingsとKeychain token setから対象accountを再構成する。強制refreshは `CredentialBroker::refresh_at` を使い、未期限切れのaccess tokenでも同じconnection別gateの下で1回だけrefreshし、新しいtoken setを検証・保存してから返す。
- 用条件gateは従来どおり `ChatGptAuthConfig::new` の既定 `Closed(ConditionsUnconfirmed)`。desktopの `LoginManager::new` だけが `TermsConfirmation::local_unpublished()` を明示する。Phase Bでも公開・配布・商用・remote hostingへ進まない。

### opt-in real-check

`herness-desktop` のcontroller専用CLIであり、Tauriを起動せず、通常のworkspace test・smoke test・UI・IPCからは呼ばれない。

```sh
HERNESS_APP_DATA_ROOT=<absolute-root> target/debug/herness-desktop --real-check <connection-id>
HERNESS_APP_DATA_ROOT=<absolute-root> target/debug/herness-desktop --real-check <connection-id> --list-models
HERNESS_APP_DATA_ROOT=<absolute-root> target/debug/herness-desktop --real-check <connection-id> --refresh
HERNESS_APP_DATA_ROOT=<absolute-root> target/debug/herness-desktop --real-check <connection-id> --sign-out
HERNESS_APP_DATA_ROOT=<absolute-root> target/debug/herness-desktop --forget-connection <connection-id>
```

- 対象は保存済みの1 connectionだけ。provider・model・endpoint・credentialをCLIから指定・変更できない。catalogに選択modelがない場合は `model_not_in_catalog` で停止し、別modelを選ばない。
- request modeは `pi-ai` のengineと同じroute（`openai-responses` / `anthropic-messages` / `openai-completions` / ChatGPT public Responses）へ、合成prompt `Reply with the single word: herness-ok.` を1回だけ送る。`max_tokens=32`、`max_retries=0`、timeout 120秒。ChatGPTは先に `/v1/models` を読み、`visibility=list` のslugだけをcatalogとして扱う。
- evidenceは `<app-data-root>/real-check/real-check-<unix-ms>-<connection-id>-<mode>.json` へmode `0600` で書く。含むのはschema version、時刻、connection ID、provider、auth method、model、mode、endpoint class（custom endpointはoriginのみ）、terminal status、固定的なfailure label、latency、catalog latency/count、provider-reported usage、catalogのslug/display name、ChatGPTのremote revoke status、local credential削除flagだけ。token・APIキー・ID token・authorization URL・provider error body・raw provider textは含めない。
- exit code: `0` 成功、`2` 引数・接続・model選択・構成の失敗、`3` credential欠落/期限切れ/読取不能、`4` provider要求の失敗または不完全終端、`5` 予約（現在はrefreshを3で返す）、`6` sign-out/credential削除/forget失敗、`7` evidence書込み失敗。
- `--forget-connection` はChatGPTなら先にsign-out（remote revokeを試行）し、APIキーならKeychain itemを削除してから、host stateからconnectionを除く。削除失敗を成功として表示しない。
- `tests/runtime/tests/acceptance.rs` は、通常のwindow automation flagがreal-checkを選ばないこと、modeごとに明示的なconnection IDが必要なこと、real-checkとforgetが排他であることを確認する。providerへは接続しない。

### Phase B runbook（人間の許可後にだけ実行する）

#### 0. 前提と許可記録

1. 対象revision・OS/toolchain・build modeを記録する。Phase Aのcommitをcheckoutし、`cargo build -p herness-desktop --locked` でdebug binaryを作る。
2. 専用のabsolute app-data rootを決める（例: `ROOT=$(mktemp -d /tmp/herness-h1-accept.XXXXXX)`）。UIとcontrollerで同じ `HERNESS_APP_DATA_ROOT` を使う。既存のcredentialを探索しない。
3. 人間へ次を提示して許可を得る: 接続ID、provider、account、model、送信する合成prompt、最大出力32 tokens、予想される料金/利用枠、検証で作るKeychain account、login/refresh/sign-out/revokeの実行、evidenceの保存先。
4. 許可が得られない経路は実行せず、UNVERIFIEDのまま残す。providerやmodelを黙って変更しない。

#### 1. APIキー経路（OpenAI・Anthropic・OpenAI互換）

1. `HERNESS_APP_DATA_ROOT="$ROOT" target/debug/herness-desktop` を起動する。
2. 「Connection and model」でproviderを選び、最も安い利用可能modelを入力する。OpenAI互換はendpointも入力し、remote HTTPなら危険確認を明示的に行う。「Add connection」で追加し、表示されたconnection IDを記録する。
3. 追加したconnectionを選択し、write-onlyのAPI key欄へ**その場で入力した検証用キー**を入れ、「Save key」を押す。表示が保存成功になり、入力欄が空になったことを確認する。既存Keychain項目は使わない。
4. controllerで `--real-check <connection-id>` を実行する。成功はexit 0かつ `REAL_CHECK_OK: ... terminal=completed`、evidenceのprovider/model/endpointClass/usageを確認する。
5. exit 3ならcredentialを直して再実行する。exit 4ならfailure labelとevidenceを記録し、別provider/modelへ切り替えない。Anthropic/OpenAI互換も同じ手順を独立したconnectionで繰り返す。

#### 2. ChatGPT経路（login・catalog・stream・refresh・sign-out）

1. provider OpenAI、auth method ChatGPT login、modelは仮のslug（例: `gpt-5.1`）でconnectionを追加し、IDを記録する。
2. connectionを選択し「Start ChatGPT login」を押す。macOSのsystem browserが `https://auth.openai.com/...` を開く。**アプリのWebViewへOpenAIのpasswordを入力しない。**
3. browserで検証用accountのloginを完了し、アプリへ戻って「Refresh」を押す。`state: available` とaccount表示、`token exchange: https_configured_unverified` を確認する。失敗時はsanitizedな `last attempt` を記録し、成功を装わない。
4. 「List ChatGPT models」を押す。`visibility=list` のmodelだけがdisplay nameとslugで表示される。取得できなければ停止し、modelを推測しない。
5. 一番安いmodelをdropdownで選び「Use selected model」を押す。connection一覧のmodelが変わったことを確認する。
6. `--real-check <id> --list-models` を実行する。exit 0、`terminalStatus: listed`、evidenceの `models` を確認する。
7. `--real-check <id>` を実行する。catalog GETの後にResponsesへ1回だけ送る。exit 0、`terminalStatus: completed`、`response.completed` 相当の終端、catalog count、usageを確認する。
8. `--real-check <id> --refresh` を実行する。exit 0、`terminalStatus: refreshed` を確認する。refreshでrefresh tokenが回転した場合はKeychainのaccount-scoped itemが置き換わる。同時に別のrefreshを実行しない。
9. `--real-check <id> --sign-out` を実行する。exit 0、`terminalStatus: signed_out`、`localCredentialsRemoved: true`、`remoteRevoke` を確認する。`remoteRevoke` が `confirmed` 以外なら、provider側の取消しは**未確認**として記録する。local削除が失敗した場合はexit 6で、接続を残す。sign-out後はこのconnectionでrunを開始しない。
10. アプリを通常quitしてから `--forget-connection <id>` を実行する。controller processは保存状態からconnectionを除く。再度アプリを起動し、connection一覧に残っていないことを確認する。

#### 3. 検証用Keychain項目の作成・削除

- APIキー: account `connection/<connection-id>/api_key`。作成は信頼UIの「Save key」だけ。値は表示も再取得もしない。
- ChatGPT: account `connection/<connection-id>/chatgpt_login/<issued-client-id>/<sha256(subject)>`。作成はsystem browser loginの完了時だけ。
- 削除は各connectionの `--forget-connection <id>` が行う。ChatGPTは先にsign-outを実行し、`remoteRevoke` の結果をevidenceへ残す。
- 削除確認は `security find-generic-password -s com.herness.credentials -a "<account>"` が「could not be found」（exit 44）を返すこと。`security dump-keychain` や既存項目の列挙は行わない。
- 接続状態を失った孤立項目だけは、記録済みのaccountを `security delete-generic-password -s com.herness.credentials -a "<account>"` で削除する。これは検証用項目の後始末であり、結果をreportへ記録する。

#### 4. 後始末

1. UIから通常quitする（`Quit herness`）。強制終了した場合は次回起動のreconciliationを記録する。
2. 全検証connectionへ `--forget-connection` を実行し、Keychain項目の不在を確認する。
3. evidence JSONをreportの証拠へコピーし、`$ROOT` のDB・host ID・一時projectを削除する。secretはコピーしない。
4. 実接続の成功・失敗・未確認をprovider/routeごとにreportへ記録し、H1受入の完了/未完了を更新する。実接続が未確認の間はTask 13とH1受入を完了にしない。

### Phase Bで確認する未確認項目

- OpenAI APIキー経路の実request・usage・料金。
- Anthropic APIキー経路の実request・usage・料金。
- OpenAI互換endpointの実request（endpoint固有のmodel/制限を含む）。
- ChatGPTの実login・callback・token exchange・ID token/JWKS検証・plan scope。
- ChatGPTの実catalog取得、選択modelでの `response.completed`、usage。
- ChatGPTの実refresh（回転refresh token・保存）。
- ChatGPTのsign-outとremote revocation（空HTTP 200の確認可否を含む）。
- 実Keychain項目の作成・削除・不在確認。
- 実providerの料金・利用枠・認可条件。
