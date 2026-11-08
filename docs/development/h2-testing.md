# H2 supervision: 契約テスト手順

H2実装で追加する共通契約の検証手順を記録する。正本仕様は [H2 supervision design](../sdd/specs/2026-11-08-h2-supervision-design.md) と [H1 runtime design](../sdd/specs/2026-11-07-h1-runtime-design.md) の「H2 integration additions」、計画は [H2 plan](../sdd/plans/2026-11-08-h2-supervision.md)。この文書は後続Taskで追記する。

## 対象と依存方向

- 契約型とportは `crates/herness-core` に置く。coreはsupervision・assessment・store・engine-pi・Tauriへ依存しない。
- SDK型、providerの生body、credential、H2の監督状態機械はcoreへ持ち込まない。
- H1の `RunState` と許可優先順位は変更しない。`RunState::Idle` は「engineに未完了の応答・tool callがない」事実のままで、入力完結・Task完了・goal完了の証拠ではない。

## Task 1で追加した契約

### Event version

- 新規書込みは `CONTRACT_VERSION = 2` のeventだけを書く。`EventDraft::into_event` と `Event::new` はversion 2を生成する。
- 既知の読込み版は1と2。version 1は `Event::from_v1` の明示的な互換decoderでrun subjectとして読み、保存済みのproject・agent・session・run・operation・sequence・kind・時刻・payloadを保持する。version 1 JSONへ書き戻す場合も旧envelopeを維持する。
- 未知version（3以降、0）は `UnknownContractVersion` で拒否し、version 2として読み替えない。
- version 2 eventは `projectId` と `subject` を持ち、subjectは次のどちらか。
  - `RunSubject`: projectに属するagent/session/run。operation IDはrun subjectだけに付けられ、同じprojectに属する必要がある。
  - `HostActivitySubject`: projectに束縛した `activityKind` と `activityId`。runを作らず、operation IDを持たない。
- version 2に旧 `agentId`/`sessionId`/`runId` を混在させた入力、version 1に `subject` を混在させた入力は拒否する。
- Task 2でstoreのhost activity永続化を追加した。run checkpointやoperation resultは引き続きrun専用で、host activity eventを入れようとした場合は架空のrun IDを作らず `UnsupportedPortFeature { feature: host_activity_events }` または構造化event errorで拒否する。

### Inputと継続

- `InputId` は受理・開始・完結を対応付けるproject-scoped ID。`InputProgress` と `InputPhase` が受理・開始・完結・取消し・失敗を表す。
- `IdleEvidence::StartupIdle` と `IdleEvidence::InputNotCompleted` は入力完結の証拠にならない。`IdleEvidence::InputCompleted` だけが、submitした入力の完結とidleの対応を表す。
- `ContinuationRequest` は直前run、新しいrun ID、同じagent/session、現在の `PermissionMode` と `PolicyVersion`、入力IDを持つ。すべてのscoped IDは同じprojectに属し、新run IDは直前runと異なる。

### Model request gateとusage

- `RequestId` と `AttemptId` はproject-scoped。`RequestGateIntent` は接続ID、用途、runまたはhost activity subject、stop/deadline制御を持つ。
- 送信前gateは `ModelRequestGatePort::admit` で同意・予算・deadline・停止を検査し、intentを保存してから `Admit` を返す。未実装のgateは `UnsupportedPortFeature { feature: request_gate }` を返し、空の成功で送信を許可しない。
- 終端観測は `ModelRequestObservation` で `PreflightFailed` / `SendStarted` / `Completed` / `Cancelled` / `SendResultUnknown`、sanitized failure、実model ID、usageを持つ。
- usageの欠落は `TokenCount::Unknown` / `TokenUsage::unknown()`。0はproviderが実際に0と報告した場合だけ使う。opaque checkpointを解析してusageを補わない。
- `StopDeadlineControl` はside effect直前に停止・deadlineを確認する。未実装のcontrol portは `UnsupportedPortFeature { feature: stop_deadline_control }` を返す。

### 接続能力

- `ConnectionCapabilities` はconnection ID、provider、認証方式、endpoint class、入力能力、用途を持ち、credential materialを含まない。
- `ConnectionUsage::AgentExecution` はagent実行と判定の両方に使える。`ConnectionUsage::AssessmentOnly` はagent実行へ渡せない。
- TypeSafe/Jev System Oneは `Provider::TypeSafe` + API key + `EndpointClass::TypeSafeSystemOne` + `AssessmentOnly`。OpenAI Decisionsは `Provider::OpenAi` + API key + `EndpointClass::OpenAiDecisions` + `AssessmentOnly` で、ChatGPTログインを流用しない。
- 通常のOpenAI・Anthropic・OpenAI互換接続はagent実行connectionとして扱い、判定にも利用できる。

## Task 2で追加した保存境界

### DB schema 4〜6

- `0004_event_subjects`: `events`をrebuildし、`subject_type`（`run` / `host_activity`）とactivity kind/ID列を追加した。run列はnullableになり、host activity eventは架空のagent/session/run IDを持たない。既存schema 3の行はcontract version・ID・sequence・kind・時刻・payloadをそのまま保持し、`project_sequences`の連番空間はrunとhost activityで共有する。既存indexは再作成し、activity用indexを追加する。
- `0005_model_requests`: 要求ID・attempt ID・project・subject・connection・用途・stop/deadline制御・intent時刻・observationを持つ。attempt IDを一意キーとし、同一intentの再記録は既存行を返す。同一attemptの異なるintent、終端結果の上書き、intentなしの観測は拒否する。usageと実model IDは`ModelRequestObservation`のJSONとして保存し、unknownを0へ変換しない。
- `0006_supervised_state`: project + keyごとのrevision付きstate row。`None`は作成、`Some(revision)`は比較更新を表し、stale revisionは状態もeventも書かずに拒否する。
- 各書込みは`TransactionBehavior::Immediate`の単一transactionで行い、commit後の`CommitReceipt`だけを返す。receiptのeventは別connectionからも確認できる。読み取りはSQLのみで、engine送信・実行・再開を行わない。
- migrationはschema 3からのみ昇順に適用する。途中のfaultはtransaction全体をrollbackし、旧schema version・旧events表・既存行を保持する。未知の新しいschemaはwrite前に拒否し、古いtargetによるdowngradeも拒否する。設定されたapp-data配下のDB以外は開かない。

### host-state format

- 読込みはformat 1・2・3。新規書込みはformat 3のみ。format 1がformat 2の`connections`/`shutdown`を持つ場合、またはformat 1・2がformat 3の`inputs`/`continuationOf`を持つ場合は拒否し、未知formatと未知fieldは解釈しない。
- format 2の全record（projects・agents・runs・approvals・connections・shutdown）をformat 3へ移行してもJSON値は保持される。format 3はrunごとの入力受理recordと、継続元runの`continuationOf`を持つ。将来のformat 3固有fieldも古いformatで明示的に拒否する。

## Task 3で追加した継続・入力対応・復旧gate

### 入力IDの対応

- `Runtime::submit_input` は既存の署名を維持し、`submit_input_with_id` が `InputId` を返す。受理recordはengine送信前にhost-stateへ保存し、`run.input_submitted` は受理phaseだけを記録する（入力本文は保存しない）。
- engineの`StateChanged(Running)`が最初の`Accepted`入力を`Started`へ進め、`StateChanged(Idle)`は`Started`の入力だけを`Completed`へ進める。run作成直後のstartup idleや、まだ開始していない`Accepted`入力は完結しない。
- 送信失敗は`run.input_failed`と`run.state_changed`で入力を`Failed`、runを`interrupted`にし、自動再試行しない。`Runtime::input_progress` と `ContinuationPort::input_progress` は同じ保存recordを返す。
- 復旧後のrunは状態だけを戻し、以前の入力本文を再送しない。

### 会話を保つ追加run

- `EnginePort::start_continuation(start, previous)` は新しいrun IDで同じagent/sessionの会話・system promptを引き継ぐ。`check_continuation` はrunやcheckpointを書く前の副作用なし検査で、missing/latestでないcheckpoint、pending invocation、未完了入力、managed process、scope不一致を明示的な `NotContinuable` で拒否する。
- `Runtime::continue_run(project, previous, text)` は直前runが`idle`で、そのrunの未解決操作・承認・managed processがない場合だけ新runを作る。新run recordと`InputId`受理を永続化してからengineを開始し、その後に入力本文を送る。`run.started` は`continuationOf`を持ち、新runの全tool・event・checkpointは新run IDへ属する。
- `ContinuationPort::continue_run` は新runの開始までを担い、入力本文は `Runtime::send_accepted_input` で渡す。hostの `Runtime::continue_run` は両方を一度に行う。古い承認は新runへ複製せず、直前入力も再送しない。

### 復旧gate

- `Runtime::resume_run` は同一processのrunと再起動後のrunを `RecoveryMode` で区別し、`run.resumed` payloadへ`same_process`/`restored`を記録する。どちらも未解決操作・pending approval・現接続/許可・checkpointの一致を先に検査する。
- `EnginePort::check_resume` はrunを`running`にする前の副作用なし検査。live sessionはconfirmed stop（`running`/`awaiting_approval`でない）で、未完了invocationやmanaged processがなければ再利用する。別processはcheckpointを再構築するが、pending invocation、disposed、latestでないcheckpointは `NotResumable` として拒否し、model要求・tool実行・入力再送を行わない。
- restoreだけではengineを開始せず、model要求0・tool実行0を維持する。

### Task 3のテスト

`tests/runtime/tests/engine.rs` は実Pi＋loopback modelで次を確認する。

- 前runの会話にしかない事実を2回目の要求が参照できる。新runのcheckpoint envelopeとtool intent eventは新run IDを持つ。
- missing checkpoint、未完了入力、pending invocationを持つcheckpointの継続は `NotContinuable` で拒否され、要求0。
- 同一processのconfirmed stop後はlive sessionを再利用し、復旧state eventを二重にpublishedしない。別processはcheckpointから再構築し、どちらも要求0で、未完了応答を新入力として再送しない。
- pending invocationを持つcheckpointの再開は `NotResumable` で、要求0・checkpoint保持。
- host runtime＋実Pi経路でも `InputId` がaccepted→started→completedとなり、startup idleが完結にならず、継続後も会話が保持される。

`tests/runtime/tests/host.rs` はfake engineでhost側の受理・開始・完結、送信失敗、継続のrun/checkpoint/input対応、running・未解決操作・managed processの拒否、`same_process`/`restored`の復旧gateと`NotResumable`拒否を確認する。


## テストコマンド

Task 1の受入で実行するコマンド:

```sh
cargo test -p herness-core --locked
cargo check --workspace --locked
```

Task 2の受入で実行するコマンド:

```sh
cargo test -p herness-store --locked
cargo test -p herness-runtime-tests --test store --locked
cargo check --workspace --locked
```

Task 3の受入で実行するコマンド:

```sh
cargo test -p herness-runtime-tests --test engine --locked
cargo test -p herness-runtime-tests --test host --locked
cargo check --workspace --all-targets --locked
```

`tests/runtime/tests/store.rs`は次を確認する。

- schema 3のv1 event fixture（contract version 1と2、ID、sequence、operation ID、kind、時刻、payload、件数）をmigration後もSQL値と`Event::from_v1`の両方で保持する。checkpoint、operation、host-state row、`project_sequences`も保持し、migration後の新eventは続きのsequenceを使う。
- host activity eventをrun eventと同じproject sequenceへ保存し、SQL上でagent/session/run列がNULL、activity kind/IDだけが入ることを確認する。別connectionのreplayと再open後の追記も確認する。
- schema 4のevents rebuild途中（statement 1と4）とschema 5のfaultで、schema 3・旧columns・旧rows・indexがrollbackされ、その後の正常openで移行できることを確認する。
- 新しいschemaを古いtargetで開くdowngradeが拒否され、既存rowが残ることを確認する。
- supervised stateの作成・更新・stale revision拒否・cross-project event拒否と、commit後に別connectionからstate/eventが見えることを確認する。
- request intentの冪等再記録、同一attemptのconflict、send-started→terminalの遷移、terminal上書き拒否、intentなし観測拒否、unknown usageとknown zeroの区別、実model ID、host activity subjectを確認する。
- host-state format 1/2→3で全recordが保持され、format 1の不正fieldと未知formatが拒否されることを確認する。

追加の確認:

```sh
cargo check --workspace --all-targets --locked
cargo test -p herness-runtime-tests --test contract_smoke --locked
cargo test -p herness-runtime-tests --test host --locked
cargo test -p herness-runtime-tests --test desktop --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

- `cargo test -p herness-core --locked` の `tests/contracts.rs` は、version 2 round-trip、version 1互換decodeと旧envelopeへのround-trip、未知version拒否、subject混在拒否、run/activity subjectのproject束縛、operation IDの所属、`RunState::Idle` と入力完結の区別、usage欠落がunknownであること、assessment-only接続のagent実行拒否を確認する。
- `tests/ports.rs` は、`ModelRequestGatePort`・`ContinuationPort`・`StopDeadlinePort` の未実装defaultが明示的な `UnsupportedPortFeature` を返し、run checkpointがhost activity eventを明示的に拒否することを確認する。
- 既存のH1 v1 history fixture・store migration・runtime回帰は削除せず、version 2が既知の読込み版になったことに合わせて期待値だけを更新する。
- 実credential・実Keychain・実provider・実Tauriは使わない。これらは後続Taskの別途許可された検証まで未確認とする。
