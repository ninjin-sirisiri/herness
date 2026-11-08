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
- storeのhost activity永続化はTask 2で追加する。Task 1のschema 3 storeでhost activity eventをrun checkpointやoperation resultへ入れようとした場合は、架空のrun IDを作らず `UnsupportedPortFeature { feature: host_activity_events }` または構造化event errorで拒否する。

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

## テストコマンド

Task 1の受入で実行するコマンド:

```sh
cargo test -p herness-core --locked
cargo check --workspace --locked
```

追加の確認:

```sh
cargo check --workspace --all-targets --locked
cargo test -p herness-store --locked
cargo test -p herness-runtime-tests --test contract_smoke --locked
cargo test -p herness-runtime-tests --test store --locked
cargo fmt --all -- --check
```

- `cargo test -p herness-core --locked` の `tests/contracts.rs` は、version 2 round-trip、version 1互換decodeと旧envelopeへのround-trip、未知version拒否、subject混在拒否、run/activity subjectのproject束縛、operation IDの所属、`RunState::Idle` と入力完結の区別、usage欠落がunknownであること、assessment-only接続のagent実行拒否を確認する。
- `tests/ports.rs` は、`ModelRequestGatePort`・`ContinuationPort`・`StopDeadlinePort` の未実装defaultが明示的な `UnsupportedPortFeature` を返し、run checkpointがhost activity eventを明示的に拒否することを確認する。
- 既存のH1 v1 history fixture・store migration・runtime回帰は削除せず、version 2が既知の読込み版になったことに合わせて期待値だけを更新する。
- 実credential・実Keychain・実provider・実Tauriは使わない。これらは後続Taskの別途許可された検証まで未確認とする。
