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

## Task 4で追加したgrant・評価器・停止制御の引継ぎ

### hostが確定したrun permission context

- `EngineStart::with_permission` はhostが解決した `RunPermissionContext` をstartと継続へ渡す。contextはrunの `GrantScope`（実際に保存したgrant）、現在policyの `SharedPolicy`、hostが選んだ `SharedPermissionEvaluator`、runの `RunControl` を持つ。
- `EnginePort::set_run_permission` はresume前に同じcontextをインストールする。未実装のengineは `UnsupportedPortFeature { feature: run_permission }` を返し、広いgrantへfallbackしない。
- Pi adapterのtool経路はcontextが無い場合に認可を拒否する。`GrantScope::for_run` を内部で再構成せず、`None` 評価器へfallbackしない。
- 許可の順序はH1のまま（schema → 保護境界 → 明示deny → grant上限 → 明示ask → mode/評価器）。自動モードでも明示deny・askは評価器より先に処理する。
- 評価は `BoundedPermissionEvaluator` がworker threadで実行し、runのdeadlineまたは既定60秒の早い方とstop要求で待機を打ち切る。timeout・停止・評価不能・busyは人間待ちとなり、実行しない。遅れて届いたallowは破棄する。
- 副作用直前にpolicy version/mode、grantのproject・version・mode・対象、最終引数（gatewayのbinding）、stop・deadlineを再確認する。評価中のpolicy変更、引数変更、停止、deadline、古い判断ではexecutorを呼ばない。
- `RuntimeDependencies::with_evaluator` は既存APIを維持し、内部で `SharedPermissionEvaluator` に包む。`with_shared_evaluator` で既に共有された同一instanceを注入できる。host runtimeとPi adapterは同じevaluator・同じpolicy handleを使う。
- adapterが実行権限を持つ場合、hostは `ToolCall` frameを観測だけにし、同じ操作を実行しない。adapterがaskとして報告した操作だけがhostの承認recordになり、人間の承認後に一度だけ実行される。

### Task 4のテスト

`tests/runtime/tests/engine.rs` は実Pi＋loopback modelとbounded mock evaluatorで次を確認する。

- 許可されたbashの副作用が1回だけ実行され、hostのexecutor呼出しは0回。`ToolCall` frameの二重実行がない。
- 子agentのgrant外へのwriteは0回、grant内は1回。継続runとresume後も同じgrantが使われる。
- 自動モードではhostの共有evaluatorが1回呼ばれ、modelが書いたrationaleは評価のauthority fieldに入らない。
- 明示denyは評価器0回で実行0、明示askは評価器0回で人間待ちになり実行0。modelの指示文は優先順位を変えない。
- 評価器unavailable、評価中の停止、deadline到達、評価中のpolicy変更、遅延したallowはすべてexecutor 0回。
- host grantが無いstartは広いgrantへfallbackせず、toolを拒否する。

`tests/runtime/tests/permissions.rs` はin-memoryで `BoundedPermissionEvaluator` のdeadline・stop・busy時の打切り、評価中のpolicy変更でallowがstaleになること、自動モードでもgrant上限が評価器より先に効くこと、明示deny/askがmodel指示で迂回されないことを確認する。

## Task 5で追加したモデル要求gateとhost pump

### 全モデル要求のgate

- `PiEngine` は `ModelRequestGatePort` を注入できる。既定は同じstoreを使う `StoreModelRequestGate` で、SDKのtool往復後の次要求を含む各 `StreamFn` 呼出しが新しい `RequestId`/`AttemptId` を持つ `RequestGateIntent` を作る。
- 送信前に adapter 自身も `RunControl` の停止・deadlineを確認し、次に gate の `admit` を呼ぶ。`Admit` 以外、gate error、intent保存失敗、停止、deadlineでは `pi_ai::stream` を呼ばない。`max_retries = 0` を維持し、隠れた再試行を追加しない。
- intent保存後、credential解決前に `SendStarted` を保存する。`SendStarted` の保存に失敗した場合もHTTPを開始しない。
- 終端では `Done` を `Completed`、停止・取消しを `Cancelled`、provider errorや途中終了を `SendResultUnknown` として保存する。実model IDはproviderが返した `response_model` を優先し、なければrequest modelを使う。
- usageは `on_provider_stream_event` で生のprovider eventのusage fieldを観測し、providerが実際に報告したfieldだけ `Known` とする。未報告のfieldは `Unknown` で、0へ変換しない。`PreflightFailed` と `Cancelled`/`SendResultUnknown` はusageを主張しない。
- request rowにはrequest/attempt ID、project、runまたはhost activity subject、connection、用途、停止・deadline snapshot、observationだけを保存する。SDK JSON、prompt、credential、provider bodyは保存・公開しない。

### host所有のpump

- `Runtime::pump` は全projectの全runのengine eventをdrainしてcommitし、active runのdeadlineを確認する。deadline到達時は既存の `Runtime::stop_run`（`StopReason::Policy`）でH1の協調停止を行い、`run.stopped` を記録する。rollbackや自動再試行はしない。
- `shutting_down` 中のpumpは `PumpReport::is_skipped()` を返し、何もしない。quitの停止・猶予・保存経路は既存のまま。
- `DesktopHost::pump` は同じruntimeを呼ぶ。`src-tauri` は `AppState` の単一hostを25ms間隔でpumpするhost-owned threadを起動し、windowや選択中projectに依存しない。新しいstore・engine・executorは作らない。
- `poll_project` はsnapshotを返すだけで `poll_run` を呼ばない。`events` fieldは既存UI形のために残すが常に空で、committed eventは `history` から読む。

### Task 5のテスト

`tests/runtime/tests/engine.rs` は実Pi＋loopback modelで次を確認する。

- gate拒否、`SendStarted` 保存失敗、停止済みcontrol、期限到達controlのいずれもprovider HTTP 0。
- tool往復を含む2要求が別々のrequest/attempt IDで保存され、各attemptにterminal observationが1つだけある。
- providerがusageを報告した場合はinput/output/cache read/writeの既知値とmodel IDが保存され、未報告のusageは `Unknown` のままで0にならない。
- provider 500ではHTTP 1回・attempt 1件で、SDKの隠れた再試行がない。

`tests/runtime/tests/desktop.rs` は実SQLite＋実Pi＋loopbackで次を確認する。

- UI pollも `poll_run` も使わず、`DesktopHost::pump` だけでhidden runと非選択projectのrunが `run.text_completed` まで進み、再表示用snapshot/historyが最新sequenceを返す。
- 長い単発要求のdeadline到達でpumpがrunを停止し、`run.stopped` を記録し、HTTP 1回のまま再試行しない。

## Task 6で追加した監督契約・承認・profile・送信同意

### crate境界

- `crates/herness-supervision` は `herness-core` とworkspace共通のserde/uuid/sha2だけに依存する。store・engine-pi・assessment・Tauri・SQLite・実HTTPへ依存せず、I/Oも行わない。契約・検証・portだけを持つ。
- `tests/supervision` はworkspace member `herness-supervision-tests` として登録し、`src/lib.rs` に合成fixture（project/condition/evidence/profile/consent、in-memoryの `SupervisionStorePort`）を置く。fixtureはsecret・実provider body・実会話を含まない。
- 新規の公開監督契約はversion 2を書き、`SupervisionContract` と `SupervisionRecord` は `ContractVersion` を持つ。version 1の監督recordは存在せず、推測しない。H1のrun状態は変更しない。

### 完了契約と承認

- `SupervisionContract` はproject・agent/session・opaque owner参照・condition版・実行scope・必須check・条件別rubric・証拠target scope・固定profile版・固定同意版・有限budget・run groupを持つ。IDはproject-scopedで、`SupervisionScopedId` が別project参照を拒否する。
- `ConditionSet` はversionと内容digestを持ち、`ConditionApproval` はproject・version・digestへ束縛する。承認basisは「人間の明示確認」と「H3承認済み設定/H4承認済みplanからの継承」を別variantで表す。
- model actorは条件・profile・budget・実行scope・同意を承認/変更できない。model提案条件は人間または承認済みownerの確認までunapprovedである。fake/foreign/expired/stale digest/owner-source不一致の承認は拒否する。H3/H4 ownerの変更actorはsubject ownerと一致しなければならない。
- condition version変更は現在の判定を `invalidatedDecisions` へ移し、completionを消し、`waiting_human` と `conditionsChanged` 理由にする。旧versionのassessmentは適用せずhistoryだけに残す。target/profile/consent変更も同じ規則で失効する。
- `SupervisionRecord` はready/running/verifying/assessing/waiting_human/stopped/failed/cancelled/completed、理由、未達条件、現在のrequired checks、run groupを持つ。stopped・waiting_human・limit・unrecoverable・cancelledと未達条件はcompletionより優先し、completion snapshotのversion・profile・同意・必須checkが一致しない場合は完了できない。

### 用途別profile

- `AssessmentProfile` はpurpose（completion/html/permission）、provider kind（通常LLM/Jev/Decisions）、connection、model、adapter版、rubric版、必要入力（text/image/structured output）、thresholdsを持つ。profile versionは監督開始時に `ProfileBinding` として固定する。
- H2既定値はcompletion met/unmet 0.95、permission allow/deny 0.99、分布sum誤差0.001。通常LLMには確率thresholdを捏造せず、provider-native confidenceは `NativeConfidence` として確率と別に保持する。これらは安全・正答率の保証ではなく、評価前の保守的な初期値である。
- `ProfileCatalog` はpurposeごとの完全一致だけを解決する。未設定は `Unset`、connection unavailable/login required、text/image/structured output不足、provider-kindとendpoint classの不一致は利用不可であり、実行model・別provider・別purpose・別versionへfallbackしない。
- Decision分布は有限・0〜1・選択肢完全一致・sumが1から0.001以内を要求し、無断で補正しない。completionのmet/unmet、permissionのallow/denyは閾値未満なら採用しない。insufficient・ask・uncertain・low confidenceは完了/実行の根拠にしない。

### 送信同意

- `DisclosureConsent` はproject・provider origin（scheme/host/port）・purpose・data種別（text/code/diff/log/image）・target-scope版へ束縛する。初回grantは人間だけが行い、同じscopeの継続は再確認なしで許可される。
- revoke、別origin、別purpose、target版変更、data種別の追加、画像追加は未送信要求を止め、新しい人間確認を要求する。空scope・wildcard・repository rootは無効で、全会話・全repositoryの既定送信は存在しない。
- `ProviderOrigin` はpath/query/fragment/userinfo/credentialを受け付けず、consent recordにsecretを含めない。

### 証拠・assessment・budget・冪等要求

- `EvidenceRecord` はID、取得者（child/CI/human）、正確なcommand/equivalent operation、実結果（exit/signal/timeout/truncation）、target版とcontent fingerprint、scope/limits、sequenceを持つ。必須check結果はpass/fail/not_run/unavailable/inconclusiveを区別し、exit 0やH1 operation成功をpassへ変換しない。passにはevidence IDが必要である。
- `AssessmentRequest`/`AssessmentResult` は条件ごとのquestion・rubric・evidence ID・met/unmet/insufficient・短いrationale/uncertainty・provider/model/adapter/rubric版を持つ。resultはrequestに含まれないevidence IDを参照できない。
- `BudgetPolicy::h2_default()` はcumulative active 7,200秒・追加30 run（初回込み最大31）・金額上限なし。金額上限は有限USDと `PriceVersion` を必須とし、見積りなし・上限超過は送信不可。人間待ち・明示pause・アプリ停止はactive timeに計上せず、再開で消費量を戻さない。Task 9がledgerを実装する。
- `SupervisionRequest` はstart/stop/reassess/resume/changeのhost-owned request IDを持ち、`execute_command` は同じIDの再送に記録済みresultを返し、mutationを再実行しない。store portはCASとresult記録の原子的境界を提供する。
- portは `ClockPort`・`EvidenceStorePort`・`AssessmentPort`・`SupervisionStorePort`。このTaskでは具体I/Oを実装しない。

### Task 6のテスト

`tests/supervision/tests/contracts.rs`:

- fake/foreign/expired/stale-digest/source-owner-mismatch承認の拒否と、人間承認とH4継承承認の区別。
- modelによる条件・profile・budget・scope・同意の承認/変更拒否、model提案条件の人間確認。
- 別projectのsubject/run group/request/evidence/condition参照の拒否。
- condition version変更でapplied decisionがhistoryへ移り、completionが消え、旧assessmentが適用されないこと。
- 同意取消し・別origin・別purpose・scope追加・画像追加・target版変更・空/unbounded scopeの拒否と再確認要求。
- 同一request IDの再送が同じresultを返し、store mutationとCASが1回だけであること。同じIDの別commandを拒否すること。
- 7,200秒/30/31 run、有限金額とprice version、見積り不足、人間待ち除外、評価timeoutの短い方。
- pass/fail/not_run/unavailable/inconclusiveの区別、exit 0のinconclusiveがpassでないこと、passにevidenceが必要なこと。
- stopped/waiting/limit/unrecoverable/cancelledと未達条件がcompletionに優先すること、必須check欠落を拒否すること。
- state/reasonの一致、record/contractのJSON round-trip、contract version 2。

`tests/supervision/tests/profiles.rs`:

- H2 threshold初期値、通常LLMに確率thresholdがないこと、未設定profileがunusableでfallbackしないこと。
- text-only connectionへのimage要求、login required、structured output不足、provider-kind/endpoint不一致のunusable。
- native confidenceが確率でないこと、uncertainが完了を支持しないこと。
- Decision分布の有限性・範囲・sum誤差・0.95採用、permission 0.99とask、低確率・uncertainが実行を支持しないこと。
- 固定profile versionと異なるversionのunusable、project外profileの拒否、Jev/Decisions接続の一致。


## Task 7で追加した判定接続能力とtoolなしtransport

### 接続能力の登録

- `ConnectionSettings` は任意の非secret `ConnectionCapabilityDeclaration`（`endpointClass` と `input`）を保持する。宣言がない既存設定はH1のprovider既定（OpenAI Responses / Anthropic Messages / OpenAI互換completions、textのみ、agent実行可）として読む。未知のendpoint class・未知fieldは推測せず拒否する。
- 宣言は `ConnectionSettings::new_with_capabilities` または `with_capabilities` で付ける。usageはendpoint classから導出し、宣言でagent実行とassessment専用を矛盾させられない。
- TypeSafeは常に `TypeSafeSystemOne` + `AssessmentOnly`。OpenAI Decisionsは `Provider::OpenAi` + API key + `OpenAiDecisions` + `AssessmentOnly` で、ChatGPTログインを拒否する。TypeSafe/Decisionsにcustom/foreign endpointは付けられず、custom endpointは従来どおりOpenAI互換だけが持てる。
- `ConnectionDirectory::capabilities` / `list_capabilities` が有効な `ConnectionCapabilities` を返し、`agent_execution_capabilities` はassessment専用接続を `AgentExecutionNotAllowed` で拒否する。`herness-engine-pi` のagent model構築も同じcapabilityを検査し、Jev/Decisionsへagent要求を送らない。
- 新しい設定を登録・更新する既存H1経路は変更しない。接続を別provider/model/originへ暗黙に付け替える処理はない。

### herness-assessment transport

- `crates/herness-assessment` は `herness-core` の `ConnectionDirectory` と `CredentialPort` だけを再利用し、store・budget・Tauri・provider固有wire schemaを持たない。Jev/Decisionsのbody schemaと通常LLM adapterはTask 10〜12が所有する。
- `AssessmentRequest` のbodyはtoolを含まないJSON objectに限る。top-level `tools` / `tool_choice` とexternal image参照（`image_url`等）は送信前に明示エラーにし、黙って削除しない。transport自身もtoolを追加しない。
- `TransportControl` のtimeoutは60秒と残りrun deadlineの短い方。`CancelToken` の取消しはin-flight要求とretry待機を打ち切り、再送しない。
- credentialは各attemptの送信直前に既存 `CredentialPort` から解決し、設定されたexact originへだけ付ける。redirectは一切followせず、H1の `redirect_auth_decision` でcross-originを分類する。cross-origin redirect・credential付きURL・external image URLはエラー。
- retryは429、transient 5xx（500/502/503/504）、送信前のconnection failureだけ。同一connectionで最大2回追加し、既定待機は1秒・2秒＋最大250ms jitter。`Retry-After` は残りdeadlineに収まる場合だけ使い、収まらなければ `RetryAfterBeyondDeadline` で止める。timeout/送信不明、認証失敗、invalid response、redirect、拒否・低確度の成功応答は再送しない。provider/model/connection fallbackはない。
- 必要text/image modalityは送信前に `ConnectionCapabilities` と照合する。画像は `ImageInput` のcaller-provided bytesだけで、URLはfetchも送信もしない。
- `AssessmentError` はHTTP status・attempt数・retry分類だけを持ち、secret・Authorization・request body・raw provider bodyを含まない。`AssessmentRequest` / `AssessmentResponse` のDebugもbodyを表示しない。
- transportは金額予約・cost/billing記録・永続化を行わない。usage/model metadataはadapterが返却bodyから解釈し、予約と記録は上位H2 request gate / Task 9 ledgerが所有する。

### Task 7のテスト

`tests/supervision/tests/adapters.rs` はloopback HTTP mockとin-memory credentialだけで次を確認する。

- assessment専用のTypeSafe/Decisions接続がagent実行に使えないこと、ChatGPTログインのDecisionsとcustom/foreign originの拒否、capability/inputの登録。
- toolを含まないbody（`tools`/`tool_choice`なし）、60秒capと短い残りdeadline、in-flight取消しで再送0、429のRetry-After、transient 5xxの最大2回retryと枯渇、auth failure / invalid responseの再送0、送信不明timeoutのretry 0、送信前connection failureのretry。
- cross-origin redirectがAuthorizationを受け取らないこと、secret canaryがerror/Debugに出ないこと、image URL拒否と対応接続でのimage bytes受理、同一connectionだけのretry、金額/cost記録を作らないこと。

`tests/runtime/tests/connections.rs` は既存H1回帰に加え、legacy settingsの互換decode、宣言付き設定のround-trip、未知capability formの拒否、directory経由の能力公開とagent実行拒否を確認する。実provider・実Keychain・実Jev/Decisions接続はこのTaskでは未確認とする。

## Task 8で追加した証拠の鮮度と永続化

### target manifestと鮮度

- `TargetManifest` はproject・target version・HEAD（分かる場合）・owner指定のread-set・入力の内容指紋を持つ。入力は `InputOrigin` でtracked/uncommitted/untracked/external/dependency/settingsを区別するが、適用判定はmtimeやHEADでなくSHA-256の内容指紋で行う。依存・設定入力はread-setに宣言されていなくてもmanifestへ含める。
- `manifestDigest` はHEAD・coverage・read-set・内容指紋を正規化してハッシュする。同じHEADでもfile内容が変わればmanifestとfingerprintが変わる。HEADだけの変更やoriginの変更は内容が同じなら証拠の適用性を失わせない。
- `FreshnessService` はworkspace readerとclockを注入され、file I/O・時計取得を自身では行わない。`TargetReadSet::Declared` は宣言pathとdependency/settingsを、`TargetReadSet::WholeProject` はproject全体の入力manifestを採取する。範囲不明は `TargetManifest::unknown` または `widen` で全体manifestへ広げ、判定不能をpassへ読み替えない。
- 証拠の適用性は、その証拠のread-setとfingerprintだけを現在manifestと比較する。関連pathが変わった証拠だけ `Invalidated`、無関係な変更では `Applies`、coverage不足は `UnknownScope` になる。`evaluate` は証拠ごとの結果を返し、storeにある他の証拠を巻き込まない。

### H1権限を通じた検証

- `VerificationService::verify` は検証前にmanifestを採取し、`VerificationBoundary` にH1の評価と実行を委ねる。`GatewayVerification` は実 `PermissionService` を持つ `ToolGateway` を包み、`Allow` のときだけsingle-use authorizationを確認してfake/実executorを呼ぶ。`Deny`・`AwaitingHuman`・boundary failureではexecutorを呼ばず、証拠も保存しない。
- 検証後にもmanifestを採取する。実行中に関連内容が変わった場合、executorがpassを報告してもstatusを `Inconclusive` へ落とし、passとして保存しない。保存するevidence targetは検証開始時のmanifestである。
- 正確なcommandはfrozen `Bash` operationのcommandと完全一致しなければならず、shell以外のread等はequivalent operationとして記録する。
- `validate_evidence_record` は保存前に、acquirer・正確な操作・実結果（exit/signal/timeout/truncation）・target版とfingerprint・scopeを検査する。commandで結果がない証拠、passなのにexit 0以外・signal・timeout・truncationがある証拠、`DONE`/`success`だけの文言、`OperationOutcome::Applied` だけでcheck結果がない証拠を拒否する。human証拠はobserverを必須とする。子agent・CI・人間の再利用も同じ検証を通す。
- 完了後の関連変更は `CompletionFreshness::Stale` を返し、`StaleCompletionReport::apply` が `SupervisionRecord::completion_stale` を設定する。recordは `completed` のまま、completion snapshotと履歴も保持し、run groupを増やさず、自動再開しない。範囲不明は `Inconclusive` としてstaleとも完了とも主張しない。

### Store schema 7と原子的な保存

- migration `0007_supervision_evidence` を追加し、`supervision_records`（project + supervisionごとのrevision付きpayload）、`evidence_records`（project + evidence ID、supervision内sequenceは一意）、`supervision_command_results`（request IDごとの結果payload）を持つ。0001〜0006は変更しない。
- `EvidenceStorePort` と `SupervisionStorePort` を `herness-store::Store` が実装する。evidence appendは同じIDの同一値を冪等に返し、異なる値はconflictにする。supervision CASはstale revisionを状態もeventも書かずに拒否する。command resultは同じrequest IDの同一結果を返し、異なる結果は `DuplicateResultConflict` にする。project外のID・recordは読み書き前に拒否する。
- `SupervisionStorePort::commit_command` を追加した。既定実装は従来のCAS + result記録だが、storeは1つのimmediate transactionでrecordとcommand resultをまとめて書き、fault時は両方rollbackする。`execute_command` はこの境界を使うため、crashで新revisionだけが残る半端なstateにならない。
- 保存payloadはsupervision/evidence/commandのJSONだけで、credential・provider body・raw request contentを含めない。

### Task 8のテスト

`tests/supervision/tests/evidence.rs`:

- pass/fail/not_run/unavailable/inconclusiveの区別、非zero exit・signal・timeout・truncationがpassにならないこと、command結果なし・`OperationOutcome::Applied` だけ・`DONE`/`success`だけの拒否。
- 同じHEADで内容が変わるmanifest/fingerprintの変化と関連証拠の失効、uncommitted/untracked/external/dependency/settings入力の包含、無関係変更の保持と影響証拠だけの失効。
- 検証中・検証後・評価中の変更検出、範囲不明のinconclusive、完了後のstale snapshot（completedのまま・run追加なし・自動再開なし）。
- 実 `PermissionService` + fake executorでallowがpass証拠を保存し、deny/askがexecutor 0回・証拠0件になること。child/CI/human証拠の再利用とhuman observer必須。
- 実SQLiteでCAS conflict、duplicate requestの同一結果、異なるcommand resultの拒否、faultによるstate/evidence/command resultのrollback、cross-project拒否、reopen後のevidence/supervision/command result読み取り。

## Task 9で追加した予算台帳

### 契約と台帳

- `BudgetLedgerRecord` は1監督対象のpolicy snapshot/version、`BudgetUsage`、clock state（Active/WaitingHuman/Paused/AppStopped）、open interval（wallとmonotonicの開始値）、run予約、money予約、未確定chargeを1つのJSON payloadとして持つ。`BudgetLedger` はwallとmonotonicを`BudgetClockPort`で、永続化を`BudgetStorePort`で注入され、自身ではI/O・時計取得をしない。
- Activeだけが稼働時間へ加算される。実行・検証・assessment・許可評価・retry待機は同じActive区間として扱い、人間待ち・明示pause・アプリ停止の時間は加算しない。区間は秒未満を切り上げ、7,199/7,200/7,201秒の境界をそのまま記録する。
- 再open時、Activeのまま残った区間はmonotonic差分とwall差分の大きい方で再開時刻まで保守的に計上する。monotonicがprocess再起動で戻ってもwall差分を使う。消費量は再開でリセットしない。
- `reserve_run` はrun数を予約し、`start_run` は予約を消費（予約がなければ直接消費）する。初回を含む最大31で、32回目は`BudgetLimitReached { RunCount }`。同じ`BudgetRequestId`の再予約・再startは同じ結果を返し、二重消費しない。start意図の保存に失敗した場合は消費0で、再open後も消費済みrunは戻らない。
- `reserve_money` はmoney capがある場合だけ使う。見積り・価格版を送信前に要求し、価格版不一致・見積り欠落・ChatGPTログイン（金額見積不能）は`BudgetPriceUnavailable`で拒否する。予約は`Reserved`→`Settled`（最低でも予約額、actualが上ならactual）/`Unresolved`/`Released`へ遷移する。usage欠落・`SendResultUnknown`・`Cancelled`は`Unresolved`のまま予約を保持し、capへの計上を続ける。`PreflightFailed`だけが`Released`になる。
- 同じattemptの同一予約は冪等。settled/released後の再予約は`BudgetReservationConflict`。全model要求（agent実行・検証/assessment・許可評価）は同じledgerの同じcapを共有する。

### 原子的なstore境界

- migration `0008_budget_ledger` を追加し、`budget_ledgers`（project + supervisionごとのrevision付きpayload）と`budget_reservations`（attempt、request、estimate、price version、state、settled額）を持つ。0001〜0007は変更しない。`LATEST_SCHEMA_VERSION`は8。
- `BudgetStorePort` は`load_budget`、`compare_and_swap_budget`、`commit_budget_admission`、`commit_budget_observation`を持つ。`herness-store::Store` は`commit_budget_admission` でbudget record・reservation・`model_requests` intentを1つのimmediate transactionへ書き、`commit_budget_observation` でobservationとsettlementを同じtransactionへ書く。faultは両方をrollbackし、admission前に失敗した場合はrequest intentも予約も残らない。
- `BudgetLedger` はCAS競合を最大4回までreloadして再評価する。競合中に他のwriterが予約を増やした場合、再評価後のcap判定で拒否するか、収まる場合だけ書き込む。run/moneyの上限判定は書き込みと同じtransactionのrevision CASで保護される。
- `BudgetRequestGate` は既存`ModelRequestGatePort`へそのまま取り付けられる。stop/deadlineはledgerへ触れる前に`Stopped`/`DeadlineReached`で拒否し、予算・price・persist失敗は`Admit`を返さない。observationはusage欠落を0にせず、未確定予約を保持する。

### Task 9のテスト

`tests/supervision/tests/budget.rs`:

- 7,199/7,200/7,201秒の境界、人間待ち・pause・アプリ停止の除外、retry待機の加算、assessment timeoutのmin(60s, 残り)。
- 初回+追加30回=31回の許可、32回目の拒否、予約→start、重複start、再open後の消費維持。
- 2つのledgerによるmoney/run capの同時予約拒否、CAS競合後の再評価（cap超過は拒否、収まる場合は成功）。
- 見積り欠落・価格版不一致・ChatGPTログインの拒否、4用途のmoney予約が同じcapを共有すること。
- usage欠落・送信不明・取消しで予約が残り、完了で最低予約額へsettleし、preflight失敗だけがreleaseされること。重複observationで二重課金しないこと。
- 実SQLiteのpersist faultでintent・record・reservationが残らず、fault解除後の再試行と再openで予約・intentが読めること。run startのfaultで消費0。
- crashでopen intervalが残る場合のwall差分による保守的計上と、その後のadmission拒否。schema 8 migration faultのrollback。



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

Task 4の受入で実行するコマンド:

```sh
cargo test -p herness-runtime-tests --test permissions --locked
cargo test -p herness-runtime-tests --test engine --locked
cargo check --workspace --all-targets --locked
```

Task 5の受入で実行するコマンド:

```sh
cargo test -p herness-runtime-tests --test engine --locked
cargo test -p herness-runtime-tests --test desktop --locked
cargo check --workspace --all-targets --locked
```

Task 6の受入で実行するコマンド:

```sh
cargo test -p herness-supervision --locked
cargo test -p herness-supervision-tests --test contracts --locked
cargo test -p herness-supervision-tests --test profiles --locked
cargo check --workspace --all-targets --locked
```

Task 7の受入で実行するコマンド:

```sh
cargo test -p herness-assessment --locked
cargo test -p herness-supervision-tests --test adapters --locked
cargo test -p herness-runtime-tests --test connections --locked
cargo test -p herness-engine-pi --lib --locked
cargo check --workspace --all-targets --locked
```

Task 7の追加確認:

- `cargo test -p herness-assessment --locked` はtimeout cap、retry既定値、tool宣言の拒否、external image参照の拒否、Debugのbody/secret非表示、loopback endpoint制約を確認する。
- `adapters.rs` はloopback mockだけを使い、429/5xx/Retry-After、最大2回retry、送信不明timeoutの再送0、取消し、cross-origin redirectのAuthorization不転送、secret canary、image bytes/URL、同一connection retry、billing非関与を確認する。
- 実Jev/Decisions/OpenAIへの接続成功は主張しない。これらは別途許可された実接続検証まで未確認である。

Task 8の受入で実行するコマンド:

```sh
cargo test -p herness-supervision-tests --test evidence --locked
cargo test -p herness-store --locked
cargo check --workspace --all-targets --locked
```

Task 8の追加確認:

- `cargo test -p herness-supervision-tests --test evidence --locked` は上記の証拠・鮮度・H1境界・SQLite原子性を確認する。
- `cargo test -p herness-store --locked` はschema 7のmigration一覧と既存store単体テストの回帰を確認する。
- `cargo test -p herness-runtime-tests --test store --locked` で既存schema 3→最新migration、v1 history、request/state回帰が維持されることを確認する。

`tests/runtime/tests/store.rs`は次を確認する。

- schema 3のv1 event fixture（contract version 1と2、ID、sequence、operation ID、kind、時刻、payload、件数）をmigration後もSQL値と`Event::from_v1`の両方で保持する。checkpoint、operation、host-state row、`project_sequences`も保持し、migration後の新eventは続きのsequenceを使う。
- host activity eventをrun eventと同じproject sequenceへ保存し、SQL上でagent/session/run列がNULL、activity kind/IDだけが入ることを確認する。別connectionのreplayと再open後の追記も確認する。
- schema 4のevents rebuild途中（statement 1と4）とschema 5のfaultで、schema 3・旧columns・旧rows・indexがrollbackされ、その後の正常openで移行できることを確認する。
- schema 7のmigration途中faultでschema 6のままrollbackされ、正常openでevidence/supervision/command resultの表が作られることを確認する（`tests/supervision/tests/evidence.rs`）。
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

Task 9の受入で実行するコマンド:

```sh
cargo test -p herness-supervision-tests --test budget --locked
cargo test -p herness-store --locked
cargo check --workspace --all-targets --locked
```

Task 9の追加確認:

- `cargo test -p herness-supervision-tests --test budget --locked` はfake clockとfault注入で、稼働境界・31/32 run・再open維持・同時予約とCAS再評価・money capの見積り/価格版/ChatGPT拒否・未確定予約の保持・preflight release・実SQLiteのpersist faultと再openを確認する。
- `cargo test -p herness-store --locked` はschema 8のmigration一覧と既存store単体テストの回帰を確認する。
- `cargo test -p herness-runtime-tests --test store --locked` で既存schema 3→8 migration、v1 history、request/state/supervised-state回帰が維持されることを確認する。
- 金額はローカル見積りであり、providerの請求額を厳密に保証しない。実provider・実credential・実Keychainは未使用のまま未確認とする。
