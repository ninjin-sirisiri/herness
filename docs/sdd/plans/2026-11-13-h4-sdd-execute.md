# H4 Host-owned SDD Execution Implementation Plan

**Goal:** 新形式planの承認から、Taskの直列起動・有限継続・HTML同期確認・host commit・台帳・finish引継ぎまでをhernessが制御する。

**Architecture:** SDD packが新形式schemaとread-only inspector、herness限定の実行連携を所有する。Rustのherness-sdd-executeが承認・順序・Git journal・台帳・復旧を所有し、H1の実行と監査、H2の監督と証拠、H3の同期barrierを利用する。SQLiteとアプリ寿命のdesktop compositionで保存・停止・最小操作を接続する。

**Tech Stack:** Rust 1.97.1 / Cargo workspace、Tauri 2.12.5、既存固定pi-rust、SQLite、Python 3.11+標準ライブラリ、Git、既存macOS WebKit、静的HTML/CSS/JavaScript。

**Spec:** [docs/sdd/specs/2026-11-13-h4-sdd-execute-design.md](../specs/2026-11-13-h4-sdd-execute-design.md)

## Global Constraints

以下はH4 specの原文を引き継ぐ。H1/H2のH4 integration additionsも承認済みの正本として全Taskへ渡す。

- 親モデルのsubagent toolを必要とせず、承認済みplanのTaskを順番に実行する。Taskごとに独立した子を作り、未達の継続はH2により同じ子で行う。
- Global Constraintsの原文、正本specの適用section、先行Taskのinterface・決定・証拠を初回と継続へ引き継ぐ。
- 必須検証、現在のHTML同期、commit結果、永続化が成立しなければ次Taskへ進まない。停止・復旧・plan変更を追跡できるようにする。
- 初期実行範囲は1 planにつき1リポジトリ・1実装checkout。承認された外部文書の読取りを、外部リポジトリへの書込み許可にしない。
- 旧形式の自動変換、Task並列実行、Taskごとのworktree、必須レビューループ、親による実装fallback、自動push・merge・公開、独自のHTML policy、OS sandboxは含めない。
- 完成版UI・配布はH5。H4では承認・開始・停止・再開・状態確認とfinish引継ぎの最小接続を作る。H4自身の開発に既存ホストを使うことは妨げず、初期H4で複数repoのplanを自己実行できるとは主張しない。
- plan取込みはread-onlyのpreviewであり、実装・モデル送信・worktree作成・commitを許可しない。
- 更新操作はproject・execution ID・request ID・expected revisionを必須とし、重複requestは保存結果を返す。同じrequest IDで別内容は拒否し、古いrevisionは副作用前に競合を返す。開始要求の再配送で子やcommitを増やさない。
- planのbytesが変わる、消える、移動する、または観測が不安定になると、新規dispatch・commitを止めて現在のTaskへ安全停止を要求する。JSONが同じでも本文・Global Constraintsの変更を無視しない。同じbytesへ戻しても停止latchは解除しない。
- 子の担当は実装・検証・報告までで、Gitのstage・commit・branch変更・履歴書換えを行わない。hostもpush・pull・merge・rebase・amend・reset・cleanを実行フローへ追加しない。

| 項目 | 初期値・規則 |
| --- | --- |
| plan形式 / inspector / H4公開応答 | version 1。未知版・未知fieldを拒否 |
| plan入力 | 正確なUTF-8 bytesで2 MiBまで。超過を切り捨てない |
| inspector timeout | 30秒。副作用なしで失敗を返す |
| planの定期照合 | 1秒。通知・副作用前照合も併用し、外部raceの完全排除とはしない |
| Task実行の同時数 | アプリ全体で1。H3の自動著作枠は別で、Taskと併進できる |
| Task監督上限 | H2の累積7,200秒・追加run30回・3連続停滞。再開・plan再承認で消費を消さない |
| 同期待ちと検証 | 人間待ち等を除きTaskの稼働時間に含める。H3側のcycle予算はH3自身が管理 |
| check timeout | 明示値と残りTask時間の短い方。未停止・不明な終了をpassにしない |
| host commit timeout | stage・hook・commitを合わせて30秒または残りTask時間の短い方。timeoutは結果照合待ち |
| 金額 / plan全体予算 | 各Taskの金額上限はH2と同じく任意。共有のplan金額・時間予算は追加しない |

## File structure

本planは[ロードマップ](../specs/2026-11-07-herness-roadmap.md)のH4だけを扱う。H4 specと[H1追加契約](../specs/2026-11-07-h1-runtime-design.md#h4-integration-additions)、[H2追加契約](../specs/2026-11-08-h2-supervision-design.md#h4-integration-additions)は2026-11-13に承認済み。以降のH4・H1・H2・H3という略記は、それぞれの正本specを指す。全briefに正本パス・適用section・Global Constraintsを渡し、会話記憶に依存しない。

調査起点はherness `0addc31`、pack `601ebed9c02828373d9851cc01ea45b8c097ac7b`、DB schema 9。実行開始時には両repoのHEAD・statusを再確認する。本plan自体は既存ホストでH4を開発する従来形式のplanであり、未実装H4の入力ではない。新形式の機械実行fixtureはTask 1で別途作る。製品の1 plan＝1 repoという制限を、この開発planを使って緩めない。

Global Constraintsは開発対象hernessの動作を定める。開発時の既存ホストは通常のsdd-executeに従ってTaskをdispatchし、実装者は対象repoへTask単位のcommitを行う。製品内の子にGitを担当させない制約と混同しない。Target Markdownを編集したらHTMLを別操作で著作し、共通検証してからcommitする。

```text
SDD_PACK_ROOT/                         # 現在 /Users/h-uma/Documents/sdd
  scripts/plan-inspect
  scripts/sddlib/plan_schema.py / plan_inspect.py
  adapters/herness/                    # H3と独立した実行capability
  skills/sdd-plan/ / sdd-execute/ / sdd-finish/
  tests/test_execution_plan.py / test_plan_inspect.py
  tests/test_herness_execution.py / fixtures/
  README.md / docs/sdd/specs/
herness/
  crates/herness-sdd-execute/src/       # contract、ports、import、approval、
                                       # packet、coordinator、barrier、git、
                                       # ledger、plan_changes、recovery
  crates/herness-core/src/             # host Git権限・監査・process/停止
  crates/herness-supervision/src/      # owner作成、check、readiness、pump
  crates/herness-store/migrations/0010_sdd_execute.sql
  src-tauri/src/sdd_execute/           # composition、pack/Git/workspace bridge
  src-tauri/src/supervision/ / html_sync/ / lifecycle/
  src-tauri/src/commands.rs / host.rs / app.rs
  src-tauri/build.rs / capabilities/ / permissions/
  tests/sdd-execute/                   # herness-sdd-execute-tests
  tests/runtime/ / tests/supervision/ / tests/html-sync/
  ui/
  docs/development/h4-testing.md
  docs/research/2026-11-13-h4-acceptance.md
```

Task 1〜3はpack、Task 4〜25は主にhernessを変更する。既存ホストのcontrollerが二つの実作業先を最初に確定し、Taskは直列・Task単位commit、変更と証拠はrepo別に記録する。隔離を選んでもTaskごとにworktreeを作らず、SDD_PACK_ROOTを絶対パスで固定する。別repo書込みが未許可なら、pack Task開始前に確認する。本plan保存はその許可や本実装開始ではない。

通常検証は一時repo・DB、fake credential、loopbackのみ。既存Keychain探索・実login・実model送信を行わない。各Taskは実行者、実コマンド・終了codeと出力、対象revision、検証範囲・未確認を報告する。新test targetは対応Taskで作成してから実行し、存在しないコマンドの成功を報告しない。以下のPythonコマンドはpackをcwdとし、pytest不足時は環境を確認して既存のuvx手順を使う。依存を無断でprojectへ追加しない。

## Task 1: 新形式planのschemaとlossless parserを作る

**Dependencies / spec:** 先行Taskなし。H4 New plan format and inspection。packのsdd-plan、md.py、test_md.py、test_task_brief.pyを読む。

**Paths / deliverable:** packのplan_schema.py、test_execution_plan.py、手著作fixtureとschema文書。従来parserを壊さず、新形式だけの厳密な解析を追加する。

**Acceptance:** 正確なUTF-8 bytes・byte範囲、必須header、Global Constraints、単一JSON block、連番Task、全field・参照・mode・finalChecksを検証する。重複key、boolを番号として扱う入力、未知field/版、壊れたfence、先行以外の依存、path escapeを拒否する。原文へ自己参照digestを埋めず、Task本文を保持する。

**Verification / evidence:** `python3 -m pytest tests/test_execution_plan.py tests/test_md.py tests/test_task_brief.py -q`。日本語/CRLF、fenced偽見出し、2 MiB境界、旧形式拒否、正常2 Task fixtureと原文byte一致を報告する。

## Task 2: 副作用なしのplan-inspect protocolを提供する

**Dependencies / spec:** Task 1。H4 New plan format and inspection、Numeric defaults and lifecycle。

**Paths / deliverable:** packのscripts/plan-inspect、plan_inspect.py、test_plan_inspect.py。capabilities/inspectと実行契約fingerprintを提供する。

**Acceptance:** stdin/stdout version 1、sourceBase64、flatなplanPath、diagnosticsと原文範囲を固定する。parser・schema・連携/実行/implementer指示の版をfingerprintへ束縛する。外部参照・model・shell・ファイル書込みを行わず、サイズ超過・不正入力・未知operationを明示する。

**Verification / evidence:** `python3 -m pytest tests/test_plan_inspect.py tests/test_execution_plan.py -q`。実subprocessのcwd・exit/stdout/stderr、filesystem不変、外部要求0、指示変更でfingerprintが変わることを報告する。

## Task 3: herness限定の実行連携とskill差分を定義する

**Dependencies / spec:** Tasks 1〜2。H4 Integration prerequisites and consuming paths、Shared operations and authorization。H1 Skills and documents。

**Paths / deliverable:** packのadapters/herness、関連skills、README、test_herness_execution.py、既存adapter回帰。実行用の独立したversion付き契約を追加する。

**Acceptance:** H3契約へ未知fieldを足さない。H4 registry承認・実行能力・pack指紋が揃う場合だけ親dispatch/子commitをhostへ移し、一回resume規則をH2有限継続へ置き換える。新形式著作と実行許可を区別し、herness不足時の親fallbackを拒否する。他ホスト・H3・doctorを変えない。

**Verification / evidence:** `python3 -m pytest tests/test_herness_execution.py tests/test_herness_adapter.py tests/test_host_adapters.py -q`、続いて`python3 -m pytest -q`。偽承認、古い指紋、既存hostの著作/execute/finish、H3独立性を報告する。

## Task 4: H4契約・portとテストpackageを定義する

**Dependencies / spec:** Tasks 1〜3の解析契約。H4 Approach and architecture、Shared operations and authorization、Durable state, plan changes and finish。

**Paths / deliverable:** herness-sdd-execute、tests/sdd-execute、workspace。herness-sdd-execute-testsにcontracts targetを作る。

**Acceptance:** execution/Task/plan revision、状態・理由・必要操作・snapshot、approval、dispatch/Git/progress journalと要求冪等性を型で区別する。H2 IDやH1 run状態をTask状態に流用せず、portは具体DB・Tauri・Piへ依存しない。unknown version拒否とnull参照を表せる。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test contracts --locked`、`cargo check --workspace --locked`。別project、ID混同、未知版、状態遷移とcore逆依存なしを報告する。

## Task 5: H4の永続状態とjournalをtransactionで保存する

**Dependencies / spec:** Task 4。H4 Durable state, plan changes and finish、Host commits and Git recovery。H1 Events and audit・Lifecycle and recovery。

**Paths / deliverable:** storeの0010_sdd_execute.sqlと実装、H4 store port、tests/sdd-executeのstore target。

**Acceptance:** schema 9から既存履歴・H2/H3状態を保持して移行する。承認、Task対応予約、要求/結果、manifest、予算補充分、Git/progress journalを保存し、CASとproject eventを原子的に扱う。失敗は旧DB保持、未知版は書込み拒否とし、restoreだけで実行しない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test store --locked`、`cargo test -p herness-store --locked`。migration fault、件数/ID保持、CAS/重複要求、別接続再読込みと保存後通知を報告する。

## Task 6: H1に承認済みhost Gitの実行・監査境界を作る

**Dependencies / spec:** Tasks 4〜5。H1 H4 integration additions 1〜2、Permission modes、Lifecycle and recovery。H4 Host commits and Git recovery。

**Paths / deliverable:** coreのhost Git権限・process/停止・監査port、runtimeの新host_git target。stage/commit用のhost専用境界を実装する。

**Acceptance:** checkout・branch・期待HEAD・path/bytes・目的・承認版を副作用前に照合し、model/previewから到達させない。argvを固定し、通常hookを省略せず、30秒/残時間・quit・process group停止を適用する。GitとDBの不確実性を保持し、push・履歴書換え・rollbackを追加しない。

**Verification / evidence:** `cargo test -p herness-runtime-tests --test host_git --locked`、`cargo test -p herness-core --locked`。実一時Git、偽権限・古いHEAD、hook停止/失敗、意図保存失敗と実行0を報告する。

## Task 7: checkout選択と実Git workspace adapterを接続する

**Dependencies / spec:** Tasks 4〜6。H4 Workspace, context and task identity、Host commits and Git recovery。H1 H4 integration additions 1。

**Paths / deliverable:** desktop/sdd_executeのgit/workspace、H4 workspace port、workspace target。read-only Git状態・manifestと明示選択による初回worktreeを提供する。

**Acceptance:** 既存選択を再利用し、隔離失敗をin-place許可と扱わない。選択先のclean・plan/spec版・branchを確認し、許可済み.gitignoreだけの準備commit後にbaselineを固定する。元checkoutのdirtyを破棄せず、外部文書sourceを読取りsnapshotへ限定する。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test workspace --locked`。実Gitでlinked/in-place、元dirty/選択先clean、失敗後要求0、ignore準備、別repo書込み0を報告する。

## Task 8: H4 registry照合とowner対象の冪等作成を実装する

**Dependencies / spec:** Tasks 4〜5。H2 H4 integration additions 1・4、Completion contract and operations。H4 Shared operations and authorization。

**Paths / deliverable:** supervision/owner_launch、desktop/supervisionのplan/mod/runtime/store、新owner_launch target。予約済み要求IDからsupervisionとchildの一意対応を復元する。

**Acceptance:** H4ApprovalUnavailableをregistry実装なしで解除しない。plan/Task/条件/packet/scope/profile/consent/上限の一致を検査し、create途中crashで新しい子を重複作成しない。不明は照合待ち、Human/H3起動と復旧後の人間再開は維持する。

**Verification / evidence:** `cargo test -p herness-supervision-tests --test owner_launch --locked`、`cargo test -p herness-supervision-tests --test desktop --locked`。正例初回1、偽owner/H3承認/重複/各crash境界の起動数を報告する。

## Task 9: 条件modeと検証操作の保存・実行を揃える

**Dependencies / spec:** Task 8。H2 H4 integration additions 3・5、Evidence and freshness。H4 New plan format and inspection。

**Paths / deliverable:** supervisionのconditions/evidence/verification、desktop/supervisionのplan/checks、check_modes target。承認されたmode・cwd・timeout・inputPathsを実経路へ通す。

**Acceptance:** checks modeは必要check全pass、assessment modeは従来評価を使う。root/60秒固定へ置換せず、実引数と入力範囲・残時間を検査する。host検証者を正しく記録し、有効証拠を再利用する。旧plan format 2等は明示decoderで元の意味を保ち、新形式を旧形式で誤読しない。

**Verification / evidence:** `cargo test -p herness-supervision-tests --test check_modes --locked`、`cargo test -p herness-supervision-tests --test evidence --locked`。サブcwd、指定timeout、scope外、checksのみの判定要求0、旧fixtureと証拠再利用を報告する。

## Task 10: owner検証準備gateをH2へ追加する

**Dependencies / spec:** Tasks 8〜9。H2 H4 integration additions 2・4、States and continuation。H4 Execution, evidence and HTML barrier。

**Paths / deliverable:** supervisorのport/state/検証開始、desktop接続、新readiness target。入力完結/Idle後のready・pending・blockedを扱う。

**Acceptance:** pendingで検証fail・追加run・停滞cycleを増やさず、時間・停止・deadlineは進む。blockedは理由付き待機、readyでも通常の検証/評価を省略しない。保存・復旧でgate待機を保持し、古いreadyを完了根拠にしない。

**Verification / evidence:** `cargo test -p herness-supervision-tests --test readiness --locked`、`cargo test -p herness-supervision-tests --test supervisor --locked`。待機→ready、blocked、timeout/停止、遅延応答と継続回帰を報告する。

## Task 11: 同projectのH3とTaskを対象単位でpumpする

**Dependencies / spec:** Tasks 8〜10。H1 H4 integration additions 3、H2 H4 integration additions 3。H3 Detection, scheduling and continuity。

**Paths / deliverable:** desktop/host.rs、supervision/runtime/mod、html_sync/worker/composition、新scheduling target。H3-active project全体の除外を対象別に置き換える。

**Acceptance:** 各監督対象を一度だけ処理し、H3 candidate handle付きadapterとTask native adapterを混ぜない。H3のアプリ全体1著作枠、H1の停止/期限、通常Human ownerの進行を維持する。UI pollや選択projectへ依存しない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test scheduling --locked`、`cargo test -p herness-html-sync-tests --test worker --locked`、`cargo test -p herness-supervision-tests --test desktop --locked`。同project併進とtool交差0を報告する。

## Task 12: inspector bridgeと副作用なしpreviewを作る

**Dependencies / spec:** Tasks 2〜5・7。H4 New plan format and inspection、Shared operations and authorization。H1 Skills and documents。

**Paths / deliverable:** H4/import、desktop/sdd_executeのpack/source bridge、import target。実Python inspectorの結果を保存可能なpreviewへ取り込む。

**Acceptance:** toolchain/pack指紋を照合し、argv/stdin・30秒・2 MiBを適用する。正確なbytesとbyte範囲を保持し、spec/section/外部aliasの実在・root・snapshotを確認する。不正応答・古いpackは不可で、inspectから子・model・Git変更を起動しない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test import --locked`、`cargo test -p herness-runtime-tests --test skills --locked`。実parser、CRLF、日本語、timeout/不正JSON、外部source拒否、要求0を報告する。

## Task 13: 開始承認registryとworkspace準備を実装する

**Dependencies / spec:** Tasks 5〜8・12。H4 Shared operations and authorization、Workspace, context and task identity。H2 Profiles, providers and disclosure。

**Paths / deliverable:** H4/approval、desktop/sdd_executeのregistry/composition、approvals target。人間の開始承認を現在の実入力に束縛する。

**Acceptance:** plan/spec/pack、checkout/branch/baseline、条件/scope、接続/同意/profile、予算、host commit/hook、H3設定を確認して保存する。H3承認を流用せず、能力不足・未同期・dirtyでは開始しない。source alias読取りとGit隔離作成は明示選択の範囲に限定する。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test approvals --locked`。偽UI/registry・古い版・別project・同意取消し・重複start、準備前後faultと無断起動0を報告する。

## Task 14: 不変packetとTask報告・先行決定の引継ぎを作る

**Dependencies / spec:** Tasks 8〜9・12〜13。H4 Workspace, context and task identity。H2 H3 integration additions 1、H4 integration additions 1。

**Paths / deliverable:** H4/packet/report、desktop/sdd_executeのH2 adapter、packet target。Task本文・原文制約・spec snapshot・先行interface/Rulingを構成する。

**Acceptance:** 初回/継続/復元で同じ条件と文脈を保ち、全plan/diffを貼らず、容量不足を隠さない。DONE/BLOCKED/NEEDS_CONTEXT、五項目の証拠、正本反映状況を解釈する。重要な未合意事項は人間待ち、可逆詳細のRulingは後続packetへ残す。子にGit操作を担当させない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test packet --locked`、`cargo test -p herness-runtime-tests --test engine --locked`。実Pi＋loopbackの初回/2回目入力、会話保持、欠けた文脈の保留と正本への反映参照を報告する。

## Task 15: 直列coordinatorとTask予算を接続する

**Dependencies / spec:** Tasks 5・8〜14。H4 Execution, evidence and HTML barrier、Numeric defaults and lifecycle。H2 States and continuation・Budgets and request failures。

**Paths / deliverable:** H4/coordinator/budget、desktop composition、coordinator target。dispatch意図とH2対応を保存して最初の未完了Taskだけを起動する。

**Acceptance:** アプリ全体1実装者、checkout所有1、同じ子の有限継続、保存済みH2結果の再取得を保証する。完了通知の重複で進行しない。H2監督分とhost終了処理分を合算し、再開/再承認で予算を戻さない。barrier/commitが未接続なら次Taskへ進ませない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test coordinator --locked`、`cargo test -p herness-supervision-tests --test budget --locked`。2 Task順序、重複通知、7,200秒/30回/停滞境界、未停止と上限後metの拒否を報告する。

## Task 16: H3必要集合と検証準備・最終barrierを結ぶ

**Dependencies / spec:** Tasks 10〜15。H4 Execution, evidence and HTML barrier。H3 Shared contract for H4 and H5・Detection, scheduling and continuity。

**Paths / deliverable:** H4/barrier、desktopのH3 adapter、barrier target。Task前後走査・明示対象・正本/plan・CSS/resource影響を和集合にする。

**Acceptance:** 実bytes・H3 revision・全依存指紋・現承認を比較し、保存Syncedやreceiptだけを信頼しない。必要なbootstrap/著作/評価はH3へ委譲し、未同期/不明/削除孤立を保留する。H3条件を緩めず、無関係な未変更Targetだけを理由に停止しない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test barrier --locked`、`cargo test -p herness-html-sync-tests --test desktop --locked`。列挙漏れ、CSS失効、古いHTML、同じbytesへの復帰、各barrier結果と無関係文書のケースを報告する。

## Task 17: host commit journalとTask確定を接続する

**Dependencies / spec:** Tasks 5〜7・15〜16。H4 Host commits and Git recovery、Execution, evidence and HTML barrier。H1 H4 integration additions 1〜2。

**Paths / deliverable:** H4/git/finalize、desktop Git adapter、commit target。対象固定→意図保存→明示path stage→hook/共通gate→commit→内容再確認を実装する。

**Acceptance:** Task変更と検証済み派生成果物だけを含め、期待parent/treeと要求trailerを保持する。未知index・外部競合・hook変更・不明結果は保留し、自動reset/再commitしない。requiredはHEAD進行、no_changeはsource不変かつ空commitなし。DB確定前に次Taskを始めない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test commit --locked`、`cargo test -p herness-runtime-tests --test host_git --locked`。実Git/共通gate、hook失敗、全journal境界fault、二重commit0、無関係stage0を報告する。

## Task 18: 互換台帳出力とfinish引継ぎを実装する

**Dependencies / spec:** Tasks 14〜17。H4 Durable state, plan changes and finish。packのledger.py・stack.py・sdd-finishを参照する。

**Paths / deliverable:** H4/ledger/finish、desktopの出力adapter、ledger target。.sdd/progress.md、brief/reportとfinish情報を保存状態から出力する。

**Acceptance:** DBを正本とし、baselineと完了範囲を変えず、出力失敗/外部改変では次Taskを保留する。最後のTaskのfinalChecksと正本反映が現最終状態を覆う場合だけready_for_finishにする。no_changeのstacked非互換を明示し、統合選択前のpush等を行わない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test ledger --locked`、packで`python3 -m pytest tests/test_stack_prs.py -q`。実packの台帳parser/preflight、出力fault、空範囲、古いfull-suite証拠と引継ぎ内容を報告する。

## Task 19: plan変更検知と限定した再承認を実装する

**Dependencies / spec:** Tasks 12〜18。H4 Durable state, plan changes and finish、Shared operations and authorization。

**Paths / deliverable:** H4/plan_changes、desktop watcher/clock接続、plan_changes target。通知・1秒照合・副作用直前確認を併用する。

**Acceptance:** 本文だけの変更、削除/移動、不安定読取りで現在Taskも安全停止し、bytes復帰でlatchを消さない。未着手だけの変更と不変な制約/参照/着手済み契約に限り、人間承認後に継承する。その他は新plan/作業整理を要求し、履歴や予算をリセットしない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test plan_changes --locked`。fake clockと実一時filesystem、atomic save、通知欠落、commit直前変更、着手済み改変拒否と再承認重複を報告する。

## Task 20: quit・crash後の照合と人間再開を接続する

**Dependencies / spec:** Tasks 5・8・15〜19。H4 Numeric defaults and lifecycle、Host commits and Git recovery。H1 Lifecycle and recovery、H2 H4 integration additions 4。

**Paths / deliverable:** H4/recovery、desktop/hostとlifecycle/quit、recovery target。起動/停止/Git/progressの未確定記録を照合する。

**Acceptance:** quitでdispatch/送信/commitを閉じ、H1/H2/H3と保存する。復元は要求0、未知送信・未停止process・Git不明結果を未実行に戻さない。成立済みcommitは人間確認後に対応付け、同じTaskを再dispatchしない。H4保存失敗もquit完了を妨げる理由として返す。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test recovery --locked`、`cargo test -p herness-runtime-tests --test desktop --locked`。別processの再読込みと各fault、予算保持、停止latch、復元時外部要求0を報告する。

## Task 21: 信頼されたdesktopへ最小操作と状態を公開する

**Dependencies / spec:** Tasks 12〜20。H4 Shared operations and authorization、Durable state, plan changes and finish。H1 Architecture・Permission modesと既存guard。

**Paths / deliverable:** desktop/sdd_execute、app/commands/build/capabilities/permissions、core/skills/capability、ui、desktop target。preview、承認開始、取得/購読、停止/取消し/再開/再承認、finish情報を接続する。

**Acceptance:** mainだけが人間確認を発行し、model/preview/remoteから拒否する。scope・同意・各Task上限と複数Task/H3費用、未検証能力を表示する。必要portと現在の承認が揃う場合だけSddTaskControllerを利用可能にする。保存snapshotとsequenceから再接続し、UI独自の成功や実装fallbackを作らない。H5の完成版画面を前倒ししない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test desktop --locked`、`cargo build -p herness-desktop --locked`。偽origin、古いrevision、同意取消し、操作重複、未同期/判定不能/commit不明の表示を報告する。

## Task 22: 実adapterで2 Task以上の横断実行を検証する

**Dependencies / spec:** Tasks 1〜21。H4 Testing and acceptance 1〜6・8、H1/H2追加契約、H3 Shared contract for H4 and H5。

**Paths / deliverable:** tests/sdd-executeのcross_phase targetと手著作fixture、pack共通fixture。実Python・SQLite・Git・Pi＋loopback・H3同期と必要なWebKitを結ぶ。

**Acceptance:** preview要求0→承認→初回/未達継続→同期→判定→host commit→次Task→finishを親dispatchなしで通す。制約/正本引継ぎ、H3同project併進、plan変更/偽DONE/古い証拠/注入/偽承認の誤進行0を確認する。検証全体をmockにせず、scripted judgeと実箇所を区別する。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test cross_phase --locked`、`cargo test -p herness-sdd-execute-tests --locked`、packで`python3 -m pytest -q`。両repo revision、実commit範囲、同期証拠、要求数・負例別結果を報告する。

## Task 23: 実Tauriでwindow非依存と再起動を確認する

**Dependencies / spec:** Tasks 20〜22。H4 Testing and acceptance 7、Numeric defaults and lifecycle。H1 Lifecycle and recovery。

**Paths / deliverable:** desktopの明示native test mode、新native_lifecycle target、h4-testing.md。H3 native_lifecycle fixtureの一時data rootと子process方式を再利用する。

**Acceptance:** 閉じたwindow・非選択projectで進行し、quit後の再起動は外部要求0で照合/人間再開を待つ。commit直前/直後・DB結果前・progress置換前のcrashを実processで確認する。既存app data・Keychain・実providerへ触れない。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test native_lifecycle --locked`、`cargo test -p herness-html-sync-tests --test native_lifecycle --locked`。使用したfresh root、native process/終了code、実Git照合、復元時要求0を報告する。

## Task 24: 評価fixtureとopt-in実接続の許可gateを整備する

**Dependencies / spec:** Tasks 22〜23。H4 Testing and acceptance。H2 Profiles, providers and disclosure、H3受入記録の未確認範囲。

**Paths / deliverable:** tests/sdd-executeのfixtures/acceptance target、明示opt-in runner、h4-testing.md。合成した新形式planで実接続受入を再現できる手順を作る。

**Acceptance:** 接続、fixture、送信bytes種別、有限要求/retry、料金/枠が明示許可されなければ送信前拒否する。必要なH3画像/残条件の能力を省略せず、承認を実login/資格情報探索へ拡張しない。誤完了・誤commit・誤dispatchと保留を別集計し、H1/H2/H3未確認を継承する。

**Verification / evidence:** `cargo test -p herness-sdd-execute-tests --test acceptance --locked`。既定外部要求0、期限切れ/範囲外/回数上限、合成正負例と未実行の実provider欄を報告する。このTaskでは実送信しない。

## Task 25: H4受入を実施し未確認を記録する

**Dependencies / spec:** Tasks 1〜24。H4 Testing and acceptance、Open items and approval。H1/H2の受入未完了とH3の限定受入を免除しない。

**Paths / deliverable:** docs/research/2026-11-13-h4-acceptance.md、h4-testing.md。Phase Aの自動/loopback/nativeと、別途許可されたPhase Bの結果を分離して保存する。

**Acceptance:** Phase Aは実pack・Git・SQLite・Pi/loopback・H3/WebKit・Tauri lifecycleで正例成立と負例誤進行0を確認する。Phase Bはcontrollerが送信範囲と有限上限を提示し、人間が許可した実接続だけで実行する。必要能力/許可がなければ未確認で保留し、Task 25やH4全体を完了扱いにしない。限定受入への変更は人間と再合意する。

**Verification / evidence:** `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo test --workspace --locked`、`cargo build -p herness-desktop --locked`。freshな絶対HERNESS_APP_DATA_ROOTで既存smoke/close-reopen/quitとH4 native fixtureを実行する。packで`python3 -m pytest -q`、両repoの変更Targetをhtml-docsで検証する。実要求数・usage・commit範囲・失敗/保留・未確認をsecretなしで報告する。
