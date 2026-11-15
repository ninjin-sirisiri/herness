# H4: herness主導のsdd-execute

**Classification:** architectural

**Status:** 2026-11-13、保存済みspecとH1/H2のH4 integration additionsへのレビュー依頼に対する利用者の「ok」により、設計と追加契約を承認済み。H4だけのsdd-planへ進む。本実装・pack変更・実モデル送信・pushの許可ではない。

**Chosen approach:** 新形式のMarkdown planを決定的に取り込み、人間が承認した版に対してRust hostがTask起動・監督・HTML同期確認・commit・進行台帳を制御する。既存の散文planをモデルで解釈して実行しない。

本specは[ロードマップ](2026-11-07-herness-roadmap.md)のH4を扱う。[H1](2026-11-07-h1-runtime-design.md)を実行・許可・監査、[H2](2026-11-08-h2-supervision-design.md)を監督・証拠・予算、[H3](2026-11-09-h3-html-sync-design.md)をHTML同期、[CONTEXT.md](../../../CONTEXT.md)を用語の正本とする。H5は本specの操作・状態・引継ぎ契約を利用する。

## Goals and non-goals

- 親モデルのsubagent toolを必要とせず、承認済みplanのTaskを順番に実行する。Taskごとに独立した子を作り、未達の継続はH2により同じ子で行う。
- Global Constraintsの原文、正本specの適用section、先行Taskのinterface・決定・証拠を初回と継続へ引き継ぐ。
- 必須検証、現在のHTML同期、commit結果、永続化が成立しなければ次Taskへ進まない。停止・復旧・plan変更を追跡できるようにする。
- 初期実行範囲は1 planにつき1リポジトリ・1実装checkout。承認された外部文書の読取りを、外部リポジトリへの書込み許可にしない。
- 旧形式の自動変換、Task並列実行、Taskごとのworktree、必須レビューループ、親による実装fallback、自動push・merge・公開、独自のHTML policy、OS sandboxは含めない。
- 完成版UI・配布はH5。H4では承認・開始・停止・再開・状態確認とfinish引継ぎの最小接続を作る。H4自身の開発に既存ホストを使うことは妨げず、初期H4で複数repoのplanを自己実行できるとは主張しない。

## Approach and architecture

比較したのは「旧planから実行条件案を作って再承認」と「新形式だけを受け付ける」の二案。利用者は後者を選んだ。commitは従来の子担当からhost担当へ移し、非同期のHTML反映を含む対象を確定してから行う。

| Component | 責務 |
| --- | --- |
| packのplan inspector | 新形式・Task対応・参照・診断・原文指紋のread-onlyな解析。承認・実行はしない |
| H4 approval registry | 人間が確認したplan版・checkout・権限・接続・条件・上限を保存し、現在の承認だけを返す |
| H4 coordinator | Task順序、起動意図、H2対応、同期barrier、commitと台帳、停止・復旧を制御 |
| H1 / H2 / H3 ports | 実tool・host Git監査、有限の監督、共通policyと文書同期を各正本に従って提供 |
| store / desktop | H4状態・要求・journalをtransactionで保存し、アプリ寿命のpumpと信頼された操作を接続 |

新しい`crates/herness-sdd-execute`はcore・supervision・html-syncの公開契約と自身のportに依存し、Pi・Tauri・具体的DBへ依存しない。coreからH4へ逆依存させない。packがschema・parser・host連携を所有し、Rustで別のMarkdown解釈を維持しない。

## New plan format and inspection

新形式は既存のGoal・Architecture・Tech Stack・Spec、Global Constraints、file structure、`## Task N:`を保ち、Taskより前に一つだけinfo stringが`sdd-execution-v1`のfenced JSON blockを持つ。Markdown全体が正本で、別の実行JSONファイルを正本にしない。通常ホストの既存planを無効にせず、herness向け`sdd-plan`がこの追加形式を著作する。

| Object | 必須fieldと意味 |
| --- | --- |
| root | `schema`は`sdd-execution-plan`、`version`は1。`specRefs`、`tasks`、`finalChecks`を持つ |
| spec reference | `source`、`path`、`sections`。sourceは`project`または人間が登録する読取り専用sourceのalias。sectionsは適用見出しの空でない配列 |
| task | `number`、`dependsOn`、`specRefs`、`readPaths`、`writePaths`、`allowShell`、`deliverables`、`conditions`、`checks`、`htmlTargets`、`commitPolicy` |
| condition | Task内で一意な`id`、空でない`title`・`rubric`、`mode`。modeは`checks`または`assessment` |
| check | Task内で一意な`id`、`conditionId`、`description`、`command`、`cwd`、正の有限な`timeoutSeconds`、`inputPaths`。commandは承認対象のshell文字列で、取込み時には実行しない |
| deliverable | project-relativeな`path`と`kind`。kindは`file`または`directory`で、存在と型を検査する |
| finalChecks | 最後のTaskのcheck IDの空でない配列。最終状態のfull suiteを表す手順・範囲を最後のTaskに明記し、その証拠を使う |

rootと各objectは未知field・重複key・未知版を拒否する。Taskは1から連番で、JSONと見出しの件数・番号・順序が一致し、空の見出しを認めない。dependsOnは存在する先行Taskだけを参照し、実行自体は常に全Taskの直列順とする。配列を黙って並べ替えたり、重複番号の最初を採用したりしない。

各Taskのconditions・specRefs・readPathsは空にしない。TaskのspecRefsはrootのspecRefsの部分集合とする。checkは実在する一つのconditionを参照し、checks modeのconditionは一つ以上のcheckを必要とする。assessment modeはH2の条件別rubric評価を使う。htmlTargetsは既知の必要文書を列挙する追加指定で、変更検出による対象を除外できない。commitPolicyは`required`または`no_change`。後者はwritePathsが空で、checkoutの内容変更がない検証・調査Taskだけに許可する。その他のfieldは省略で補わず、不要な配列は明示的に空にする。

パスは正規project-relative形式とし、絶対パス・`..`・symlinkによるroot脱出を拒否する。cwdは`.`またはroot内のdirectory。readPaths・writePathsはH2のbounded scopeに従い、`.`や`*`で権限を無制限にしない。外部specは登録済みsourceの読取りsnapshotとしてhostが渡し、子のproject-relative grantを外へ広げない。aliasの絶対rootと送信範囲は開始前に人間が承認する。

Task本文を作業brief、構造化blockを実行条件として扱う。本文や正本specと矛盾が見つかれば開始・継続を止めて解消する。形式検査が散文の意味の一致やspec承認を証明したとは表示しない。条件の散文抽出、実行時のモデルによるcheck追加、見つからないspecや検証コマンドの補完は行わない。

packに新しい`plan-inspect`を追加する。cwdをproject rootとし、stdin/stdoutのJSON protocol `sdd-plan-inspect` version 1で`capabilities`と`inspect`を提供する。inspect要求は正規`planPath`と正確なbytesの`sourceBase64`、応答は原文digest、header・Global Constraints・Task本文のbyte範囲、構造化条件、参照、diagnosticsを持つ。planPathはprojectの`docs/sdd/plans/`直下のMarkdownに限定する。capabilitiesはschema版と実行契約のfingerprintを返し、対象にはparser・schema・連携定義・execute指示・implementer指示を含める。H3のHTML policy fingerprintで代用しない。

inspectorはUTF-8・fence・JSON、必須headerとGlobal Constraintsの存在・順序、構造と参照の内部整合を検査し、ファイルを書かず、外部参照を開かず、model・shellを起動しない。正本の実在・承認・現在版はhostが別に照合する。旧形式は`unsupported_plan_format`、不正形式は`invalid_plan`として、該当byte範囲と理由を返す。非zero終了、不正JSON、timeout、過大入力、対応しないfingerprintは利用不可であり、`task-brief`のscratch出力やRustの推測parserへfallbackしない。

## Shared operations and authorization

plan取込みはread-onlyのpreviewであり、実装・モデル送信・worktree作成・commitを許可しない。開始操作で、spec承認を確認した人間が次を一つの承認版として確認する。

- 正確なplan bytesとdigest、解析結果、Global Constraints原文、参照spec・外部source・pack実行契約のfingerprint。
- project、実checkoutのcanonical rootとGit識別、branchとbase branch、Task別の条件・scope・必須検証・HTML対象。
- 実行接続、H2 profile・用途別送信同意、各Taskの有限予算、hostによる対象変更のstage・commitとローカルhook実行。
- 必要なH3設定・送信同意・能力。H3承認を実装承認に流用せず、H4承認でH3条件も緩めない。

承認は信頼された人間UIからだけ保存する。repo内の文字列、完了報告、環境変数、receipt、`ApprovedOwner`や`H4SddTask`という値だけでは起動しない。H4 registryを照合した非serializableなhost権限により、Taskの条件承認をH2へ継承する。各Taskや修正可能な追加runの前に同じ承認を繰り返さない。

| Operation | 結果・制約 |
| --- | --- |
| inspect / get / subscribe | previewまたは保存済みsnapshot・project sequenceを返す。inspectだけでは副作用なし |
| approve-and-start | workspaceと現入力を照合し、承認・起動意図を保存して実行。能力・同意不足では開始しない |
| pause / cancel | 新規dispatch・送信・commitを止め、現在の子へ協調停止。cancelは終端で、変更や履歴を消さない |
| resume | 人間操作。停止確認、現入力、権限・同意・残予算、Gitと未確定操作を照合し、可能な同じTaskから再開 |
| approve-plan-revision | 停止後に差分と継承可能性を確認する。新しい承認版を保存するまで旧版・新版とも実行しない |
| finish handoff | 全Taskの確定と最終証拠を渡す。外部Git操作の許可には変換しない |

更新操作はproject・execution ID・request ID・expected revisionを必須とし、重複requestは保存結果を返す。同じrequest IDで別内容は拒否し、古いrevisionは副作用前に競合を返す。開始要求の再配送で子やcommitを増やさない。

実行snapshotはversion、project、execution IDとrevision、plan digest・承認版、checkout・branch・baseline、現在Task、各Taskの安定ID・number・進行/phase・H2参照・commit範囲・no_change・証拠参照、停止理由と必要操作、消費/予約予算、現在への適用、最終project sequenceを返す。未成立の参照はnullとして捏造しない。失敗はunsupported_plan_format・invalid_plan・unavailable・approval_required・conflict・plan_changed・html_not_synced・recovery_required・budget_exhausted・git_result_unknownを区別し、H1/H2/H3の詳細参照も保持する。UIからの成功宣言で状態を変更しない。

## Workspace, context and task identity

実装checkoutは既存SDDの一度だけのworktree選択を維持する。既存のWorktree記録・linked worktree・同じ会話での回答を優先し、未決定の場合だけ隔離を尋ねる。隔離を選んだ明示承認によって初回のworktree・新branchを作り、commit許可だけで作成や削除を行わない。隔離失敗をin-place許可と扱わず、選んだcheckoutのdirtyだけが開始を妨げる。無断のstash・reset・clean・checkoutによる変更破棄は行わない。

選択先には承認するplan・specの版が実在し、必要なH3同期と共通HTML検証が成立し、初回Task前のindex/worktreeはcleanであることを要求する。`.sdd/`のliteral ignoreがなければ、開始承認に含めた準備操作として.gitignoreだけを編集・commitする。Branch baselineは準備完了後のfull SHAを一度保存し、再開で置き換えない。Worktree実パス・branch・baselineをDBと`.sdd/progress.md`へ記録する。

Execution ID、plan revision、Taskの安定IDとnumber、H2 supervision ID、子agent/session、run/input、commit要求IDを区別する。Taskの安定IDはexecution内で保持し、番号や親会話から推定し直さない。同じcheckout・branchの実行所有は一つとする。

manifestはreadPaths・checkのinputPaths・writePaths・成果物・必要文書と関連設定を含め、不明な依存はproject全体へ広げるか判定不能にする。`.git/`・`.sdd/`と開始時に明示した生成出力はsourceの不変性確認から除外できるが、検証inputや成果物を除外しない。no_changeの変更なしはこの対象sourceについての保証で、テストの一時出力やGit内部の更新まで禁止した意味ではない。

H4はTask本文と、Global Constraintsの正確な原文、参照specの適用sectionと現在snapshot、先行interface・Ruling・未解決事項、scope、report要求を不変packetへ組み立てる。plan全体や全diffを毎回貼らない。必要文脈が容量・送信範囲に収まらなければ、黙って切り捨てず人間待ちにする。報告はDONE・BLOCKED・NEEDS_CONTEXTと、成果物、五項目の証拠、後続へ影響する決定を含む。DONEだけを完了としない。

正本specの重要な変更は人間の判断が必要であり、子が承認範囲を広げない。合意範囲内の可逆な詳細はRulingとして記録する。後続へ影響する決定は正本specに反映し、依存文書も整合または正本への委譲を確認してからTaskを確定する。specの現在版はこの記録を伴う場合だけ更新し、外部からの未確認変更は人間待ちにする。

## Execution, evidence and HTML barrier

1. coordinatorは未完了の最初のTaskだけを選び、承認・checkout・plan版を照合する。BASEとmanifest、H2対応の予約、dispatch要求IDを副作用前に保存する。
2. owner起動でH2対象とpacketを一度だけ作成・接続する。対応IDが不明なcrash後は新しい子を作り直さず照合する。H2は実grantと既存の許可モードを使う。
3. 子が入力完結かつIdleになり、未解決tool/processがなくなったら、H4の検証準備gateで必要なH3同期を待つ。通常の同期待ちを失敗した検証や子の停滞と誤認しない。停止・deadlineは待機中も有効とする。
4. H3が整った安定snapshotでH2の必須検証・条件評価を行う。有効な子・CI・人間の証拠を五項目と入力manifestで照合して再利用する。不足・古い証拠だけを取り直し、修正可能な未達は同じ子へ返す。BLOCKED・NEEDS_CONTEXTは同じpromptで再試行しない。
5. H2完了snapshot、成果物、正本反映、現在のplan・scope・停止・予算、H3 barrierを再照合する。hostがcommit対象を確定し、Git journalを保存してcommitする。
6. commit後のHEAD・tree・index・worktreeと文書版を再確認する。内容が変わっていれば関連証拠を失効し、未確認のまま完了にしない。完了結果・commit範囲・次Taskの選択可能状態をtransactionで保存し、progress出力後に次Taskを起動する。

H3必須集合は、Task前後の共通Target走査で作成・変更を確認した文書、参照するproject内の正本specと実行plan、htmlTargetsの和集合とする。CSS・resource等の変更はH3の依存関係から影響文書を追加する。集合・依存が確定しなければ安全側に広げるか人間待ちにし、JSONの列挙だけを信用して省略しない。無関係で変更のないTargetの失敗だけではTaskを止めない。

barrier要求前とTask確定直前に実ファイルbytes、H3原文revision、source・HTML・CSS/resource・policy・設定/profile等の現在指紋を採取し、H3の保存状態・承認と照合する。既存`H4Barrier`は保存状態と呼出側の入力を比較するだけなので、単にそのSynced応答やrepoのreceiptだけを信頼しない。NotApproved・Missing・Mismatch・Unsyncedを区別して保留する。

H3によるcompanion不足のbootstrap・著作・評価・反映はH3へ委譲する。削除・移動でorphanedが生じたら必要な後始末の人間判断を求め、H4が旧HTMLを自動削除・移動してGit gateを通さない。同期中のH3と同じprojectのTask監督を進めるため、現在のproject全体を除外するpumpを対象単位の排他へ補修する。候補toolの文脈をTask用のnative toolへ混ぜない。

## Host commits and Git recovery

子の担当は実装・検証・報告までで、Gitのstage・commit・branch変更・履歴書換えを行わない。hostもpush・pull・merge・rebase・amend・reset・cleanを実行フローへ追加しない。シェル許可はOS sandboxではなく、任意scriptの副作用を完全に防げるとは保証しない。予期しないGit操作を検知した場合は停止する。

hostはBASEからの変更と新規ファイル、H3が反映したcompanion・receiptを内容manifestで照合する。承認済みwrite scopeと派生HTML成果物に限定し、無関係な変更、外部編集競合、不明なindex変更があれば人間待ちにする。`git add .`や`git add -A`で一括stageせず、確定したパスをargvで渡す。外部processとの完全排他や、許可範囲内の変更の作者を完全に特定することは保証しない。

commit意図には要求ID、execution・Task、branch、期待parent、対象pathとbytes、message、hook前状態を保存する。期待treeはindexへのstageが済んだ後にしか確定できず、stageは意図保存より後の副作用であるため、意図ではなくcommit結果へ実treeを保存し、commit後のHEAD・tree・index再確認と全journal境界の照合で突き合わせる。commit messageは`Task N: title`と要求を識別する`Herness-Execution`・`Herness-Task`・`Herness-Request` trailerを持ち、秘密を入れない。通常hookと共通staged HTML検証を省略せず、hook失敗・変更・timeout・停止・保存失敗は成功にしない。commit後の記録に失敗してもreset・同じcommitの自動再実行はしない。

復旧ではbranch・parent・tree・要求trailerと保存manifestから、成立済み・未実行・不明を照合する。明確に成立しているcommitは人間の復旧確認後に台帳へ結び付け、同じTaskを再dispatchしない。照合不能なら人間待ちに残す。GitとSQLiteを原子的な一つのtransactionと偽らない。

required Taskは承認対象の成果物をcommitしてBASEからHEADが進む必要がある。no_change Taskは変更なしの証拠を記録し、空commitを作らない。完了範囲は実際のBASE..HEADとして保持する。過去に完了した範囲を後の正本補修で書き換えない。

## Durable state, plan changes and finish

| State | 意味 |
| --- | --- |
| preview / ready | 未実行の取込み案／承認済みで開始可能 |
| running / waiting_html / verifying | 子を実行中／必要な同期待ち／H2による検証・評価中 |
| committing | 対象固定・Git副作用と結果照合中。完了Taskではない |
| waiting_human / stopping / stopped | 判断・権限・能力等の待機／停止要求済み／停止確認済みまたは復旧照合待ち |
| failed / cancelled | 回復不能／明示取消し。成功ではない |
| ready_for_finish | 全Task確定、現最終状態のfull-suite証拠と正本反映を確認し、統合の選択待ち |

executionと各Taskの状態を別に保持し、Taskにはpending・active・completeの進行と上記のphase・停止理由・現在への適用を持たせる。H2 completedはH4 Task completeではない。DBの保存状態が正本で、project sequence付きeventは保存後に通知する。通知queueの配達を進行条件にせず、復旧時はH2/H3の保存結果から照合する。

planのbytesが変わる、消える、移動する、または観測が不安定になると、新規dispatch・commitを止めて現在のTaskへ安全停止を要求する。JSONが同じでも本文・Global Constraintsの変更を無視しない。同じbytesへ戻しても停止latchは解除しない。監視は通知に加えて定期照合を行い、各副作用直前にも確認する。完了後の変更は履歴を消さず現在への適用をstaleにする。

初期の再承認は、Global Constraints、rootのspecRefs、完了済みと着手済みTaskの本文・構造化契約が不変で、未着手Taskだけを変更する場合に継承可能とする。着手済みTaskの条件・scopeを変える場合や完了済みTaskを改変する場合は既存executionへ自動移行せず、新planと人間による作業状態の整理を必要とする。継承可能な新版でも差分・新しい参照・権限・送信範囲・上限を人間が承認し、同じTaskの消費済み予算とcommit履歴を維持する。

`.sdd/progress.md`、Task brief・reportは互換用の出力とする。Worktree、full SHAのBranch baseline、`Task N: complete (commits base7..head7)`、no_change Taskの`Task N: complete (no_change)`、Rulingを既存形式で出力し、DBではfull SHAを保持する。`no_change`行は空のcommit範囲を捏造しないための明示形式であり、既存packの台帳parserはこの行を解釈しない。したがってstacked PR preflightはTask数不一致として互換なしを返し、H4はfinish前にその制約を提示する。出力は一時ファイルと置換を用い、失敗時は次Taskを保留する。外部からのprogress改変を承認や完了として取り込まず、既存の別台帳を黙って上書きしない。通常ホストで開始した旧executionの履歴移行は初期範囲外。

最後のTaskに属するfinalChecksの証拠が最終内容を覆い、関連spec反映も成立すればready_for_finishとする。失敗はそのTaskを未完了としてH2の範囲内で扱い、範囲外の修正や上限は人間待ちにする。host commit後のhookによる変更等で証拠が古くなった場合もready_for_finishにしない。

finish引継ぎはcheckout・base branch・Branch baseline・plan版・台帳・各Taskの範囲・最終証拠・未確認を渡す。既存sdd-finishの全体検証と正本反映確認を満たしたうえで、人間がlocal merge・single PR・branch保持・stacked PRを選ぶ。H4は統合の実行機構を新設せず、既存skillへ引き継ぐ。空のcommit範囲を持つno_change Taskは既存stack-prsの非空範囲要件を満たさないため、stacked PR互換なしと明示する。範囲を捏造せず、finish前にこの制約を提示する。

## Numeric defaults and lifecycle

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

Taskの稼働上限はH2監督分とその完了後のhost処理分の合算とし、H4がcommit・journal照合の消費も保存する。H2 completedを理由にTaskの時計を止めたり、新しい上限を与えたりしない。有限のTask数と各Task上限を開始前に示し、複数Taskと別途承認されたH3 cycleで費用が生じ得ると説明する。NoPriceEstimator等で見積不能な経路は、金額上限付き要求を許可しない。H2の60秒評価timeout・限定retry・閾値とH1の停止猶予を変更しない。

window閉鎖・非選択projectでもhost pumpが進む。quitは新規dispatch・送信・commitを止め、H1/H2/H3と状態を保存する。再起動は承認・Task・journal・予算・停止latchを復元するだけで外部要求を送らない。人間の再開前にGit、未確定操作、現在のplan・spec・権限・同意・残予算を照合する。停止未確認のprocessや結果不明の要求を未実行に戻して再送しない。

## Integration prerequisites and consuming paths

調査起点はherness `b474ecf`。H1/H2受入は未完了で、H3は[2026-11-10のtext-only reduced scope受入](../../research/2026-11-09-h3-acceptance.md)である。既存のH4 owner型・H3 barrierの存在は、H4が実装済みである証拠ではない。

- [H1 H4 integration additions](2026-11-07-h1-runtime-design.md#h4-integration-additions)にhost Gitの承認・監査・停止・結果不明と対象単位の実行分離を追加案として記録する。
- [H2 H4 integration additions](2026-11-08-h2-supervision-design.md#h4-integration-additions)にH4 registry照合、冪等なowner対象作成、検証準備gate、対象別pumpと停止・復旧の追加案を記録する。現在はauthorize_owner_launchがH4ApprovalUnavailableを返し、packet再束縛もH3専用である。
- H3のbarrierと同期状態はH3正本を変更せず消費する。必要集合の発見、実ファイル再照合、Task進行への反映はH4が所有する。現在のgeneric H2 pumpがH3-active project全体を除外する点を補修する。
- `crates/herness-sdd-execute/src/`にimport・approval・coordinator・ledger・git・recovery・ports、storeに既存schemaの次の順序付きmigration、`src-tauri/src/sdd_execute/`にcomposition・Git/pack bridgeと最小IPCを配置する。既存migration・履歴・承認を削除せず、未知形式のDB再作成をしない。
- `tests/sdd-execute/`を新しい契約・横断テストの起点とし、既存`tests/runtime/`・`tests/supervision/`・`tests/html-sync/`を回帰する。H5はversion付きsnapshot・理由・必要操作・証拠・予算・sequenceを使い、独自の成功状態を作らない。
- SDD packでは新schema・plan-inspect・herness実行連携・sdd-plan/execute/implementer/finishのherness差分とテストを追加する。H3 version 1契約へ未知fieldを足さず、独立したversion付きexecution capabilityを定義する。人間のH4 registry承認なしに親dispatch・子commitを置き換えず、hernessで能力不足なら親fallbackを禁止し、他ホストの動作を維持する。

有効なherness実行契約では、既存controllerの未完了Taskに対する一回だけのresume規則を、H2の同じ子・同じ承認範囲での有限継続へ置き換える。BLOCKED・NEEDS_CONTEXT、重要な未合意事項、停滞・上限・復旧待ちから無断で進まない規則は維持する。この差分を他ホストへ適用しない。

packとherness両方の開発変更を必要とするが、このspec保存は別repoの編集許可ではない。実装planで各repoの作業先と先行関係を明示する。H1/H2追加契約もレビューを受け、承認後に計画へ含める。

## Testing and acceptance

1. 新形式の正常系と、旧形式、未知版・field、重複JSON key、偽Task headingを含むfence、欠番・重複・空Task、循環/後方ではない依存、参照不足、path escape・symlinkを実pack parserで検査する。inspectによるファイル変更・モデル要求は0件とする。
2. 取込みだけでは子起動・送信・Git操作0件。偽owner、偽registry、H3承認の流用、古いplan/pack/profile/consent、別project・古いrevision・重複要求からの無断起動0件を確認する。
3. 実Pi＋loopback、実SQLite、実packとH3同期経路を結び、親dispatchなしで2 Task以上が直列に進み、初回・継続へ原文制約とspecが渡る。未達の修正、正当な完了、TaskとH3の同project併進、禁止scopeへの変更0件を確認する。
4. 必須検証fail・不足/古い証拠・虚偽DONE・注入・未停止process・H3未同期/版不一致/依存漏れ・能力不足では次Taskとcommitを拒否する。全体manifestの変更、CSS/resource変更、同じbytesへの復帰も扱う。
5. host commitでTask変更と検証済みcompanion/receiptだけが含まれ、共通Git gateを通る。無関係なdirty/index、hook変更・失敗、HEAD/branch競合、各journal/commit/DB保存境界のfaultを注入し、重複commit0件、完了範囲の改変0件を確認する。no_changeとstacked非互換も表示する。
6. planの本文だけの変更・削除・移動で現在Taskを安全停止する。停止未確認では再開せず、新版承認でも予算を保持する。未着手だけの変更は継承でき、着手済み・完了済みの変更は自動移行しない。
7. 別process復旧、通知欠落、progress出力失敗・改変、window閉鎖・非選択project・quitを実Tauri接続で確認する。復元時の外部要求0件、消費維持、未確定Gitの照合を確認する。
8. 最終Taskのfull-suite失敗・正本未反映・古い証拠ではready_for_finishにしない。正常時は既存ledger/stack preflightとの互換とfinish情報を確認し、選択前のpush・merge・公開0件と他ホストの既存execute/H3回帰を確認する。

通常検証は一時repo・DB・fake credential・loopbackのみで行う。受入記録は実行者、実コマンド、実結果、対象revision、検証範囲と未確認を保持する。新schemaのPythonテスト、Rust workspace fmt/clippy/test/build、実Tauri lifecycle、変更Targetの共通HTML検証を実装planで具体化する。scripted judgeの成功を実モデル品質と混同しない。

実providerでの実装・完了評価・HTML評価の一連の受入は、接続、fixtureと送信bytes種別、有限要求数/retry、料金または枠を提示し、別途人間の許可を得てから行う。H3の画像・残条件、H1/H2接続の未確認は継承し、必要能力を確認できなければ実運用の受入は保留する。限定受入は実行時gateの迂回ではない。

## Open items and approval

未決定の製品動作を実装者へ委ねない。parser schema・host Git・owner/readiness接続は本specと各正本の追加案をレビューしてから実装planに落とす。OS・配布・完成版画面はH5、実provider能力・実接続の受入は有効化前に別途確認する。未確認を理由に条件や送信同意を黙って緩めない。

利用者は、新形式だけの取込み、1リポジトリ、plan変更時の現在Taskの安全停止、hernessによるcommitを選択した。上限継承・台帳・finishまでの設計要約を確認し、「ok」と回答して設計文書の保存を許可した。この記録は保存後のspec・追加契約の承認ではない。文書の検証・設計文書だけのcommit後にレビューを依頼し、明示的な承認後にH4のsdd-planへ進む。

続いて、設計文書commit `2d53146`のH4 specとH1/H2のH4 integration additionsへのレビュー依頼に、利用者が「ok」と回答した。2026-11-13の設計・追加契約の承認として記録し、H4だけの実装planを作成する。H1/H2の受入未完了とH3の限定受入は維持し、本実装・別repo編集・実接続・pushはまだ許可しない。
