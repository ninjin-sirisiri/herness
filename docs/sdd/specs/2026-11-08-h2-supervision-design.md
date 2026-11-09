# H2: 継続実行と完了判定

**Classification:** architectural

**Status:** 2026-11-08に利用者が本specとH1共有契約の追加を承認し、sdd-planを指示した。[H2実装plan](../plans/2026-11-08-h2-supervision.md)を保存済み。本実装・実モデルへの送信は未許可。

**Chosen approach:** 必須検証と安全条件をhostが検査し、モデルによる条件別の評価をhostが統合する。モデルは状態遷移・権限・完了条件を変更しない。

本specは[ロードマップ](2026-11-07-herness-roadmap.md)のH2を扱う。[H1](2026-11-07-h1-runtime-design.md)を実行・権限・保存の正本、[CONTEXT.md](../../../CONTEXT.md)を用語の正本とする。H1は実装済みだが[受入未完了](../../research/2026-11-08-h1-acceptance.md)。H2の設計承認とplan作成の指示は、H1の未確認項目を免除しない。

## Goals and non-goals

- 同じ完了条件を通常LLM・Jev・OpenAI Decisionsで評価でき、未達なら同じ子エージェントの作業を有限の範囲で継続する。
- 必須検証、証拠の適用範囲、停止・人間待ち・予算をモデルより優先し、完了に至らない理由を永続化する。
- H3の品質評価とH4のTask監督が利用する共通契約を提供し、同じモデル接続基盤からH1の許可評価器を提供する。
- SDD planの解釈・Task台帳・Git境界はH4、HTML固有の条件・検証・公開はH3が所有する。H2は既存SDDの再開回数やHTML policyを変更しない。
- 自動push・merge・公開、権限拡大、OS隔離、必須の独立レビュー、Taskの並列化、新規CLI製品は含めない。
- 対象はhostが完了条件・権限・上限を設定して監督する子agentであり、通常チャットや親agentを無条件に繰り返さない。sdd-executeへの組込みはH4が所有する。

## Approach and architecture

比較した案は、採用する「条件別評価をhostで統合」と、「必須検証後に一つの総合質問で判定」の二つ。前者は証拠・未達条件を追跡でき、複数の要因を一問に混ぜないDecisionモデルの利用にも合う。後者は問いをまとめやすいが、情報不足と未達の切分けが弱い。

Rust hostにアプリ寿命のsupervisorを置く。WebViewのpollや選択中のprojectに依存せず、engineイベント・検証・deadlineを処理する。各監督対象は一つの子agentと一連のrunを束ね、H3 jobやH4 TaskのIDを不透明なowner参照として持つ。これらを同じ識別子にしない。

| Component | 責務 |
| --- | --- |
| Supervisor | 承認済み条件、状態遷移、追加実行、停止、排他所有 |
| Evidence service | 検証記録、対象版、証拠の鮮度、必要な範囲の組立て |
| Assessment service | 条件別の問い、応答検証、結果の統合。実行toolを持たない |
| Provider adapters | 通常LLM・Jev・Decisionsの通信、能力・応答の正規化 |
| Budget and disclosure service | 稼働時間・回数・要求予約・使用量・送信同意 |
| Durable supervision store | H1のSQLiteに監督状態・条件・証拠・判定・予算を保存 |

## Shared contract

### Completion contract and operations

監督対象はproject、agent/session、owner参照、条件版、実行範囲、必須検証、条件別rubric、証拠の対象範囲、判定profile版、送信同意版、予算、run群を保持する。IDはproject内で安定し、公開契約はversion付きとする。モデルが作った条件案は人間が開始前に確認する。H3の承認済み設定やH4の承認済みplanから条件を渡す場合、その承認を継承して毎回は確認しない。取込みの正当性は各ownerが保証し、H2が散文を推測して補わない。

| 操作 | 成功・制約 |
| --- | --- |
| 作成・開始 | 条件と承認根拠、能力、許可、送信範囲、有限上限を検査して保存してから実行。初回は子agentを作成できる |
| 取得・購読 | 状態、理由、未達条件、証拠、判定先と版、使用済み・予約済み予算、最終sequenceを返す |
| 一時停止・取消し | 新規要求を止めH1の停止経路を使う。既存変更を巻き戻さず、取消しは履歴を残す |
| 再判定・再開 | 人間の操作。現在の条件・対象・権限・同意を照合し、必要な証拠を取り直す。消費済み予算は維持する |
| 条件・profile・上限の変更 | 人間または承認済みowner操作だけ。停止・版更新後に再確認する。旧判定を失効し、予算の変更前後を残す |

子agentは条件・権限・上限を変更できない。条件や対象版が変わった実行中の判定結果は履歴だけに残し、状態へ適用しない。同じ入力での判定の引き直しを自動で繰り返さない。重複要求IDは同じ結果を返し、追加run・送信・取消しを重複実行しない。

### Evidence and freshness

各証拠はID、取得者、正確なコマンドまたは同等の操作、実際の結果・出力・終了状態、対象の版、検証範囲と限界を持つ。run・操作ID、取得時sequence、truncation、依存する条件・ファイル・設定・依存関係の指紋も記録する。子agent・CI・人間の証拠も同じ要件で再利用し、親が実行していないことだけを理由に再検証しない。

必須検証の結果はpass・fail・not_run・unavailable・inconclusiveを区別する。H1の操作成功は検証成功ではない。shellはexit code・signal・timeout・停止確認を調べ、非zero終了をpassにしない。単なる「成功した」という報告やDONE、commit、idleを証拠の代わりにしない。人間の観測証拠は観測者と対象版を明示し、機械検証と混同しない。

鮮度は経過秒数でなく対象・範囲への適用可能性で決める。HEADやH1 sequenceだけでは、未commit・shell・外部編集を含む作業状態を表せない。ownerが定めたread-set、関連設定・依存関係・条件を内容指紋とmanifestで検証前後・判定前後・完了確定直前に照合する。範囲が不明ならproject全体の入力manifestへ広げるか判定不能とし、根拠なく除外しない。

関連入力が変われば影響する検証と評価だけを失効し、無関係な証拠は保持する。変更中の検証、結果不明の操作、未停止の管理下process、欠けた・省略された必須情報は完了を禁止する。外部編集との完全な同時実行分離は保証せず、完了は記録したsnapshotに対する結果とする。後の関連変更はその適用状態をstaleにし、ownerへ通知する。H2だけで自動再開・公開はしない。

### Model assessment and permission evaluation

完了評価は条件IDごとにmet・unmet・insufficientを問い、必要な証拠だけを渡す。全必須検証が現対象でpassし、必要な条件がすべてmetの場合だけ完了候補となる。決定的な検証だけで証明できる条件にはモデルを強制せず、品質等の意味評価が必要な条件をモデルへ渡す。複数条件の平均点で一つの未達を隠さない。

通常LLMはschema付きの条件別結果と根拠の証拠IDを返す。未知ID、欠落、矛盾、不正schema、拒否、uncertainは判定不能とする。自己申告の数値を校正済み確率として扱わない。Jev・Decisionsはmet・unmet・insufficientのchoiceと全選択肢の確率を使い、選択結果と分布の整合・有限値・範囲・和を検証する。選択されたmetまたはunmetの確率が0.95以上の場合に採用し、それ以外やinsufficientは判定不能にする。providerのconfidenceは確率とは別に保存し、異なるprovider間で同じ尺度と仮定しない。

Decision応答から存在しない文章の理由を作らない。問い・rubric・送信した証拠ID・分布・選択・適用したhost規則を説明可能な記録とする。通常LLMの短い根拠はモデルの説明として区別し、内部思考を要求・保存しない。

操作許可は別の用途・問い・記録とする。H1のFrozenOperation、依頼作業、許可境界、必要な証拠を使い、allow・deny・askを評価する。Decision方式のallow・denyは選択確率0.99以上、それ以外はask。通常LLMはschema・操作との結付け・根拠参照・不確実性の検査を通した明示的なallow・denyだけを採用し、不確実ならask。確率を持たない方式の結果を数値閾値との同等保証として表示しない。

H2は詳細判定を保存してH1の既存PermissionEvaluatorPortへallow・deny・askまたはsanitized errorを返す。H1のdeny・ask・grant上限・最終引数照合・single-use承認を変更しない。完了評価の高い確率を操作許可へ流用しない。証拠内の指示や変更理由は権限の正本ではなく、prompt injectionへの耐性を完全な隔離保証とはしない。

### States and continuation

| 状態 | 意味・次の操作 |
| --- | --- |
| ready | 条件等の承認済み。開始待ち |
| running | 初回または追加の子runを実行中 |
| verifying / assessing | 安定した対象で検証中／条件を評価中 |
| waiting_human | 操作承認、条件判断、送信同意、認証、判定不能等。理由と必要操作を返す |
| stopped | 人間停止、停滞、予算、停止未確認、復旧照合待ち。再開には原因解消が必要 |
| failed / cancelled | 回復不能／明示取消し。完了ではない |
| completed | 記録snapshotで全条件成立。後の関連変更によるstaleを別に保持する |

H1のrun状態とは別に保存する。今回submitした入力の完結と対応が取れたidleだけを検証開始に使い、作成直後のidleや、未解決のtool・背景shellがある状態では判定しない。検証で修正可能なfailが出たら、その不足と証拠を同じ子agentへ返し、同じ条件・許可内で追加runを起動する。未達を直せる範囲で「続けますか」は毎回尋ねない。

追加runでは会話、承認済み条件・制約、未達条件と証拠を維持する。H1の同一runの復旧と区別し、新しいrun IDを持たせる。文脈容量不足を新しい無関係なsessionで黙って補わず、人間待ちにする。BLOCKED・NEEDS_CONTEXT相当の報告は同じ入力で再試行せず、必要な判断や文脈を求める。Task固有の報告契約はH4が解釈する。

1評価サイクルはrunの安定、検証、必要なモデル評価までとする。3回連続の評価サイクルで、関連成果物・未達条件・有効な検証結果・有用な取得証拠に進展がなければstoppedとする。ログの時刻・応答文言・tool回数だけの変化は進展と数えない。調査で得た新しい関連証拠は進展に含め、file編集の有無だけで決めない。進展を確認できなければ安全側へ停止し、人間が根拠を追加して再開できる。

停止・人間待ち・上限・回復不能は完了判定より優先する。停止未確認の間は次runや再判定を開始しない。アプリ再起動は状態を復元するだけで実行・送信せず、照合と人間の再開操作を必要とする。進行中だった判定は適用せず、遅延応答も古いattemptとして無視する。取消し・停止はundoではなく、既存成果物や履歴を削除しない。

### Profiles, providers and disclosure

実行モデルと判定モデルは独立に選ぶ。完了評価・HTML評価・操作許可の用途別profileをprojectに設定し、監督開始時に版を固定する。未設定のprofileを実行モデルで黙って代用しない。利用不可の接続や未対応の画像入力を成功扱いにせず、別モデルへ自動切替しない。

通常LLMはH1の接続・認証境界を再利用するが、評価専用のtoolなし要求を使い、通常の作業agentをjudgeとして起動しない。JevはAPIキーでPOST /v1/systemone、DecisionsはOpenAI APIキーでPOST /v1/decisionsへ接続する。2026-11-08確認の基準はJevの固定ID jev-1.14.0とDecisionsのgpt-6-luna。ChatGPTログインをDecisionsのAPI認可として流用しない。model alias・返却された実model ID・adapter/rubric版を記録し、モデル更新時は評価をやり直す。

Jevは直接のTypeSafe接続に加え、利用者が明示選択したCommand Code Provider API gateway（assessment-only、固定`typesafe/jev-1.14.0`）でも利用できる。gatewayは暗黙のfallbackではなく、connection設定・origin・consent・budget・固定modelを別に検証し、agent実行や他providerへの切替には使わない。gatewayの選択・verificationは信頼された人間UIだけが行う。

接続資格情報はH1と同じKeychain境界に置き、判定入力・DB・イベントへ入れない。送信同意はproject・接続先origin・用途・データ種別・対象範囲の版へ結び付け、初回の人間承認後は同じ範囲内で継続する。別provider、scope拡大、画像追加、同意取消しでは未送信要求を止め再確認する。取消しは既に送信した内容を取り消さない。

入力は必要な原文・コード・差分・ログ・画像に限定し、全会話・全repositoryを既定送信しない。秘密情報の除外を行うが、任意の秘密を完全検出できるとは保証しない。除外や容量制限で必要な情報を欠いた場合はinsufficientとする。画像は承認範囲のbytesを送り、任意の外部URLや資格情報付きURLをproviderに取得させない。対象HTMLの撮影・情報保持のrubricはH3が所有する。

## Budgets and request failures

初期上限は監督対象1件につき累積稼働2時間・追加実行30回。初回を含むrun数は最大31であり、追加runの起動意図を保存した時点で回数を消費する。実行・検証・評価・許可判定・同じ接続への再試行待機を合算し、人間待ち・明示一時停止・アプリ停止中は除く。再開で消費量をリセットしない。経過時間はmonotonic clockと永続化した区間で計測し、クラッシュ時の未確定区間は保守的に計上する。

金額上限は任意。指定時は実行・検証に伴うモデル要求・完了評価・許可評価の費用を同じ予算へ合算し、並行要求は送信前に上限見積りを予約する。価格版・入力上限・最大出力・料金条件が不明なら送信しない。ChatGPTログイン等の金額見積不能な経路は金額上限付きでは利用不可。使用量欠落・timeout後の課金不明は予約を解放せず照合待ちにする。金額はローカル見積りで、外部請求の厳密な上限保証ではない。

deadlineは長い単発runにも適用し、到達したら新規tool・要求を止めH1へ協調停止する。既に送信済みの要求の課金や既存変更の巻戻しは保証しない。停止猶予はH1の規則に従う。予算到達後に届いた成功をcompletedへ採用しない。共有のproject予算は初期要件にせず、H3・H4が生成する各監督対象にも有限の上限を適用する。

評価要求の429・一時的な5xx・接続前の一時障害だけ、同じ接続で最大2回追加再試行する。待機は1秒・2秒を基準にjitterを加え、Retry-Afterが残りdeadlineに収まらなければ確認待ちにする。送信済みか不明なtimeout、不正応答、低確度、拒否、認証失敗は自動で引き直さない。実行モデル要求・副作用を伴うtoolにはこの再試行規則を流用しない。SDKの隠れた再試行は無効にする。

## H1 integration prerequisites

現在のmain 225ff5dを調査した結果であり、H1の保証が検証済みという意味ではない。次をH1所有の実行境界で満たす必要がある。H2の実装planは前提の補修と追加契約を明示し、H1の正本を先に整合させる。今回コードは変更しない。

| 必要な保証 | 現状と解消条件 |
| --- | --- |
| 同じ会話での追加run、submitとidleの対応 | Piはrunごとに新しいruntimeを作り、起動時idleを先に通知する。SDK型を漏らさない継続・入力識別境界と実adapterテストが必要 |
| 復旧と未確定操作の照合 | 同一process再開と未完了応答の復元には制約がある。再実行せず照合し、利用不能なら再開不可を返す |
| 実toolへのgrant・評価器の引継ぎ | Pi内の許可経路は評価器なし・再構成したgrantで動く。hostの制限と評価器を唯一の実行経路へ適用し、二重実行を防ぐ |
| 使用量・要求状態・停止deadline | H1公開eventにusageはない。SDK checkpointをH2が解析せず、要求ID・使用量・終了状態をhost型で取得する追加契約が必要 |
| UIから独立した監視 | 現在のイベント処理はUIのproject pollに依存する。host所有の監視へ接続し、閉じたwindowや非選択projectでも進める |
| 永続化・イベント | H2状態と通知をtransaction化する。run作成前の監督イベントに架空のrun IDを与えず、project sequenceを共有するH1のenvelope拡張が必要 |

H1のOpenAI・Anthropic APIキー経路は受入未確認のまま保持する。H1全体が受入済みと偽らず、H2も各接続のmock・実接続・未確認を区別する。

## Data flow and ordering

1. ownerまたは人間が条件・証拠範囲・profile・上限を確定し、hostが承認・能力・同意を検査する。
2. 監督対象と初回要求の意図を保存し、H1を通じて親の会話から独立した子agentを開始する。
3. 対応する実行の安定を待ち、対象版を採取して必須検証を実行または再利用する。検証コマンドもH1の権限境界を通す。
4. 修正可能なfailは未達として継続し、機構不足・結果不明・人間判断が必要なら待機または停止する。
5. 必要なモデル評価の入力を固定し、同意・予算予約を保存してから送信する。全回答が揃うまで成功にしない。
6. 条件・対象・許可・同意・予算・停止状態を再照合し、証拠と状態を保存してから通知する。完了には完了snapshotを含める。
7. 未達は不足を子agentへ渡して追加runへ進み、completedはownerへ返す。次Task・HTML反映・公開の許可には変換しない。

監督対象ごとに一つのcontrollerだけが遷移を確定し、revisionの比較更新で重複イベント・遅延結果を排除する。復旧時は未完了の要求意図を未送信と決め付けず、手動再開前に照合する。

## Numeric defaults

| 項目 | 初期値・意味 |
| --- | --- |
| 稼働上限・追加run | 7,200秒・30回。人間待ち等を除き、初回runと検証・判定も時間へ含める |
| 停滞 | 3連続評価サイクルで進展を確認できなければ停止 |
| 金額上限 | 既定なし。指定時は有限のUSD額と価格版、全モデル要求の見積りを必要とする |
| 評価timeout | 1要求60秒または残り稼働時間の短い方。許可評価器も適用し、永久に呼出しを占有させない |
| 一時障害の追加再試行 | 最大2回、待機基準1秒・2秒。各要求は予算内、別モデルfallbackなし |
| Decisionの採用確率 | 完了条件のmet・unmetは0.95以上、操作allow・denyは0.99以上。insufficient・askは実行／完了の根拠にしない |
| 分布の許容誤差 | 確率は有限で0〜1、選択肢が完全一致し合計の1からの誤差0.001以内。無断で補正しない |
| 初期profile | 未設定は利用不可。判定providerと送信同意を人間が選ぶ |

閾値は安全性・正答率の保証ではなく、評価前の保守的な設計初期値。provider・model・用途ごとの評価セットで妥当性を確認する。通常LLMには同じ確率閾値を捏造しない。閾値を下げる変更はprofile版更新と人間の再確認を必要とする。

## Testing and acceptance

- **契約と遷移:** 同じ条件を三方式へ渡す。必須fail・未実行・証拠不足・停止・人間待ち・上限で、モデルがmetを返しても完了しない。開始直後idle、重複・遅延応答、版変更を検証する。
- **証拠:** SDDの取得者・操作・実結果・対象・範囲を保つ再利用、関連変更だけの失効、未commit・外部／shell変更、検証途中の変更、truncation、非zero shellをテストする。
- **実adapter統合:** 実Pi＋loopback modelで初回と追加runの会話・制約保持、子grantと自動評価器、明示deny・ask、停止・復旧照合を確認する。service mockだけで実tool経路の成功としない。
- **予算とlifecycle:** fake clockとfault injectionで長い単発runのdeadline、30回制限、同時予約、費用不明、再起動時送信0、再開時の消費維持、停止未確認をテストする。実Tauriでwindowなし・非選択projectの継続も確認する。
- **provider契約:** 三方式の正常・拒否・不正schema・欠落／重複回答・未知ID・不正分布・低確度・429・5xx・timeout・auth失敗をmockで検証する。Jevの応答をDecisionsのschemaとして扱わない。
- **送信と権限:** 同意取消し・origin／用途／画像追加・秘密canary・入力中の偽指示・判断中の最終引数変更・予算切れで実行を許可しない。judgeがtoolを実行できないことを確認する。
- **評価セット:** 完了・未達・証拠不足、古い成功、虚偽DONE、範囲外操作、紛らわしい変更理由、指示注入を含める。必須の負例では誤完了・誤allowを一つも許さず、保留率と誤停止も記録する。これは未知の入力で誤りがないという保証ではない。
- **実接続:** 利用者が別途許可した合成証拠・有限の要求数と料金で、通常LLM・Jev・Decisionsの各経路を確認する。無許可のlogin・有料要求はしない。許可がない経路は未確認で、mock成功を実接続の受入へ流用しない。

H2受入には上記の自動検証、H1前提の実adapter検証、許可済み実接続の証跡が必要。未確認経路を免除するには人間と受入範囲を再合意し、それまでは全体の完成を主張しない。H3のHTML品質やH4のplan取込みそのものはH2受入に含めず、owner fixtureで共通契約を確認する。

## Consuming paths and references

- 提案配置はcrates/herness-supervision/に共通監督・証拠・判定、crates/herness-assessment/にtoolなしprovider adapter。H1のcore・engine-pi・storeとsrc-tauriが接続する。tests/supervision/で契約を検証する。これらの新規crateはまだ存在しない。
- H3は条件・原文版・画像等の証拠・公開前の再照合を渡し、H4は承認済み条件・制約・Task対応と順序を所有する。H5はこのspecの状態・理由・証拠・再開操作を使い、UI独自の成功を作らない。
- SDD正本は../sdd/skills/verification-before-completion/SKILL.md、sdd-goal、sdd-executeとそのimplementer-prompt。五項目の証拠契約を再利用する。H3・H4のhost差分が未承認の間は既存packの動作を置き換えない。
- 2026-11-08に[Jev API](https://docs.typesafe.ai/api/system-one.md)、[models](https://docs.typesafe.ai/models.md)、[confidence](https://docs.typesafe.ai/confidence.md)、[既知の弱点](https://docs.typesafe.ai/model-jaggedness.md)、[Decisions guide](https://developers.openai.com/api/docs/guides/decisions)、[API reference](https://developers.openai.com/api/reference/resources/decisions/methods/create)を確認した。文書の取得は実モデル検証ではない。

## Open items and approval

H1境界の補修・追加APIとmigrationはH1正本のH2 integration additionsへ反映し、利用者が共有契約の変更としてレビュー・承認した。H2の実装planはこの補修・拡張を先行Taskとして含める。H1受入の未確認経路は未確認のまま追跡する。モデル別の閾値検証・通常LLMの対応能力・画像上限は接続を有効にする前に検証し、満たさないprofileは利用不可とする。これらを黙ったfallbackや成功扱いで埋めない。

面談で合意したのは、条件案の事前確認と承認継承、累積稼働2時間・追加30回、金額上限は任意、範囲承認後の継続送信、判定不能後は人間が再開、条件別評価をhostが統合する構成。停滞・timeout・確率等の数値と残る詳細はこの設計案でレビューする。本specの保存・commitは設計の承認ではなく、本実装や実接続を開始しない。

2026-11-08、利用者が子agent共通の継続機構とsdd-executeへの組込みの区別を確認した後、「ok、sdd-planに進んで」と指示し、本specを承認した。plan作成前のH1共有契約は、H1正本のH2 integration additionsへ追加案として反映した。追加案の承認は別途記録し、本実装・実接続の許可とは区別する。

続いて利用者がH1の追加契約を承認したため、plan作成前の共有契約レビューは完了した。実装時の前提補修と未確認経路の検証が完了したという意味ではない。
