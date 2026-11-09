# H3: HTML companionの自動更新と視覚的再構成

**Classification:** architectural

**Status:** 2026-11-09、利用者が本specとH1/H2のH3 integration additionsを承認し、[H3実装plan](../plans/2026-11-09-h3-html-sync.md)を保存済み。設計承認は本実装・追加の実モデル送信・pushの許可ではない。

**Chosen approach:** Rust hostによる変更イベント監視と定期照合、候補領域でのagent著作、SDD共通検証とH2評価、履歴を残すhost反映を組み合わせる。

本specは[ロードマップ](2026-11-07-herness-roadmap.md)のH3だけを扱う。実行・許可・保存は[H1](2026-11-07-h1-runtime-design.md)、監督・判定・送信は[H2](2026-11-08-h2-supervision-design.md)、用語は[CONTEXT.md](../../../CONTEXT.md)を正本とする。H1/H2の実装はmainへ統合済みだが、[H1受入](../../research/2026-11-08-h1-acceptance.md)・[H2受入](../../research/2026-11-08-h2-acceptance.md)は未完了であり、本specで免除しない。

## Goals and non-goals

- Target Markdownの内部編集・shell経由の編集・外部編集から、親モデルのdispatchなしでHTML用agentを起動する。
- 全文情報と意味を保持し、本文の言い換え、順序変更、根拠のある図解・グラフ、補助的な要約を認める。逐語一致だけを完成条件にしない。
- 最新の原文、候補、依存入力に対して検証・評価できた成果物だけを反映し、同期状態・競合・停止理由・証拠を後続phaseへ提供する。
- Markdown正本、Targetの範囲、正確なbytesのdigest、静的な安全性、共通validatorを維持する。他ホストの標準動作を変えない。
- Markdownの自動修正、機械的なMarkdown-to-HTML renderer、文書削除・移動の代行、Git操作、Task全体の完了判定、完成版preview UIは含めない。
- 意味保持・認知負荷の軽減を数学的に証明すること、モデルの誤判定をなくすこと、外部processとの完全な同時実行分離は保証しない。

## Approach and components

比較した方式は、採用する「変更イベント＋定期照合」と「定期的な全Target走査だけ」。後者は構成が単純だが変更への反応が走査間隔に依存する。前者でも通知を事実そのものとせず、内容を読み直して取りこぼし・重複・atomic saveを照合する。

| Component | 責務 |
| --- | --- |
| Target observer | 共通policyによるTarget解決、H1通知とfilesystem変更の取込み、定期照合、依存入力の失効 |
| Sync coordinator | 設定承認、文書ごとの直列化、世代・停止latch・予算cycle、H2のowner、永続状態 |
| Authoring workspace | 不変snapshotと制限された候補領域。agentに正式なMarkdown・HTML・CSSへの書込み権限を与えない |
| Common policy bridge | SDDのbootstrap、候補検証、対応表・図の根拠・receiptの静的検査。独自validatorで代用しない |
| Evidence builder | 原文・HTML・対応表・検証結果・render証拠を、条件別の入力としてH2へ渡す |
| Publisher and history | 版照合、旧版の保存、候補と評価receiptの反映、結果不明の照合、明示的な復元 |

処理の所有者はアプリ寿命のRust hostとする。windowの有無、選択中のproject、WebViewのpollを進行条件にしない。H3のjob、世代、H2監督対象、agent/session、run、反映要求は別の識別子とする。

## Shared contract for H4 and H5

### Configuration and authorization

有効化はproject単位の人間操作とする。Target集合、著作接続とmodel、HTML評価profile・rubric、送信先とデータ種別・範囲、必須検証、上限、候補の自動反映と旧版保存を設定版へ束ねて承認する。新しいTargetが同じ承認済み集合へ加わる場合は個別承認を繰り返さない。scope拡大、接続先・profile・rubric・policy契約の変更は再確認する。

未承認projectを開いたときは状態の走査だけを行い、agent起動・外部送信・HTML変更を行わない。有効化時には既存の未同期Targetと不足companionを示し、その範囲の処理も承認に含める。既存Targetのcompanion不足は共通bootstrapを明示的に呼び、対象・結果を記録してから候補を著作する。metadata不正をbootstrap不足と偽って修復しない。

H3設定は信頼された人間UIで変更し、agent・生成HTML・repo内のreceiptを承認主体にしない。H2へ渡す継承承認は、実在する設定版とjobにhost内部で結び付ける。未検証profileや不足する能力を実行モデル・別providerで代用しない。

### Identity, state and operations

文書キーはproject IDと共通resolverの正規Target相対パス。原文版は正確なMarkdown bytesのSHA-256とし、観測ごとの単調増加revisionも持つ。同じ内容へ戻る変更でもrevisionは戻さない。設定、policy、CSS、参照resource、候補と対応表、評価証拠の指紋を別に保持する。

| H3状態 | 意味 |
| --- | --- |
| disabled | 未承認または明示無効。走査だけで送信しない |
| pending | 未同期、編集の収束または実行枠を待つ |
| authoring / verifying / assessing | 候補の著作／共通・render検証／H2評価中 |
| ready_to_publish / publishing | 全条件成立候補／版照合と履歴保存を伴う反映中 |
| synced | 記録した原文・HTML・依存入力のsnapshotで反映まで成立 |
| waiting_human | 外部HTML競合、判定不能、権限・認証・能力不足等。必要操作を返す |
| stopped / failed / cancelled | 停止・上限・停滞／回復不能／明示取消し。同期成功ではない |
| orphaned | Markdownが存在しない旧成果物。HTMLは残し、同期成功とはしない |

世代にはsupersededの履歴も持たせる。過去世代の完了と、現在の文書がsyncedかどうかは別に返す。原文・依存入力・HTMLの後続変更で、過去の成功記録を消さず現在への適用を失効する。

操作は設定・有効化、一覧・取得・購読、一時停止・取消し、人間による再開・再評価・再生成、競合解消、履歴取得・復元を提供する。公開応答はversion付きで、project・文書キー・job/cycle・世代・原文digest・設定版・状態と理由・必要操作・H2参照・証拠参照・現在への適用可否・最終project sequenceを含める。重複request IDは保存済み結果を返し、実行・送信・反映を増やさない。古いrevisionへの更新は副作用前に競合を返す。

H4は、要求した文書版と依存入力が現在もsyncedであることを完了barrierとして照合する。H3の失敗はMarkdown編集や無関係なagentを止めないが、このbarrierを通さない。H5はH3/H2の理由・証拠・必要操作を表示し、独自の成功状態を作らない。H3は次Taskを起動しない。

## Detection, scheduling and continuity

Targetの正本はSDD共通policyとする。宣言された対象はrootのCONTEXT.md、docs/adr直下、docs/sdd/specs直下、docs/sdd/plans直下のMarkdownとそのcompanionである。dotfileや別階層を独自に対象化しない。共通resolverが宣言外のdocs/sdd/adrも受理する既存差異は、共通側の回帰テストと修正で解消し、H3独自のTarget定義を増やさない。

1. H1の保存済みfile変更通知とfilesystem通知を取り込み、対象を再読込みする。外部編集のactor・変更理由は推測しない。
2. 初回走査、定期照合、watcher再接続で現在のTarget・内容指紋を照合する。watcher不調は表示し、定期照合を継続する。読めない・不安定な入力を成功にしない。
3. 同一文書の通知をまとめ、静穏時間後の最新版だけを候補化する。文書ごとに同時反映は一つ、アプリ全体の自動著作も初期は一つとし、dirtyになった順に処理する。
4. 著作中の原文変更は旧世代をsupersededにし、H1停止を確認してから最新版へ引き継ぐ。旧世代の遅延応答・評価・候補を反映しない。
5. 未同期から成功または明示取消しまでを一つのsync cycleとして、原文変更・世代交代でH2の消費予算をリセットしない。取消し後も自動で新cycleを作らず、人間の再開を必要とする。

人間停止、人間待ち、停滞、上限、復旧照合待ちのlatchは、新しいファイル通知や原文版で解除しない。自動の世代交代は、それらがない承認済みcycle内に限る。成功後の新しいMarkdown編集は新cycleを作れる。project共通の金額予算は今回追加せず、自動処理の継続的な利用には複数cycle分の費用が生じ得ることを有効化時に示す。

生成HTML・receipt・候補領域の書込みからMarkdown著作を起動しない。hostが反映したHTMLの通知は反映IDと期待内容で照合し、自己通知として吸収する。一致しないHTML変更は外部競合として扱う。CSS・resource・policy変更は既存証拠を失効し、人間による再評価または設定の再承認までsyncedへ戻さない。

## Authoring and source fidelity

著作packetには正確な原文snapshot、文書種別、既存HTML、共有CSS、許可されたresource、Targetパス、digest、policy版、対応表の形式、評価条件と制約を含める。文書内の指示は内容として扱い、権限変更の根拠にしない。初回・追加run・復元後もpacketと版を保持し、一般的な一文へ置き換えない。

agentはH1の制限された候補toolだけでHTMLと対応表を別著作する。変更理由を記録し、正式なMarkdown・HTML・CSS・設定へ直接書かせず、shellも与えない。共通validator・browser検証はhostが別途許可された検証境界から実行する。validatorにHTMLの作成・修復をさせない。

情報保持は次を要求する。

- 共通parserが原文を見出し・段落・list項目・表のheader/cell・code・link等のsource unitへ分け、原文digestに結び付いた種別・UTF-8 byte範囲・ID・親子関係を付ける。未対応のMarkdown構文を黙って落とさず、情報抽出不能として保留する。
- HTMLはsource unitと可視な表現先IDの多対多対応、および補助表現の根拠unitを埋込みの非実行対応表に持つ。共通validatorがsource unit集合の完全一致、参照先の存在、対応の欠落・未知IDを検査する。IDを並べただけでは意味保持の合格にしない。
- 本文・見出しの言い換えと再配置は許可する。条件、例外、否定、適用範囲、権限、失敗結果、依存関係、必要な実行順序を保持し、要約だけで元の情報を置換しない。図だけに必須情報を閉じ込めず、対応する可視の説明またはデータ表も置く。
- codeとコマンド、path、識別子、用語集の正規名・Avoid、link先は正確に保持する。codeの改行表現だけはLFへ正規化できる。数値・単位・比較演算・閾値の対応を検査し、単位変換等は入力・式・結果を追跡可能にする。hostの制限された計算で検算できない新しい計算値は採用しない。
- 原文見出しへの既存fragment IDは対応箇所に保持する。表示用見出しの階層は意味に沿って再構成できるが、DOMの読書順と見た目・keyboard順を一致させる。planのTask番号と論理的実行順、ADRの判断、用語と定義の対応を変えない。
- hidden、aria-hidden、表示されないtemplateや付録に情報を詰めただけでは可視情報保持としない。対応表自体は本文の代わりにならない。全文の原文併記は必須にせず、言い換え後の内容を評価する。

## Diagrams, rendering and assessment

図解・グラフは静的HTMLまたは安全なSVG部分集合で表現する。script、イベント属性、foreignObject、外部参照、実行時描画、アニメーション、任意の埋込みHTMLは許可しない。SVGの要素・属性・参照を共通policyのallowlistで検査する。文書固有のinline CSS・追加stylesheetは導入せず、共有CSSのclassを使う。既存の安全な原文画像も依存manifestへ含める。

図のnode・edge・label、グラフの値・単位・系列・軸は根拠unitに結び付ける。根拠のない因果・依存・時系列・数値・進捗を追加しない。caption、テキストによる同等説明、データ表を備え、色だけで意味を表さない。

静的検証の合格後、権限とnetworkを持たない隔離された文書閲覧環境で実際にrenderする。アプリのprivileged DOMへ挿入せず、Tauri IPCを公開しない。許可済みのローカルresourceと共有CSSだけを読み、request遮断、DOM・accessibility tree・layout指標・viewport・browser版・画像の指紋を証拠にする。主要領域・headingの区別、overflow、重なり、読めない文字、outline・keyboard移動、図のラベルと表を検査する。撮影は生成済み候補の表示であり、画像生成ではない。

H2にはpurpose=Htmlを使い、条件別に次を評価させる。全条件met、全必須検証pass、現在への証拠適用が揃うまで反映しない。

1. 各source unitの情報・条件・例外が対応箇所に残り、文書全体でも矛盾・意味変更がない。
2. 要約・図・グラフの主張が根拠に支持され、補助表現と正本由来の情報を混同しない。
3. 再構成によって目的・判断・制約・操作を探しやすく、情報を隠しただけの短縮や過度な装飾になっていない。
4. 実renderの証拠から、階層・読み順・文字・表・図を利用可能と判断できる。

評価入力はsource unitごとの全文と関連文脈、対応するHTMLの可視内容、対応表、図の根拠、検証・render証拠に限定する。分割評価でも全unitの評価coverageと文書全体の整合評価を要求し、省略や容量超過をmetにしない。画像が必要な条件には承認済み画像bytesを渡す。text・構造指標だけで判断できない条件をtext-only profileで合格にせず、画像能力・同意がなければ保留する。

通常LLM・Jev・DecisionsはH2の同じ条件契約を使う。確率・採用規則・失敗時の扱いをH3で緩めない。判定不能は人間待ち、修正可能なunmetは同じ子agentへの有限継続とする。実モデル・画像能力の確認は別途許可を得た評価セットで行い、mockを実確認へ流用しない。

## Common SDD policy and offline evidence

変更先の正本はpack全体の../sddである。H3のplanは、README、HTML正本spec、必要なADRの整合、共通policy/CLI・Git gate・CI・テスト、herness向け連携定義と条件付きskill指示を含める。既存hostへ自動著作を一律適用しない。新しいADRが必要なら、そのpackで合意してから保存する。

標準のstrict契約は維持する。再構成された文書はHTML headのmetaでname=sdd-html-contract、content=semantic-v1を明示し、共通validatorがその契約を検査する。未知の契約は拒否する。このモードを理解しない古いpackでは利用不可とし、strict検査の黙った迂回を行わない。本設計文書自体には、実装前の既存strict契約を適用する。

対応表はHTML内のtemplate#sdd-provenanceにJSONとして埋め込み、実行しない。source digest、unit定義、可視表現先、補助表現と根拠、計算の入力・式・結果を持つ。共通parser・schemaを正本とし、H3で別のsource分解を実装しない。

評価receiptはdocs/sdd/html-evidence以下に置くJSONの補助成果物とし、Target Markdownの種類は増やさない。ファイル名は正規Target相対パスのUTF-8 bytesのSHA-256に.jsonを付ける。sourceパス・digest、完全なHTML bytesのdigest、CSS/resource/policyの指紋、設定・rubric・profile版、世代とH2参照、検証結果と条件別判定・証拠参照を持つ。receipt自身のhashをHTMLへ埋める循環参照は作らない。秘密情報、内部思考、資格情報、生のprovider errorは含めない。

CIはnetworkもagentも使わず、静的安全性、digest、対応表の構造とcoverage、厳密保持対象、図の根拠構造、receiptと成果物・policyの結付きを検査する。意味や画像品質を独立再評価したとは表示しない。receiptは署名付き証明ではなく、悪意ある全面的な捏造への耐性を保証しない。H3はrepo内のreceiptだけを信頼してsyncedにせず、自身の保存済み評価・承認と照合するか新たに評価する。

semantic-v1では、承認済みcycle内の候補修正、および人間が指示した同一原文の再生成・競合解消・復元を明示的に扱う。原文変更を偽造して既存のHTML-only gateを抜けない。Git/CIも同一原文に対する正当な再評価と新しいreceiptの整合を検査できるようにする。strict文書の編集順序・同一digest時の制限は変えない。Markdown削除後に旧HTMLを残す選択はGit gateの免除ではなく、commit時の孤立成果物の整理は利用者が別途行う。

## Publication, conflicts and recovery

反映は次の順序とする。

1. 共通検証・H2評価・render証拠を、固定された候補bytesとread-setへ結び付ける。H2評価後にhostがreceiptを作成し、正式相対パスに見立てた候補一式へ共通policyの最終検証を行う。候補段階の検査を最終検証の代わりにしない。
2. 原文revision/digest、設定・policy・CSS/resource、正式HTMLの期待版または不存在、停止・同意・予算を再照合する。
3. 反映要求ID、意図、旧HTMLと旧receipt、前後の内容指紋を永続化する。旧版保存に失敗したら置換しない。
4. 正式なパスのroot・symlink・版をH1で再検査し、同一filesystemの一時ファイルから置換する。HTMLとreceiptの複数ファイル反映を単一のfilesystem transactionとは主張せず、journalで途中状態を照合する。
5. 実ファイルを再読込みし、原文・依存入力も再照合する。結果と現在への適用を保存してからproject sequence付きでsyncedを通知する。

外部processは最終照合と置換の間にも変更できる。これをOS lockで完全排除する保証はしない。検知した競合では上書きせず、反映後の不一致・保存失敗・中断では結果不明として照合待ちにする。未検証候補で旧成果物を置換しない。現在の外部変更を巻き戻す自動rollbackは行わない。

外部HTML編集は実行中・待機中・synced後のいずれでも確認待ちにする。人間は現在のHTMLを検証・評価して採用するか、履歴を残して再生成版へ置換するかを選ぶ。同じsource digestが書かれていても無条件採用しない。既存metadataが不正な場合も、明示的な競合解消なしに上書きしない。

Markdown削除・移動では旧jobを停止し、旧HTML・receiptを残してorphanedと残存パスを通知する。移動は旧パスの削除と新Targetの追加として扱い、新パスへの著作権限は既存の設定scopeに従う。旧HTMLの自動移動・削除、Git操作、削除のundo機能は追加しない。

取消しは新規処理を止めるだけで、反映済み成果物を巻き戻さない。反映後の復元は人間が対象の履歴版を指定する別操作とし、現在版の照合と退避を行ってから戻す。Markdownは変更せず、復元直後は未同期とし、自動再生成で直ちに復元を打ち消さない。復元失敗・重複要求も反映と同じ照合・冪等規則に従う。

アプリ終了はH1/H2の停止・保存規則へ従う。再起動はjob・latch・使用済み予算・反映journalを復元し、送信や著作を自動再開しない。人間の再開前に原文・候補・正式HTML・receipt・未確定反映を照合する。window閉鎖だけでは処理を止めない。

## Numeric defaults and limits

| 項目 | 初期値・規則 |
| --- | --- |
| 変更の静穏時間 | 750 ms。編集継続中はpendingを表示し、安定した版を待つ |
| 定期照合 | 開いているprojectを5秒間隔、および初回・watcher復旧時に照合 |
| 自動著作の同時数 | アプリ全体で1。文書ごとの候補反映も1 |
| cycle上限 | H2の累積7,200秒・追加run30回・3回連続停滞。世代交代・再開で消費を消さない |
| 金額上限 | H2と同じく任意。見積不能時に上限付き送信を許可しない。未実装の価格推定を補ったとは扱わない |
| Markdown / 候補HTML | 2 MiB / 8 MiBまで。超過は能力不足として保留し、切り捨てない |
| SVG複雑度 | 1文書合計5,000要素まで。超過は失敗として簡素化を求める |
| render検証のviewport | 1,280×800と390×844 CSS px、light/dark、200%拡大を検査。browser版も記録 |
| render timeout | 1候補30秒または残りcycle時間の短い方。未完了の撮影をpassにしない |
| モデル要求 | H2の60秒timeout、同一接続の限定retry、met/unmetの0.95採用規則を維持 |
| 旧版履歴 | H3から自動削除しない。容量不足は反映前に保留し、黙って履歴を間引かない |

上限は軽さの実測保証ではない。入力・画像はさらに選択profileの容量上限と送信同意に従う。検証の時間もH2の稼働時間に算入する。

## Integration prerequisites and consuming paths

設計時HEADは7a1500b。H2実装が存在することと、H3でそのまま利用できることを区別する。

- H1正本のH3 integration additionsに、job候補だけを編集する境界とhost反映・履歴・照合の追加案を記録する。既存native file toolのroot検証を無効にしない。
- H2正本のH3 integration additionsに、packet保持、ExecutionScopeを実grantへ適用、承認済みowner起動、purpose=Html、HTML証拠入力、世代交代時の予算・停止latch保持を記録する。現行adapterのCompletion専用制限を、purpose偽装で回避しない。
- 現在のowner通知はメモリqueueなので、H3はDBの監督状態からも回復する。H3状態・反映意図・projectイベントを永続化し、通知だけで状態を確定しない。
- 配置はcrates/herness-html-syncに同期・候補・反映、既存core/storeに必要な境界とtransactional migration、supervision/assessmentに正本追加、src-tauriにアプリ寿命のcompositionと最小操作接続、tests/html-syncに統合テストを予定する。新規crateは未作成。
- ../sdd/scripts/sddlib/html_policy.pyとhtml_docs.py、共通テスト、READMEと連携指示を更新する。parser・schema・CLI・Git gateの仕様は同じpackを正本とする。packの読込み許可を他repoへの書込み許可と混同せず、plan実行時にhernessとpack両方の作業範囲を明示する。

## Testing and acceptance

- **検知:** native tool、shell、外部editor、atomic save、連続変更、重複・欠落通知、watcher障害・復旧、複数project、symlink escape、Target階層、初回bootstrapを検証する。親モデルのdispatchなしで起動することを実Pi＋loopbackで確認する。
- **scopeとpacket:** 実agentが原文・正式HTML・CSS・設定を変更できず、候補だけを変更できること、shell拒否、変更理由、初回・追加run・復元後の指示保持を実tool経路で確認する。
- **鮮度と上限:** 著作中・検証中・評価中・反映直前の原文変更、同じbytesへ戻る変更、CSS/resource変更、遅延応答、世代交代での予算維持、停止latch、自己通知ループ、request重複を検証する。
- **情報保持:** 言い換え・順序変更・正しい要約・図解・グラフの正例と、但し書き欠落、否定反転、閾値変更、権限拡大、code/path/link変更、根拠のないedge・数値、対応表だけのcoverage、隠し本文、未対応構文を含む負例を作る。
- **安全性と閲覧:** 危険なHTML/SVG、外部通信、IPC試行、inline CSS、巨大入力、overflow・重なり、dark/狭幅/拡大、keyboard、図の説明不足を検査する。静的検査を通る意味改変も別評価の負例にする。
- **反映と復旧:** 旧版保存失敗、各ファイル反映途中・DB保存途中のfault、外部HTML競合、取消し、二重反映、復元、Markdown削除・移動、window閉鎖、quit・再起動時送信0を確認する。履歴や他者の編集を自動削除しない。
- **共通契約:** strictの既存回帰、semantic-v1のCLI・index/PR検証、receipt欠落・不一致・未知版、HTML-only再評価、他ホストの既存動作維持、networkなしCIを確認する。receiptの構造合格をモデル精度の証拠にしない。
- **品質受入:** 用語集・ADR・spec・planの代表文書で全文情報と意味を確認し、同じ情報を探す読解課題で原文順の手著作baselineと比較する。観測者・文書版・誤答・所要時間・困難点を記録し、少なくとも必須条件・例外を取り違えず、利用者が理解を助ける表現と確認できることを必要とする。装飾の好みを設計面談だけで決着させない。
- **実モデル:** 通常LLM・Jev・Decisionsを同じ評価セットで確認する。画像条件は対応能力と許可のある接続で確認し、不足経路は未確認のまま残す。負例の誤同期は受入不可とし、保留率・誤停止も記録する。合成token条件の成功だけで実文書の意味評価を受け入れない。

H3の受入には自動検証、実adapter・実Tauriのlifecycle、代表文書の人間観測、許可された実モデル評価が必要。未確認経路やH1/H2前提を免除する場合は別途人間と受入範囲を合意し、それまでH3全体の完成を主張しない。

## Open items and approval

面談で合意したのは、project単位の有効化、失敗時は通常作業を続け完了だけ保留、意味を保つ言い換え、外部HTML競合での確認待ち、削除・移動時の旧成果物保持、履歴付き自動反映、意味評価とoffline CIの分担である。利用者はこの設計理解に基づくspecとH1/H2追加案の保存・検証・設計文書だけのcommitを許可した。

parserの具体的な依存選択、SVG allowlistとreceipt schemaの実装定義、browser capture adapterはplanで具体化する。ただし本specの全unit coverage・厳密保持対象・静的安全性・network/IPC遮断・評価必須を弱めない。採用するprofileの画像能力・入力上限・実文書での判別力は有効化前の検証事項であり、満たせないprofileは利用不可とする。

2026-11-09、保存済みspecとH1/H2のH3 integration additionsのレビュー依頼に、利用者が「ok」と回答した。本specと追加契約の承認を記録し、H3だけのsdd-planへ進む。本実装・packへの変更・実接続・pushは別の指示と必要な許可の後に行う。
