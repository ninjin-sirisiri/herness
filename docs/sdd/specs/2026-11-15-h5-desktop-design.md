# H5: チャット中心のデスクトップ操作と個人用macOS導入

**Classification:** architectural

**Status:** 2026-11-15、commit 9256cc5の設計書とH1/H4追加契約案へのレビュー依頼に利用者が「ok」と回答し、本specと追加契約を承認済み。H5だけのsdd-planへ進む。実装・別repo編集・実モデル送信・pushは開始しない。

**Chosen approach:** アプリ寿命のRust hostを維持し、既存の静的Web UIをチャット中心の画面へ分割する。本体と固定版SDD packを一つの個人用.appに含め、外部ツールは診断と導入案内で扱う。

本specは[ロードマップ](2026-11-07-herness-roadmap.md)のH5を扱う。実行・会話・履歴・権限・認証・配布資源の読込みは[H1](2026-11-07-h1-runtime-design.md)、監督・証拠・判定は[H2](2026-11-08-h2-supervision-design.md)、HTML同期は[H3](2026-11-09-h3-html-sync-design.md)、Task進行・停止確認・finish引継ぎは[H4](2026-11-13-h4-sdd-execute-design.md)を正本とする。追加契約は各正本のH5 integration additionsに置き、用語は[CONTEXT.md](../../../CONTEXT.md)に従う。

## Goals and non-goals

- 自分のApple Silicon Macで、Finderから起動し、プロジェクトを開いてSDDによる設計相談・specレビュー・plan作成・承認済みplan実行へ進める。
- 同じ通常会話へ追加入力し、閉じた画面やアプリ再起動後も保存済みの会話・実行・承認待ちを探せる。復元だけで送信・実行しない。
- 変更理由をチャット以外の専用画面から確認し、Task・HTML同期・証拠・予算・停止理由と必要操作を追跡できる。
- 本体とSDD packを同梱する。Git・Python 3.11+・利用者のbuild/testツールは同梱せず、不足・版不一致・設定方法を示してインストールを促す。
- 一般公開、Intel・他OS、古いmacOSへの互換保証、Developer ID署名・notarization・App Store・自動更新、クラウド同期・telemetryは初期範囲外。
- IDE・汎用ファイル編集器・ターミナル、会話の分岐・履歴編集・削除、資格情報や履歴の削除UI、worktree削除、新しい統合実行機構は追加しない。自動push・merge・公開、Task並列化、UIによる完了宣言は行わない。

## Alternatives and architecture

比較した画面構成は、会話と監督を常時並べるワークスペース型、採用するチャット中心、監督画面中心の三案。利用者はチャット中心を選んだ。常設の多列画面を避け、相談と文書の読解領域を優先する一方、人間待ちと停止を隠さない。

既存のvanilla JavaScript・HTML・CSSをES modulesへ責務分割し、初期構成にfrontend frameworkや製品用Node runtimeを追加しない。最終的な色・余白の細部は実装時の可逆な調整とし、画面の意味・操作・安全境界は本specで固定する。

| Component | 責務 |
| --- | --- |
| App shell | プロジェクト・会話の選択、主要画面、注意表示、設定への入口 |
| Conversation view | 保存済み本文、応答表示、明示送信、skill選択、通常会話と子ログの区別 |
| Activity / action views | H2/H3/H4のsnapshot・必要操作・条件・証拠・予算の表示と正本操作への接続 |
| Rationale view | H1のページ付き監査履歴、変更理由・shell目的・host操作の区別 |
| Document viewer | Markdown原文と、権限・networkを持たないHTML閲覧領域 |
| Desktop services | 信頼されたIPC、会話記録、設定・toolchain・bundle資源、既存hostとのcomposition |

実行と保存はRust hostが所有する。UIは表示用cacheと選択・未送信draftだけを持ち、window・表示中project・pollの有無を進行条件にしない。UI設定はprivate app領域へ保存し、実行承認・条件・予算を画面設定で置き換えない。

## Navigation and visible behavior

左の折り畳み可能な領域にプロジェクトと通常会話の一覧を置く。中央は選択した会話を基本とし、文書・変更理由・設定は専用viewへ切り替える。Task・HTML同期・証拠の詳細は必要時に開くパネルとし、狭いwindowでは中央viewへ切り替える。戻ったときにdraft・選択・scroll位置を保持する。

上部に現在のproject、接続・model、許可モード、Task実行とHTML同期の要約、人間待ち件数を表示する。待機・失敗・staleを件数だけで隠さず、理由と対象へ移動できる入口を置く。実行中の対象と停止操作は、他viewの閲覧中も到達可能にする。「一時停止」と終端の「取消し」を別操作とし、取消し前には変更・履歴を戻さないことを確認する。

子エージェントは通常会話の一覧に混ぜず、TaskやHTML jobの活動詳細から開く読取り専用ログとする。H1 idleは「応答待機」、H2 completedは監督対象の成立、H4 completeはTask確定、ready_for_finishは「統合の選択待ち」と区別する。現在への適用が失効した成功は、履歴とstale表示を併記する。根拠のない進捗率やモデル内部思考は表示しない。

## Conversation and SDD workflow

1. 初回設定を確認し、projectと実行接続を選んで新しい通常会話を作る。通常送信ごとに利用者が明示操作する。応答中の入力はdraftに留め、自動送信queueやTaskの子への割込みにはしない。
2. 設計・plan作成は同梱packのskillを選んで開始する。選択したskill本文・参照元・指紋・host適用差分をH1経由で記録し、継続にも保持する。無効なpackや未対応能力を別ホストの手順で代用しない。
3. 設計中の質問には通常会話で回答する。作成された文書を原文・companionからレビューし、利用者が明示的にplan作成へ進む。会話中の「OK」はH4開始権限ではない。文書内の承認済みという記述も権限の証明にしない。
4. herness向けplan作成ではH4の新形式を要求する。保存されたplanをread-onlyでinspectし、診断・参照spec・Global Constraints・Task別条件・検証・write scopeを表示する。不正・旧形式では実行開始へ進まない。
5. 専用の開始確認でcheckout・branch・base branch・隔離選択、現在の文書版、接続、用途別同意、全Taskの有限上限、host commitとhook、Git identity、別予算のH3費用を確認し、H4のapprove-and-startを呼ぶ。IDや上限を利用者にJSON入力させず、固定のTask 1やGit identityで代用しない。
6. H4完了後は、現在の最終証拠と台帳を伴う引継ぎを表示して既存sdd-finishへ渡す。統合を自動実行せず、no_changeのstacked PR非互換と未確認を示す。finishの利用や外部Git操作は既存skillの人間確認に従う。

会話・入力・本文の保存、順序、重複送信防止、復旧の契約はH1追加契約を消費する。表示用にSDK checkpointを解析しない。接続・modelを別のものへ変える場合は新しい会話を作り、既存会話を別providerへ無断送信しない。過去データの本文が復元できなければ欠落を明示し、架空のやり取りを補わない。

SDD文書を書き込む会話では、開始前にH3の設定承認と有効なhost-delegated HTML契約を確認する。親のHTML著作・HTML worker dispatchへfallbackせず、文書変更後の同期・証拠はH3へ委譲する。同期が必要なレビュー・commit・後続操作は各正本のbarrierを満たしてから進める。H4の開始前には、同じ実checkoutで編集可能な通常runの停止も確認し、動作中の編集とTask所有を競合させない。

Taskが同じcheckoutを所有している間も、別の通常会話で読取り専用の相談を行える。hostがread・searchだけのgrantを適用し、write・edit・shell・Git変更を拒否する。子ログの入力欄は設けない。停止要求だけで編集を解禁せず、停止確認と所有状態を照合する。編集を伴う送信は利用者が改めて範囲を選び、重要なTask変更はH4のplan修正・再承認へ案内する。H4停止でも着手済みTaskの契約変更が自動移行可能になるわけではない。

## Activities, approval and recovery

H2は条件別のpass・fail・不足、証拠の取得者・実操作・実結果・対象版・範囲、判定先・profile版・適用規則、消費・予約・unknownを表示する。通常LLMの説明とDecisionの分布・host規則を区別し、確率のない方式に数値を作らない。見積不能な金額上限は設定可能に見せず、理由を示す。

H3はproject単位の有効化確認を提供し、既存の未同期・不足companion、Target集合、著作接続、Html profile、送信範囲、上限、自動反映と履歴保存を表示する。未承認時は走査だけとする。文書ごとの原文版・世代・状態・watcher健全性・失敗理由・証拠を表示し、再開・再評価・再生成・競合採用/置換・履歴復元をH3の操作へ接続する。復元は対象版と現在版を確認する別操作であり、直後をsyncedとしない。orphanedは残存パスを示すだけで削除しない。

H4はprojectの保存済みexecution一覧から再接続する。plan版・承認ID/版・現在Task・各Task phase・commit範囲・no_change・現在への適用・消費/予約予算を取得し、再開で承認IDを作り直さない。開始直後のreadyやchildStarted=falseを失敗・完了と解釈しない。current_approval不足だけを理由に初回の承認入口を消さず、開始前の能力照合はhostが行う。

停止要求、子の停止確認、H4の再開可能性を区別する。H4追加契約の停止照合操作はhostの結果を取得するもので、人間が「停止済み」と宣言する機能ではない。plan変更の差分・継承可否・新しい承認範囲、結果不明Git・復旧待ち・不足証拠を表示し、汎用の再試行ボタンで迂回しない。

H1の操作承認は実際の最終引数・cwd・対象・操作IDへ結び付けて表示する。設定権限/自動判定モード、明示deny/ask、実行scopeの設定は信頼された設定viewから版付きで更新する。H2のprofile選択・verification・用途別送信同意と分離し、未確認のprofileを確認済み扱いにしない。APIキーは一時入力後に消去し、保存済みsecretの再表示やWebView内OAuth password入力はしない。

## Rationale and document viewing

変更理由画面はH1のproject指定・固定上限sequence付き降順ページを使い、取得済みページへ新着を混ぜない。新着は別の入口で表示する。ファイル操作はrationale・対象・差分・変更前後版・成否・操作/run参照を表示し、shellはpurpose・command・結果、host反映やcommitはhostの目的として区別する。外部編集の理由を推測せず、記録がない事実を示す。初期は取得済み項目の絞込みのみとし、全履歴検索を保証しない。

文書一覧からMarkdown原文とcompanionを切り替えて読める。古いHTMLは対応する原文digestと未同期表示を伴って閲覧できるが、現在の成功とはしない。壊れたmetadataや静的安全性検査に失敗したHTMLは描画せず、安全なテキスト表示と診断へ切り替える。

生成HTMLをprivileged main DOMへ挿入しない。閲覧にはIPCのない独立したnative WKWebView領域を用い、H3のresource allowlist・非永続storage・network遮断の境界を再利用する。preview専用の寿命・読み上げ名・閉じる操作を持ち、表示したbytesと版を明示する。任意project fileの配信、remote navigation、popup、download、script実行を許可しない。文書リンクの移動はhostが許可した文書参照に限定し、外部URLはmain側の明示操作でのみシステムブラウザへ渡す。previewを見たことや静的検証だけでH3の意味・品質評価を成立させない。

## Data flow, errors and synchronization

UIは起動・再表示・project切替時にversion付きsnapshotとsequenceを取得する。通知は保存済み状態の再取得契機であり、重複・欠落・順序逆転で操作を再実行しない。旧snapshotを新snapshotへ上書き適用せず、sequence欠落では再取得する。未対応versionは利用不可として表示し、部分データから成功を推測しない。

更新は対象project・安定ID・request ID・expected revisionへ結び付ける。同じ要求の再配送には同じIDを使い、別内容に同じIDを流用しない。競合は最新状態を読み直して人間へ戻す。通信timeout後に新しいIDで開始・送信・commitをやり直さない。H4の10種のerrorとH1/H2/H3のsanitized診断・参照・必要操作を保持し、生のprovider errorや資格情報を表示しない。

通常会話本文はテキストと安全なMarkdown表現として表示し、raw HTML・script・実行リンクを受け入れない。モデル本文やrepo内文字列から操作確認を偽造できないよう、承認UIはhostの構造化状態だけから構成する。mainの画面切替にURL query・fragment・remote originを使って既存caller guardを緩めず、未信頼previewへcommand権限を与えない。

## Personal macOS bundle and onboarding

最初の保証対象は現在のarm64開発機（macOS 27.2.1）で、bundleの最低版は27.2とする。27.2の全patch版や将来版の動作を既に確認したとはしない。release .appをローカルで作成して利用者が配置し、ad-hoc署名を用いる。一般配布のGatekeeper通過やnotarization済みとは表示せず、quarantineの一括解除・セキュリティ設定の自動変更を案内手順へ加えない。

同梱SDD packはソースrepoから作る版固定の配布artifactであり、新しい独立正本ではない。pack全体のskills・scripts・formats・schema・adapter・policy等、実行に必要な参照とライセンスをbundle resourcesへ含める。.git・worktreeの管理情報・秘密・開発用cacheは含めず、必要ファイルの欠落やsymlinkによるbundle外参照を検査する。manifestへsource revision・内容指紋・H3/H4契約指紋を保存し、起動時に読み取り専用の資源として照合する。アプリから編集・自己更新しない。

調査時のH4検証済みpackは../sddのmainではなく、../sdd/.worktrees/h4-execのb210b3aac3faf84c5ad201aa6502dface8c4cdf2である。配布用入力はこのH4契約を満たす版としてbuild時に固定・検証し、開発者の絶対パスや環境変数SDD_PACK_ROOTを製品の必須条件にしない。別repoの統合・変更は本specでは許可しない。

初回起動は、同梱pack確認、Git・Python検出、必要な明示パス設定、接続・model、project、用途別profile/同意の順に案内する。Git・Pythonは起動時に実行可能性と版を検査し、FinderのPATHだけに依存しない。build/testツールはprojectと必要操作に応じて診断する。導入案内は利用者が手動で実施し、アプリによるdownload・package manager実行・sudo・自動インストールは行わない。不足時は設定・履歴閲覧を使えても、依存する開始操作を利用不可とする。

設定にはtoolchainの検出結果・実パス・版、接続の非secret状態、bundle/pack版、保存先を表示する。明示パスが不正なら別の実行ファイルへ黙ってfallbackしない。通常の起動・走査・履歴復元だけでモデルへ送信しない。利用者のシェルprofileを無条件にsourceしない。

更新は安全停止・保存・アプリ終了後の手動差替えとする。安定したbundle identifierとapp data/Keychainの参照を維持し、packだけを別更新しない。再起動時にpack/profile/同意の指紋が変われば、所有specに従って再承認・照合を求める。DBは既存migrationに従い、旧アプリへのdowngrade・自動DB再作成・自動rollbackを許可しない。更新手順では停止と保存の確認方法、private dataのバックアップ方法、旧版を起動しない条件を説明する。

ChatGPT認証は既存のlocal・unpublished・non-commercial gateを維持する。今回の自分用buildを公開・配布の許可へ変換せず、利用条件やライセンスの適合確認が不足すれば該当接続を利用不可にする。本体やpackの一般公開は別の判断とする。

## Numeric defaults and accessibility

| 項目 | 初期値・規則 |
| --- | --- |
| 主window | 初期1,024×760、最小720×560 CSS px。200%拡大ではパネルを単一viewへ切替え、主要操作を隠さない |
| snapshot再照合 | 表示中の活動は2秒間隔をfallbackとし、再表示・通知・操作後にも取得。hostの進行とは独立 |
| 会話/監査ページ | H1の既定100件・上限500件。cursorとlive sequenceを区別 |
| 通常入力上限 | H1追加契約のUTF-8 256 KiB。送信前に示し、黙って切り捨てない |
| 停止猶予・予算 | H1の10秒、H2/H3/H4の既存上限を変更しない。画面を閉じて消費をリセットしない |
| 性能計測 | release版、同一機で起動5回、idleと実行中のhost＋所属WebKitのRSS・peak・測定条件を記録。外部build/test processは別記 |

日本語UIを初期言語とし、system font、OS追従のlight/dark、明確なheading/landmark、色だけに依存しない状態表示を使う。主要操作はkeyboardで到達でき、focusを見失わない。modalを閉じたら起点へ戻し、応答streamでscrollやfocusを奪わない。画面更新の読み上げは承認待ち・失敗等の意味のある変化にまとめ、tokenごとの通知をしない。VoiceOver、200%拡大、light/dark、狭いwindowで実操作を確認する。

軽さの数値上限は未合意である。既存debug測定の起動中央値337 ms・idle約204.5 MiBは参考で、releaseや全実行時の保証へ流用しない。初回release計測後、H5受入前に起動・idle・実行時の数値基準を人間と合意し、未合意のまま軽量性を達成済みとしない。

## Integration prerequisites and consuming paths

調査起点はherness 9594a15。H4はmainへ統合済みだが[受入記録](../../research/2026-11-13-h4-acceptance.md)ではPhase Aのみ確認し、Phase BとH4全体は未完了。H1/H2の未確認接続、H3のtext-only reduced scope受入も引き継ぐ。

現在のstart_runは毎回新agentを作り、通常会話の追加入力・正規化されたuser本文履歴・stream表示を公開していない。history IPCもcursor付き降順履歴ではない。H1追加契約を先行実装し、SDK型をUIへ漏らさない。toolchain設定と同梱pack解決も環境変数依存から接続し直す。

H4にはexecution/承認の一覧IPCと停止確認の操作接続がなく、現在のfinish_handoffはfinal_evidence_not_verifiedを残して常にready=falseを返す。H4追加契約に従って正本の規則を満たすcompositionを接続する。error detailsの脱落、resumeで承認IDを作り直す最小画面、Task 1だけの上限・固定Git identityを完成版へ引き継がない。

- ui/をshell、conversation、activities、rationale、documents、settings、IPC/state modulesへ分割する。既存最小画面の接続能力を製品viewから失わない。
- src-tauri/src/に会話・設定・preview・bundleのcompositionと信頼されたcommandを追加し、build.rsとcapabilitiesの明示allowlistを整合する。
- crates/herness-core、herness-engine-pi、herness-storeでH1の会話公開契約・保存互換を実装し、src-tauri/src/sdd_executeとcrates/herness-sdd-executeでH4追加接続を実装する。実行・保存の所有権をfrontendへ移さない。
- tests/desktop-ui/を新しいUI横断テストの起点とし、既存tests/runtime/、tests/supervision/、tests/html-sync/、tests/sdd-execute/を回帰する。pack自体を変更する必要が生じた場合は別途許可を得て作業先を明示する。

## Testing and acceptance

1. 正規化された会話の初回・追加送信、保存前失敗、重複request、送信結果不明、streamの欠落/重複、再接続、旧履歴欠落、未対応versionを実Pi＋loopback・実storeで検証する。復元時の外部要求0件と、通常会話とH2/H3/H4子の所有分離を確認する。
2. UIから設計相談・原文/HTMLレビュー・herness形式plan作成・read-only preview・専用開始確認・複数Task直列実行・停止確認・再開・finish引継ぎを通す。Task実行中の相談はread/searchのみで、write/edit/shellと子への直接入力を実tool経路で拒否する。
3. stale成功、未同期、判定不能、予算unknown/到達、plan変更、Git結果不明、古いrevision、未停止process、no_changeの非互換を表示し、原因を解消しない再開・commit・次Task・finish成功を拒否する。全Taskの上限・同意と既存承認IDを保つ。
4. 変更理由の別画面・差分・actor区別、100件を超える固定cursor履歴、新着との分離、H3の有効化・競合採用/置換・履歴復元・orphaned表示を実操作で確認する。取消し・復元で既存変更や履歴を削除しない。
5. untrusted本文・HTML・SVGからIPC、外部通信、project外resource、popup/download、承認UI偽造、資格情報取得を試みて拒否を確認する。previewとprivileged DOMを分離し、APIキーの入力後消去と秘密の非公開を検証する。
6. Finder起動のrelease .appで、shell由来のPATHやSDD_PACK_ROOTなしに同梱packを解決する。Git/Pythonなし・旧版・明示パス不正・pack欠落/改変を診断し、案内だけでinstall・送信しない。移動した.app、手動更新、既存DB/Keychain参照、未知形式の拒否を確認する。
7. 実WKWebViewでkeyboard・VoiceOver・拡大・theme・狭幅・focus・draft保持を確認する。window閉鎖・Dock再表示・非選択project・quit・再起動と停止未確認を実Tauriで検証し、保存結果をUIの通知だけで判断しない。
8. release性能を定義した条件で測定し、未解決の数値基準を受入前に合意する。Rustのfmt/clippy/test/build、UIテスト、共通HTML検証、bundle smokeを実装planで具体化し、command・実結果・revision・範囲を記録する。

通常の自動検証は一時project・DB・fake credential・loopbackだけを使う。実providerによる設計から実行・HTML評価までの確認は、fixtureと送信bytes種別、接続・用途、有限回数/retry、料金または枠を提示して別途許可を得る。実接続用runnerの不足も検証準備へ含め、scripted judgeや画面表示の成功を実モデル品質の受入へ流用しない。

H5のUI/bundle検証と製品全体の受入を区別する。上流の未確認・画像/品質能力不足・利用条件未確認を免除せず、必要な機能は利用不可/保留と表示する。全体完成条件が成立しない間はherness全体の完成を主張しない。限定受入へ変える場合は別途人間の明示合意を必要とする。

## Open items and approval

未解決なのは、release実測に基づく軽さの数値基準（H5受入前）、実provider受入の接続・送信範囲・料金等の許可（実送信前）、公開へ進む場合の利用条件・ライセンス・署名・OS対応（今回の範囲外）である。これらを未合意のまま性能達成・実接続確認済み・公開可能と扱わない。画面の色・余白等は安全契約を変えない範囲で実装時に調整し、実表示で確認する。

利用者は自分用、チャット中心、設計からの利用、本体とSDD packの同梱・他ツールの導入案内、Task実行中の読取り専用相談を選んだ。上記の範囲・前提補修・未解決項目を示した保存確認へ「この範囲で保存」と回答し、specとH1/H4追加契約案、ロードマップ、HTMLの保存・検証・設計文書だけのcommitを許可した。保存後の設計・追加契約のレビュー承認、sdd-plan・実装・別repo編集・実モデル送信・pushの許可ではない。

続いてcommit 9256cc5の設計書とH1/H4追加契約案へのレビュー依頼に、利用者が「ok」と回答した。2026-11-15の設計・追加契約の承認として記録し、H5だけの実装planを作成する。軽さの数値基準と実provider受入の許可は記載した解消時点まで未解決のまま保持し、本実装・別repo編集・実送信・pushを許可しない。
