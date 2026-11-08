# herness H1: pi-rust spike結果

## 結論

**Tauri＋pi-rustのネイティブ埋め込みをH1の第一候補にできる。** Node runtimeなしで、このMac上のTauriとRust製エージェントを接続し、ウィンドウ閉鎖後の実行継続、明示的終了前の停止・保存、別プロセスでの復元を確認した。

これは採用の推薦であり、基盤採用・H1のspec・本実装への承認ではない。認証とモデルはmockを用いたため、実アカウントでのChatGPTログインや実モデル接続の成功を保証しない。初期のcoding harness全体やPiの全機能互換も実証していない。

## 許可された範囲と実行環境

- 最大45分の使い捨てspike。ソース・依存の取得、ローカルビルドと検証のみ。
- 実ログイン、実資格情報の読込み、外部モデルへの送信、有料API呼び出しは行っていない。
- エージェント実行基盤の本実装はhernessに追加していない。probeのコードはすべて使い捨て。
- 実行環境: macOS 27.2 / arm64、Cargo 1.97.1、Xcodeの開発ディレクトリが利用可能な環境。
- Pi Rust移植: `yannelli/pi-rust` v0.12.11、commit `4294dba7ac3646477912cc778536fdff0a912d6e`。
- Tauri: 2.12.5。probe用Cargo.lockが解決したtauri-buildは2.7.4。Tauri側と上流側の依存lockは別々であり、同一の依存グラフでの比較ではない。
- 一時領域: `/private/var/folders/1l/g5bm30qs6mq6m4zd0hqj2y4r0000gn/T/opencode/herness-pi-rust-spike.ZBZhB8`。以下、このパスを`SPIKE`と呼ぶ。

## 確認できたこと

### 埋め込みと独自ツール

- `pi-embedded`をRustからビルドし、hostがセッションと独自ツールを登録できた。
- 作成ツールのJSON Schemaに`rationale`を必須化し、理由なしの呼出しをファイル変更前に拒否できた。
- 実ファイルの書込み前に、実行意図・呼出しID・変更理由がcheckpointに保存されていることをhandler内で確認した。書込み後の結果も保存できた。
- hostが作る別セッション間で会話が混ざらないことを確認した。
- 実際の`../sdd/skills/sdd-design/SKILL.md`をsystem contextに渡せた。ただしskillの自動発見や、SDD全工程の実行を検証したものではない。

### 許可モードの接続境界

- 設定権限モードではclassifierを呼ばず、自動判定モードではhostが用意したclassifierへ接続できた。
- 明示的な拒否をclassifierの許可より優先し、必ず確認する操作を人間の応答まで待たせられた。
- classifier不在を許可扱いにせず、実行せずに待機・中断できた。
- classifierは使い捨ての固定結果を返すmock。実LLM・Decisionモデルの精度、prompt injection耐性、完全な権限システムを検証したものではない。

### 停止・保存・復元

- 協調的なシェルwrapperから起動した直接の子プロセスを停止できた。任意の孫プロセスや、切り離されたプロセスの停止保証ではない。
- Tauriで非表示の実WebViewウィンドウを作成して閉じても、アプリ所有のセッションは実行中のままだった。
- その後にセッションをsuspendし、paused checkpointを保存してアプリを明示的に終了できた。
- 別のネイティブSDKプロセスで、そのTauriプロセスが残したcheckpointを復元し、再開できた。
- 画面を見せる製品UI、署名・notarization、インストール・更新、OS強制終了・電源断は未検証。

### APIキーとChatGPT認証

- `pi-ai`のRust製AuthResolverで、偽のAPIキーと偽のChatGPT/Codex OAuth資格情報を解決し、hostのStreamFnへ渡せた。実providerのHTTP送信はscripted streamに置き換えた。
- 実APIキー・アクセストークンがセッションsnapshotに入らない構造を、偽の値で確認した。
- 上流のOpenAI OAuthテスト10件は、ローカルmock serverを用いて成功した。ChatGPTの動的client登録、callback検証、更新と、Codexのbrowser/device-code系の分岐を含む。
- `pi-embedded`付属の`create_openai_stream`は`openai-completions`だけを扱う。Responses・ChatGPT/Codexには、`pi-ai`の認証・provider層をhostのStreamFnでつなぐ実装が必要。
- 実ブラウザとOpenAIサーバーでのログイン、アカウントごとの利用可否、トークン更新、実モデル要求は未確認。H1の実装検証前に、利用可能な認証経路と実ログインの許可を確認する。

## 検証記録

実行者はいずれもこのセッションのagent。対象は固定した上流commitと、一時領域内の使い捨てprobeである。

| 作業ディレクトリ | コマンド | 実際の結果 | 検証範囲 |
| --- | --- | --- | --- |
| `SPIKE/source`、追加probe前 | `cargo test -p pi-embedded --locked --test integration` | exit 0、52 passed / 0 failed | 上流のembedded integration tests |
| `SPIKE/source`、追加probe後 | `cargo test -p pi-embedded --locked --test integration` | exit 0、63 passed / 0 failed | 上流52件＋追加11件。host接続はmock modelを利用 |
| `SPIKE/source` | `cargo test -p pi-ai --locked --lib auth::oauth::tests::openai -- --test-threads=1` | exit 0、10 passed / 0 failed、684 filtered out | OpenAI OAuth関連の上流unit testsのみ。実ログインなし |
| `SPIKE/source` | `cargo build -p pi-embedded --locked --release --example herness_spike` | exit 0 | headless SDKの使い捨てexample |
| `SPIKE` | `python3 measure.py` | exit 0、5回のREADY到達と別プロセスsave/restore成功 | SDK単体の限定的な測定 |
| `SPIKE/tauri` | `cargo build --release --locked` | exit 0 | Tauri＋Rust SDKの未bundle binary |
| `SPIKE` | `python3 run_tauri.py` | exit 0、Tauri終了0、別プロセス復元0 | 非表示window閉鎖後もRunning、終了前Paused、復元後Idle |

途中で追加probeの一時ディレクトリを早く破棄するfixtureミスと、Tauriの必須icon不足が発生した。probe側の寿命管理と単色のRGBA fixtureを修正し、上記の最終確認を行った。上流の製品コードは修正していない。

## 測定値と限界

- Headless SDK exampleのrelease binary: 8,542,464 bytes（約8.15 MiB）。
- 同exampleのREADY後RSS: 5回の中央値3,504 KiB（約3.42 MiB）。
- 同exampleのプロセス開始からREADYまで: 5回の中央値10.82 ms。最初の1回は444.68 ms、残りは8.12〜11.20 ms。
- Tauriの使い捨て未bundle binary: 13,056,496 bytes（約12.45 MiB）。
- Tauriのwindow作成・閉鎖・SDK中断・保存・終了までの一連のprobe: 約993.34 ms。これはアプリの起動時間ではない。

**これらはscripted modelを使う最小fixtureの値であり、製品のメモリや配布サイズの予測ではない。** 本番のprovider接続、会話履歴、実行中のtool、複数agent、WebKitプロセスを含むTauri全体のメモリ、署名済み配布物は測っていない。Electron・Node・Rig・Gooseより軽いという比較結果でもない。

## H1の設計へ持ち込む制約

- Piの完全なcoding-agent SDKをそのまま使うのではなく、小さい`pi-embedded`と`pi-ai`をhost adapterで接続する案を第一候補とする。
- セッションをUIではなくアプリに所有させ、通常のbackgroundingやwindow閉鎖をSDKのSuspend lifecycleに直接対応させない。
- `FileSessionStore`のcompare-and-swapはprocess-local。別プロセスからの同時書込みを許すなら、herness側の調整が必要。
- セッションの破棄と、後から再開するための停止・保存は別操作。disposeしたセッションはそのままrestoreできないため、通常のアプリ終了をdisposeに置き換えない。
- 実行途中の不確実な変更を自動で再実行しない。記録の永続化、状態の照合、再許可をhostで設計する。
- 許可判定、変更理由、完了判定は別の概念。判定モデルやhookはOS sandboxではない。
- 実ChatGPT認証、実モデル接続、製品相当のプロセス全体の性能・停止・復旧、packaged appは未検証事項として残す。H1の実装受入条件に、必要な検証と利用者の許可を記載する。

## 根拠となるソース

- [pi-rust v0.12.11](https://github.com/yannelli/pi-rust/tree/v0.12.11)
- [embedded host契約](https://github.com/yannelli/pi-rust/blob/v0.12.11/crates/pi-embedded/src/host.rs)
- [embedded runtimeのlifecycle](https://github.com/yannelli/pi-rust/blob/v0.12.11/crates/pi-embedded/src/runtime.rs)
- [embedded付属OpenAI streamの対応API](https://github.com/yannelli/pi-rust/blob/v0.12.11/crates/pi-embedded/src/openai.rs)
- [Rust OAuthの登録](https://github.com/yannelli/pi-rust/blob/v0.12.11/crates/pi-ai/src/auth/oauth/mod.rs)
- [Tauriの終了制御](https://v2.tauri.app/develop/plugins/)

一時領域にはREADME、追加test、example、Tauri fixture、測定scriptとJSON結果が残る。これらは再利用するアプリコードではなく、現在の設計判断のための使い捨て証拠である。
