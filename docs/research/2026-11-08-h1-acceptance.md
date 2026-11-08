# H1 受入証跡と実接続の状態（2026-11-08、Task 13 Phase A / Phase B）

**Status:** Phase Aの自動検証・実Tauri検証・mock検証に加え、Phase BでOpenAI互換とChatGPTの実接続を確認した。OpenAIとAnthropicのAPIキー経路は検証用キーがなく**UNVERIFIED**であり、利用者の判断で未確認のまま残す。したがってTask 13もH1受入も完了していない。H2以降の設計・実装へは進まない。

- **対象revision:** `3ab4d46`（Task 12最終commit）からTask 13 Phase A、Phase B前の修正 `03ad815`・`403839b` まで。最終検証のrevisionは末尾に記録する。
- **環境:** macOS 27.2（build 26B123）、Apple M5、arm64、16 GiB。`rustc 1.97.1 (8bab26f4f 2026-07-14)`、`cargo 1.97.1 (c980f4866 2026-06-30)`。debug build。
- **正本spec:** [H1 runtime design](../sdd/specs/2026-11-07-h1-runtime-design.md)のTesting and acceptance、Open items and resolution、Approval。
- **手順:** [h1-testing.md](../development/h1-testing.md)のTask 13 Phase A節とPhase B runbook。
- **Phase Bの証拠:**  sanitized evidence JSONは`.sdd/reports/phase-b-evidence/`（git管理外）に保存した。secret・token・ID token・生URL・provider error bodyは含まない。

## 証拠の分類

| 分類 | 意味 |
| --- | --- |
| automated | 通常のworkspace test。loopback mock・scripted engine・fake credential・一時DB/projectだけを使う |
| desktop | 実Tauri processを起動するsmoke/close/reopen/quit検証 |
| mock | provider·OAuth·engine·Keychainをloopback/scripted/fakeで検証したもの。実接続の成功ではない |
| real | 実provider・実account・実Keychainへ接続した結果。Phase Aには存在しない |
| unverified | 証拠がない、または実接続の許可・料金が未確認 |

## 実行コマンドと結果（Phase A）

| コマンド | 終了code | 結果 |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | 差分なし |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | warningなし |
| `cargo test --workspace --locked` | 0 | **327 passed, 0 failed, 1 ignored** |
| `cargo build -p herness-desktop --locked` | 0 | `Finished dev profile` |
| `HERNESS_APP_DATA_ROOT=<tmp> target/debug/herness-desktop --smoke-test` | 0 | `SMOKE_READY: pid=91506 startup_ms=477`、`SMOKE_OK` |
| `HERNESS_APP_DATA_ROOT=<tmp> target/debug/herness-desktop --close-reopen-test` | 0 | `CLOSE_REOPEN_HIDDEN: pid=91505 generation=1`、`CLOSE_REOPEN_OK: ... generation=2` |
| `HERNESS_APP_DATA_ROOT=<tmp> target/debug/herness-desktop --quit-test` | 0 | `QUIT_TEST_READY: pid=91504`、`QUIT_OK: pid=91504 save=confirmed stop=confirmed` |
| `HERNESS_APP_DATA_ROOT=<tmp> target/debug/herness-desktop --real-check <unknown-uuid>` | 2 | `REAL_CHECK_FAILED: ... failure=connection_not_found`、evidence書込み、providerへ未接続 |
| 実provider route（OpenAI・Anthropic・OpenAI互換・ChatGPT） | — | Phase Aでは未実行。結果は下記Phase B節 |

- 1 ignoredは `measure_running_host_rss`（Task 12の手動計測fixture）であり、pass数へ加算しない。
- **spikeの73件はhernessのpass数へ加算していない。** spikeは設計選択の証拠であり、本実装のtest結果ではない。
- desktopのPID・startup_msはこの実行の値であり、性能目標ではない。

## Phase B 実接続結果（2026-11-08）

利用者が信頼されたUIで検証用接続を設定し、合成prompt `Reply with the single word: herness-ok.`・最大32 output tokens・各経路1回の条件で実行した。既存の資格情報は探索・流用していない。

| 経路 | 実行 | 結果 | 証拠 |
| --- | --- | --- | --- |
| OpenAI互換 APIキー → openai-completions | `--real-check <connection>` | **確認済み** `terminal=completed`、1,324 ms、usage 41/23/64 tokens | `real-check-...-request.json`（provider=openai_compatible, model=deepseek/deepseek-v4.1-flash） |
| ChatGPT login → catalog | UI login後に `--real-check <connection> --list-models` | **確認済み** `terminal=listed`、8 models、`gpt-6-luna` を含む | `real-check-...-list_models.json` |
| ChatGPT Responses → `response.completed` | `--real-check <connection>` | **確認済み** `terminal=completed`、3,059 ms、usage 16/7/23 tokens | `real-check-...-request.json` |
| ChatGPT refresh | `--real-check <connection> --refresh` | **確認済み** `terminal=refreshed`、1,223 ms | `real-check-...-refresh.json` |
| ChatGPT sign-out / remote revoke | `--real-check <connection> --sign-out` | **確認済み** `terminal=signed_out`、`remoteRevoke=confirmed`、`localCredentialsRemoved=true` | `real-check-...-sign_out.json` |
| 検証用Keychain項目の削除 | `--forget-connection` と `security find-generic-password` | **確認済み** APIキー・ChatGPT account-scoped itemともexit 44（不在） | `real-check-...-forget.json`、account単位の不在確認 |
| OpenAI APIキー → openai-responses | — | **UNVERIFIED**: 検証用キーがないため未実行 | なし |
| Anthropic APIキー → anthropic-messages | — | **UNVERIFIED**: 検証用キーがないため未実行 | なし |

- Phase B中に、Tauriのasync commandからengineの`Runtime::block_on`を呼ぶnested runtime panicを発見した。`03ad815`でengine runtimeへfutureをspawnしてchannelで待つ方式へ修正し、回帰testを追加した。修正後、`Quit herness` は `QUIT_OK save=confirmed stop=confirmed` で終了した。
- 多重Add防止のため`403839b`で送信中にAddボタンを無効化した。
- 誤って追加した接続は`--forget-connection`で削除した。ログイン済みの1件は`remoteRevoke=confirmed`でsign-outした。
- ChatGPTのaccount mappingはTask 13 Phase Aの既知の制約どおりプロセス内にあり、再起動後の再認可には新規loginが必要だった。選択account（`vaultAccount`）は修正後のloginで永続化された。
- OpenAI/Anthropicの未確認は利用者の判断で未確認のまま残す。当該経路を利用可能・確認済みとは表示しない。

## test target別の件数

| target | passed | failed | ignored | 主な証拠 |
| --- | ---: | ---: | ---: | --- |
| `herness-core` lib | 52 | 0 | 0 | 契約・schema・rationale上限・path/symlink・ID・history |
| `herness-core` `tests/contracts.rs` | 13 | 0 | 0 | 公開契約のround-tripとversion |
| `herness-core` `tests/ports.rs` | 5 | 0 | 0 | port境界とfake実装 |
| `herness-store` lib | 9 | 0 | 0 | schema/migration/config |
| `herness-engine-pi` lib | 33 | 0 | 0 | adapter・checkpoint・event変換・catalog・GPT transport・probe |
| `herness-runtime-tests` lib | 1 | 0 | 0 | fixture整合 |
| `tests/connections.rs` | 13 | 0 | 0 | Keychain fake・redaction・refresh直列化・non-fallback・強制refresh |
| `tests/contract_smoke.rs` | 4 | 0 | 0 | contract version・project分離 |
| `tests/desktop.rs` | 17 | 0 | 1 | 実SQLite・実PiEngine・loopback mock・別process復旧・実Tauri相当composition |
| `tests/engine.rs` | 31 | 0 | 0 | 4 provider route・tool往復・終端・取消し・secret canary |
| `tests/files.rs` | 12 | 0 | 0 | rationale/diff/version/保存失敗/symlink/競合 |
| `tests/host.rs` | 18 | 0 | 0 | permission・approval・stop/resume・restore・subscription |
| `tests/oauth.rs` | 29 | 0 | 0 | callback/state/nonce/PKCE/ID token/refresh/revoke mock |
| `tests/permissions.rs` | 20 | 0 | 0 | deny/ask/allow優先・stale・自動mode不在 |
| `tests/shell.rs` | 14 | 0 | 0 | process group・停止・timeout・保存失敗 |
| `tests/skills.rs` | 12 | 0 | 0 | pack指紋・相対参照・capability不足・toolchain |
| `tests/store.rs` | 15 | 0 | 0 | transaction・fault injection・history・照合 |
| `tests/acceptance.rs` | 4 | 0 | 0 | opt-in real-checkの明示性・window automation非起動 |
| `herness-desktop` lib | 25 | 0 | 0 | guard・Keychain adapter・quit・login・real-check証跡 |

## spec受入領域との対応

| specの受入領域 | 分類 | 現在の証拠 | 状態 |
| --- | --- | --- | --- |
| Unit: schema・空白理由・上限、版・path・symlink、許可優先、切替での古い判断失効、secret非公開、provider選択とerror変換 | automated / mock | `herness-core` lib、`tests/contract_smoke.rs`、`tests/files.rs`、`tests/permissions.rs`、`tests/connections.rs`、`tests/engine.rs`の`secrets_never_reach_the_checkpoint_events_or_database`・各provider auth失敗test | 確認済み（mock） |
| Store / integration: 副作用前の永続化禁止、file変更後の保存失敗、同一file競合、checkpoint+auditのtransaction、結果不明の照合、再開時の再許可、履歴ページの安定性 | automated | `tests/store.rs`、`tests/files.rs`の`pre_write_persistence_fault...`・`post_write_result_fault...`・`concurrent_edits...`、`tests/host.rs`のrestore/approval/resume/subscription test | 確認済み |
| Engine adapter: 複数session分離、実skill context、途中停止、tool拒否・確認、event再配送、SDK snapshot互換 | automated / mock | `herness-engine-pi` lib、`tests/engine.rs`の`multiple_sessions...`・`stop_mid_tool...`・`history_and_event_redelivery...`・`unknown_checkpoint_versions...`、`tests/skills.rs` | 確認済み（loopback mock） |
| Connection: OpenAI・Anthropic・OpenAI互換の各経路をローカルmockで検証。ChatGPTのcallback・state・refresh・取消し・port競合、接続ごとの秘密と同時refresh分離 | automated / mock / real | `tests/engine.rs`の各provider tool往復・終端・取消し、`tests/oauth.rs`、`tests/connections.rs`、Phase Bのreal-check evidence | mockは全経路確認済み。実接続はOpenAI互換とChatGPTを確認済み。**OpenAI/Anthropic APIキーはUNVERIFIED** |
| Tauri / security: 信頼main UIだけが許可変更・実行・資格情報保存を呼べる。custom commandの公開範囲、remote origin/previewの拒否、生成HTMLをprivileged DOMへ入れない | automated / desktop | `src-tauri/src/guard.rs` unit、`tests/desktop.rs`の`trusted_main_origin...`・`ui_uses_text_only_rendering...`・`project_open_rejects...`、実Tauri smoke/close/quit | 確認済み。command ACLは`build.rs`と`capabilities/main.json` |
| Lifecycle: 実window閉鎖後の継続、quit中の承認待ち・shell・stream停止、保存と別process復元、強制終了後の照合待ち | automated / desktop | `tests/desktop.rs`のnormal/unconfirmed/force/crash worker、`explicit_shutdown_stops_a_managed_shell_group`、`closed_window_runtime...`、実Tauri close/reopen/quit | 確認済み（active runが10秒を超えるGUI選択操作はmanual test未実施） |
| 実接続の受入: 利用者が許可した検証用接続で、対象API経路とChatGPT login・更新・取消し・実要求を確認 | real | Phase BでOpenAI互換の実要求、ChatGPTのlogin・catalog・Responses・refresh・sign-out/revoke・Keychain削除を確認 | **一部確認**。OpenAI/Anthropic APIキーはUNVERIFIED |
| H1受入の合成条件: 自動検証、実Tauriと選定adapterの接続、実接続の確認結果 | composite | 自動検証・実Tauri・OpenAI互換・ChatGPTは確認済み。OpenAI/Anthropicの実接続が未確認 | **未完了**（利用者の判断で未確認のまま残す） |

## 横断確認（brief記載の項目）

| 項目 | 証拠 | 結果 |
| --- | --- | --- |
| file理由・diff・結果 | `tests/files.rs`の`write_records_before_and_after_versions_diff_and_audit_correspondence`、`whitespace_or_missing_rationale_is_rejected_before_any_file_change`、`edit_records...`; `tests/engine.rs`の`write_tool_records_a_rationale_and_a_durable_file_change` | 理由必須、差分・前後版・result・`file.change`を確認 |
| permission優先と古い判断 | `tests/permissions.rs`の`deny_then_ask_then_allow_precedence...`、`stale_authorizations...`、`approval_and_policy_update_races...`、`tests/host.rs`の`stale_approval_after_policy_bump...`・`stale_approval_after_run_resume...` | deny/ask優先、version/args/run変更で失効 |
| 保存失敗 | `tests/files.rs`のpre/post write fault、`tests/shell.rs`のpre-save/stop後保存失敗、`tests/store.rs`の`failed_commit_before_rows...`、`tests/host.rs`のforced shutdown | 事前失敗は副作用なし、事後失敗は`Unverifiable`で照合待ち |
| secret非公開 | `tests/connections.rs`のcanary 2件、`tests/engine.rs`の`secrets_never_reach...`、`tests/oauth.rs`のredaction test、real-check evidence test | DB・checkpoint・event・WAL・public value・evidenceへ出ない |
| provider routing | `tests/engine.rs`のOpenAI/Anthropic/OpenAI互換/ChatGPT各route、`herness-engine-pi`の`model_for_maps_every_provider...` | Responses/Messages/Completions/public Responsesへroute。fallbackなし |
| skill不足 | `tests/skills.rs`の`run_context_distinguishes_reading_from_unavailable_worker_execution`、`missing_and_non_executable_tools...`、`real_sdd_pack...` | H1は`SddTaskController`/`HtmlWorker`をUnavailableとして返し、親model dispatchへfallbackしない |
| 停止・復元 | `tests/desktop.rs`の4 worker、`tests/host.rs`の`stop_resume_and_idle...`・`restore_makes_zero_requests...`、`tests/shell.rs`のstop/timeout | 停止・保存・別process復元・照合待ちを確認。起動時request 0 |
| subscription再接続 | `tests/host.rs`の`subscription_reconnect_matches_final_state_without_duplicates_or_loss`、`redelivery_after_approval_does_not_re_execute` | 重複・欠落なし、再配送は再実行しない |

## 接続経路ごとの状態

| 経路 | mock証拠 | 実接続 | Phase Bで必要な証拠 |
| --- | --- | --- | --- |
| OpenAI APIキー → openai-responses | `openai_api_key_text_turn...`、`openai_tool_round_trip...`、auth失敗test | **UNVERIFIED**（検証用キーなし） | 将来 `--real-check` で provider=openai, endpointClass=openai_responses, terminal=completed を確認する |
| Anthropic APIキー → anthropic-messages | `anthropic_tool_round_trip...`、auth失敗test、cancel test | **UNVERIFIED**（検証用キーなし） | 将来 `--real-check` で endpointClass=anthropic_messages, terminal=completed を確認する |
| OpenAI互換 → openai-completions | `openai_compatible_tool_round_trip...`、auth失敗test、cancel test | **確認済み** `terminal=completed`、usage 41/23/64、1,324 ms | `real-check-...-request.json`（model=deepseek/deepseek-v4.1-flash） |
| ChatGPT login/callback/state/PKCE/ID token | `tests/oauth.rs` 29件 | **確認済み** 実browser login、`state: available`、選択account永続化 | 実login後のUI status、catalog成功 |
| ChatGPT catalog/Responses/終端 | `chatgpt_uses_the_public_catalog...`、incomplete/early disconnect/failed usage-limit test | **確認済み** catalog 8 models、`terminal=completed`、usage 16/7/23、3,059 ms | `real-check-...-list_models.json`、`real-check-...-request.json` |
| ChatGPT refresh | `refresh_rotates_tokens_and_concurrent_refreshes...` | **確認済み** `terminal=refreshed`、1,223 ms | `real-check-...-refresh.json` |
| ChatGPT sign-out/revoke | `sign_out_removes...`、`sign_out_confirms...`、`sign_out_selected...`、`auth::https`のempty 200 test | **確認済み** `remoteRevoke=confirmed`、`localCredentialsRemoved=true` | `real-check-...-sign_out.json` |
| 実Keychain | `src-tauri`のKeychain adapter fake testのみ | **確認済み** 検証用項目の作成・削除・不在（exit 44） | `--forget-connection` と `security find-generic-password` |

## 明示的な除外・未確認

- **spikeの73件は数えていない。** `docs/research/2026-11-07-pi-rust-spike.md`は設計根拠。
- `measure_running_host_rss` は手動fixtureで、自動testのpassではない。
- 実Tauriのclose button人間クリック、macOS dock reopen、quit猶予後のkeep waiting/force quitのGUI操作は自動化していない。controllerの判断はunit test、復旧は別process fixtureで確認した。
- Phase Aでは実providerの応答・料金・利用枠・認可条件・Keychain項目に一切触れていない。Phase Bでは利用者が設定した検証用接続だけを使用した。
- **OpenAIとAnthropicのAPIキー経路はUNVERIFIED**（検証用キーがない）。利用者の判断で未確認のまま残す。当該経路を利用可能・確認済みと表示せず、Task 13/H1受入も完了にしない。
- OpenAI互換とChatGPTの実接続は確認済みだが、料金・利用枠の継続的な保証や全modelの互換を意味しない。
- 実Tauriのclose button人間クリック、macOS dock reopen、quit猶予後のkeep waiting/force quitのGUI操作は自動化していない。通常quitは `QUIT_OK save=confirmed stop=confirmed` で確認した。
- H2の評価器、H3のHTML同期、H4のTask進行、H5の配布は開始していない。
