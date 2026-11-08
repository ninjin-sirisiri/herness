# H1 受入証跡と実接続の状態（2026-11-08、Task 13 Phase A）

**Status:** Phase Aの自動検証・実Tauri検証・mock検証を記録する。実接続はすべて**UNVERIFIED**であり、Task 13もH1受入も完了していない。H2以降の設計・実装へは進まない。

- **対象revision:** `3ab4d46`（Task 12最終commit）からのTask 13 Phase A差分。Phase Aのcommit SHAは最終reportに記録する。
- **環境:** macOS 27.2（build 26B123）、Apple M5、arm64、16 GiB。`rustc 1.97.1 (8bab26f4f 2026-07-14)`、`cargo 1.97.1 (c980f4866 2026-06-30)`。debug build。
- **正本spec:** [H1 runtime design](../sdd/specs/2026-11-07-h1-runtime-design.md)のTesting and acceptance、Open items and resolution、Approval。
- **手順:** [h1-testing.md](../development/h1-testing.md)のTask 13 Phase A節とPhase B runbook。

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
| 実provider route（OpenAI・Anthropic・OpenAI互換・ChatGPT） | — | **UNVERIFIED**。Phase B runbookでのみ実行する |

- 1 ignoredは `measure_running_host_rss`（Task 12の手動計測fixture）であり、pass数へ加算しない。
- **spikeの73件はhernessのpass数へ加算していない。** spikeは設計選択の証拠であり、本実装のtest結果ではない。
- desktopのPID・startup_msはこの実行の値であり、性能目標ではない。

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
| Connection: OpenAI・Anthropic・OpenAI互換の各経路をローカルmockで検証。ChatGPTのcallback・state・refresh・取消し・port競合、接続ごとの秘密と同時refresh分離 | automated / mock | `tests/engine.rs`の各provider tool往復・終端・取消し、`tests/oauth.rs`のstate/nonce/PKCE/port競合/refresh/revoke、`tests/connections.rs`のrefresh直列化 | 確認済み（mock）。**実接続はUNVERIFIED** |
| Tauri / security: 信頼main UIだけが許可変更・実行・資格情報保存を呼べる。custom commandの公開範囲、remote origin/previewの拒否、生成HTMLをprivileged DOMへ入れない | automated / desktop | `src-tauri/src/guard.rs` unit、`tests/desktop.rs`の`trusted_main_origin...`・`ui_uses_text_only_rendering...`・`project_open_rejects...`、実Tauri smoke/close/quit | 確認済み。command ACLは`build.rs`と`capabilities/main.json` |
| Lifecycle: 実window閉鎖後の継続、quit中の承認待ち・shell・stream停止、保存と別process復元、強制終了後の照合待ち | automated / desktop | `tests/desktop.rs`のnormal/unconfirmed/force/crash worker、`explicit_shutdown_stops_a_managed_shell_group`、`closed_window_runtime...`、実Tauri close/reopen/quit | 確認済み（active runが10秒を超えるGUI選択操作はmanual test未実施） |
| 実接続の受入: 利用者が許可した検証用接続で、対象API経路とChatGPT login・更新・取消し・実要求を確認 | real | なし | **UNVERIFIED**（Phase B） |
| H1受入の合成条件: 自動検証、実Tauriと選定adapterの接続、実接続の確認結果 | composite | 自動検証・実Tauriは確認済み。実接続が未確認 | **未完了** |

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
| OpenAI APIキー → openai-responses | `openai_api_key_text_turn...`、`openai_tool_round_trip...`、auth失敗test | UNVERIFIED | `--real-check` evidence: provider=openai, model, endpointClass=openai_responses, terminal=completed, latency, usage |
| Anthropic APIキー → anthropic-messages | `anthropic_tool_round_trip...`、auth失敗test、cancel test | UNVERIFIED | 同evidence: endpointClass=anthropic_messages |
| OpenAI互換 → openai-completions | `openai_compatible_tool_round_trip...`、auth失敗test、cancel test | UNVERIFIED | 同evidence: endpointClass=openai_completions、origin |
| ChatGPT login/callback/state/PKCE/ID token | `tests/oauth.rs` 29件 | UNVERIFIED | 実browser login、ID token/JWKS検証、plan scope、account選択 |
| ChatGPT catalog/Responses/終端 | `chatgpt_uses_the_public_catalog...`、incomplete/early disconnect/failed usage-limit test | UNVERIFIED | `--list-models`と`--real-check`のcatalog count・terminal=completed・usage |
| ChatGPT refresh | `refresh_rotates_tokens_and_concurrent_refreshes...` | UNVERIFIED | `--real-check --refresh` terminal=refreshed、Keychain回転確認 |
| ChatGPT sign-out/revoke | `sign_out_removes...`、`sign_out_confirms...`、`sign_out_selected...`、`auth::https`のempty 200 test | UNVERIFIED | `--real-check --sign-out`のremoteRevokeとlocal削除、Keychain不在確認 |
| 実Keychain | `src-tauri`のKeychain adapter fake testのみ | UNVERIFIED | 検証用項目の作成・削除・不在確認（Phase B） |

## 明示的な除外・未確認

- **spikeの73件は数えていない。** `docs/research/2026-11-07-pi-rust-spike.md`は設計根拠。
- `measure_running_host_rss` は手動fixtureで、自動testのpassではない。
- 実Tauriのclose button人間クリック、macOS dock reopen、quit猶予後のkeep waiting/force quitのGUI操作は自動化していない。controllerの判断はunit test、復旧は別process fixtureで確認した。
- 実providerの応答・料金・利用枠・認可条件・Keychain項目はPhase Aで一切触れていない。
- 実接続が未確認の間、ChatGPT loginや各APIキー経路を「利用可能・完成済み」と表示しない。mock成功を実接続成功として扱わない。
- H2の評価器、H3のHTML同期、H4のTask進行、H5の配布は開始していない。
