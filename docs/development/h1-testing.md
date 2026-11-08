# H1 runtime: 依存方針とテスト手順

H1のRust workspaceにおけるtoolchain、依存方針、テストコマンド、Task 1で固定した契約の検証範囲を記録する。正本仕様は [H1 runtime design](../sdd/specs/2026-11-07-h1-runtime-design.md)、計画は [H1 plan](../sdd/plans/2026-11-08-h1-runtime.md)。

## Toolchain

- `rust-toolchain.toml` は `1.97.1-aarch64-apple-darwin` を固定する。このworktreeを作成したmacOS arm64環境に導入済みのstable toolchainであり、`rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)` と一致する。
- workspaceはedition 2024、resolver 3、`rust-version = "1.97.1"` を使う。
- `Cargo.lock` を追跡する。依存更新時はlock差分とadapter互換テストを同じ変更で確認する。

## 依存方針

`herness-core` の依存は次の4つに限定する。

| crate | 用途 | 理由 |
| --- | --- | --- |
| `serde` (`derive`) | 公開契約のJSON表現 | version付きevent・error・引数schemaの安定した直列化 |
| `serde_json` | event payload | payloadを型付きenvelope内の構造化JSONとして保持 |
| `sha2` | 最終tool引数のSHA-256 digest | 承認を人間が確認した最終引数へ束縛する。I/O・network・秘密の保存には使わない |
| `uuid` (`v4`) | project・scoped ID・connection ID | 再起動をまたいで衝突しない安定ID |

- async runtime、HTTP client、DB、Tauri、pi crate、時刻整形crateはTask 1のcoreへ入れない。checkpointはadapter所有のversion付きopaque bytesとして運び、coreは解釈しない。
- `tests/runtime` は `herness-core` にだけ依存するlibrary crate。black-box test用に `serde_json` をdev-dependencyとする。
- 依存追加は、そのTaskのreportで用途とcoreの依存方向（store・engine・Tauriへ依存しない）への影響を説明する。
- secretは `SecretString` / `ResolvedCredential` に閉じ込め、`Serialize`・`Display` を実装しない。`Debug` は `[REDACTED]` を返す。event・error・checkpoint・connection情報へtokenやproviderの生errorを入れない。
- 合成fixtureだけを使い、実APIキー、実OAuth token、既存Keychain項目、外部serviceを通常テストから参照しない。

### Git対象外

`.gitignore` は `.sdd/` の行を維持したまま、Rust build成果物（`/target/`）、一時DB（`*.db`, `*.sqlite`, journal/WAL/SHM）、ローカル資格情報（`*.credentials`, `credentials.local.json`, `.env*`, `.secrets/`）を除外する。

## テストコマンド

Task 1の受入で実行するコマンド:

```sh
cargo test -p herness-core
cargo test -p herness-runtime-tests
cargo test -p herness-runtime-tests --test permissions
cargo fmt --all -- --check
```

追加の静的検査:

```sh
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

- testはnetwork・外部service・実資格情報を必要としない。依存取得後の通常実行はofflineで完結する。
- 後続Taskでstore・engine・Tauriを追加しても、`herness-core` からそれらへの依存を追加しない。workspace全体のtestは `cargo test --workspace --locked` で実行する。
- 実接続・実Keychain・実Tauriの確認はTask 13の別途許可まで行わない。mock成功を実接続成功として扱わない。

## Task 1で固定した契約と検証

`herness-core` のtestは次を確認する。

- **contract version:** 1のみ受付。0・2は `UnknownContractVersion`、非数値は `InvalidContractVersion`。event JSONの `contractVersion: 2` はdeserialize時に拒否する。
- **ID:** project・agent・session・run・operationはtypedかつproject-scoped。別projectのIDは `CrossProjectReference` で拒否する。kindの異なるprefixや不正UUIDも拒否する。
- **run状態:** `running`, `awaiting_approval`, `paused`, `interrupted`, `idle`, `failed` の6つ。`idle` は「engineに未完了の応答・tool callがない」状態として文書化し、Task/goal完了を表す状態や `completed` 状態を持たない。
- **rationale / purpose:** trim後に非空、最大1,000 Unicode scalar values。空、空白のみ、1,000、1,001、非ASCII（`あ`）、astral plane（`😀`、UTF-16では2,000 code units）で境界を検証する。byte長・UTF-16長は使わない。
- **tool schema:** read・search・write・edit・bash。offset/limit/maxResults/timeoutMsの0、空path/query、未知field、空のrationale/purpose、1,001文字のpurposeを拒否する。
- **frozen operation:** 最終引数・cwd・policy版・許可モードをprivate fieldへ固定し、deserialize時も再検証する。別projectのoperation IDとtool/引数の不一致を拒否する。
- **event:** `contractVersion`、project/agent/session/run、任意のoperation、sequence、kind、時刻、payloadを持つ。sequence 0とproject混在を拒否する。
- **checkpoint:** `formatVersion` 付きopaque bytes。0を拒否し、任意bytesのround-tripとDebugのredactionを確認する。coreは内容を解釈しない。
- **history:** 既定100件、上限500件。0件・501件、cursor 0を拒否する。
- **connection:** 公開JSONはconnection ID・provider・model・認証方式・状態だけを含み、token/secret/authorization fieldを持たない。
- **ports:** engine・store・credential・permission evaluatorはtrait objectとして利用可能。fake実装でcommit、checkpoint、history、secret redaction、configured/automatic modeの可用性を確認する。
