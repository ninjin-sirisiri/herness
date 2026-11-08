# H1 ChatGPT OAuth利用条件と公式フローの確認（2026-11-08）

Task 8の実装直前に、OpenAIの現行「Sign in with ChatGPT / token sharing for open-source apps」文書を再確認した記録。実装はmockと`127.0.0.1` loopback listenerだけを使い、OpenAIのhostへは接続していない。

## 確認日と対象

- 確認日: 2026-11-08
- 確認した公式ページ:
  - https://developers.openai.com/siwc/token-sharing-open-source
  - https://developers.openai.com/siwc/token-sharing-open-source/sign-in
  - https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions
  - https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- 実装した契約version: 1。hernessの変更は `crates/herness-core/src/connections/` と `crates/herness-engine-pi/src/auth/`、testは `tests/runtime/tests/oauth.rs`。

## 適用条件（公式文書の記載）

- overviewは「ChatGPT plan usage」を、**open-source / locally hostedなapp**向けの任意機能として説明している。paidまたはremotely hostedなappで提供する場合は[interest form](https://openai.com/form/sign-in-with-chatgpt-interest/)を完了するよう求めている。
- このflowはOAuthのpublic clientとして動的登録し、初回sign-inで**user-defined agent**を登録する。client（利用者が認可する登録）とagent host（toolが動く環境）を分け、`ext_agent_host_id`をhostごとに安定させる。
- 利用者のChatGPT会話その他のaccount contextへのaccessを与えるものではない。Responses APIの対象requestに限る。
- 初回登録は`client_id=dynamic_agent_client`と`agent_name_hint`、永続化済み`ext_agent_host_id`を使う。`dynamic_agent_client`は登録の入口であり、保存・token exchangeに使うissued client IDではない。
- 以降のsign-inは、そのaccount/workspaceで発行済みの`client_id`を再利用し、`agent_name_hint`を送らない。保持している`id_token_hint`と保存済みemailの`login_hint`を任意で送れる。
- clientはuserとworkspaceにboundされる。hostは別で、同じuser/workspaceでもhostごとに異なる`ext_agent_host_id`を持つ。

## hernessへの適用判断（gate）

hernessは次の状態にある。

- macOS上で動く**locally hosted**なdesktop appであり、remote serviceではない。
- 未公開で、商用提供もしていない。
- **licenseは未決定**で、open-sourceとして配布もしていない。
- 実accountでのlogin・model requestはまだ許可されていない（Task 13の別途許可が必要）。

したがって、Task 8で確認できた適合範囲は**local・unpublished・non-commercialの開発利用**に限る。実装は`TermsGate::LocalUnpublishedUse`だけを許可し、次は行っていない。

- 公開、配布、licenseの選択、open-source化の宣言
- 有償提供、remote hosting、interest formの提出
- OpenAI hostへの実接続、実login、実credentialの作成・読取り

`ChatGptAuthConfig`の既定gateは`Closed(ConditionsUnconfirmed)`で、hostがこの記録を確認して`LocalUnpublishedUse`を明示した場合だけ開発用に開く。`TermsGate::Closed`は`LicenseUndecided`、`PublishedOrDistributed`、`PaidOffering`、`RemoteHosted`、`ConditionsUnconfirmed`を明示的に返し、login attemptを開始しない。公開・配布・商用化・remote hostingへ進む場合は、このgateを人間の判断なしに開けない。open-source条件を満たすか、paid/remoteとしてinterest formが必要かを再確認する。

この判断は「open-sourceでない個人用buildは無条件に許される」という主張ではない。公式文書のlocally hosted向け説明の範囲で開発を続け、配布・提供条件が変わった時点で停止して人間へ戻す、という限定的な確認である。

## 確認したendpointとparameter

### Authorization

- endpoint: `https://auth.openai.com/api/accounts/authorize`
- 初回登録:
  - `client_id=dynamic_agent_client`
  - `agent_name_hint=<appの実際の名前>`（初回だけ。再認可では送らない）
  - `ext_agent_host_id=<hostごとに安定したopaque ID>`
- 再認可:
  - `client_id=<issued client ID>`
  - `ext_agent_host_id=<同じhost ID>`
  - 任意: `id_token_hint=<前回保持したID token>`（期限切れでもaccount識別には使える）
  - 任意: `login_hint=<検証済みID tokenのemail>`
- 共通:
  - `response_type=code`
  - `redirect_uri=http://127.0.0.1:<port>/auth/callback`
    - listenerをbrowserより先に起動する。
    - scheme・host・pathは固定し、可変なのはportだけ。
    - `localhost`へ置換しない。`/callback`と`/auth/callback`を混同しない。
    - 同じattemptではauthorizeとtoken exchangeに同じURIを送る。
  - `scope=openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`
  - `resource=https://api.openai.com/v1`
  - `state=<attemptごとのfresh random>`
  - `nonce=<attemptごとのfresh random>`
  - `code_challenge_method=S256`
  - `code_challenge=<PKCE verifierのSHA-256 base64url、paddingなし>`

### Callback

- 成功時: `code`、`state`、新規登録では発行された`client_id`、任意で`scope`。
- 再認可では`client_id`を省略できる。省略時は保存済みのclient IDを使う。
- callbackが異なる`client_id`を返した場合は、選択中accountの登録を置き換えず拒否する。
- `error=access_denied`は`state`を検証してからattemptを終了し、codeを交換しない。

### Token exchange

- endpoint: `https://auth.openai.com/api/accounts/oauth/token`
- `authorization_code` grantをform-encodedで送る。
- 送る値: 発行済み`client_id`、`code`、`code_verifier`、authorizeと同一の`redirect_uri`、同一の`resource`。
- client secretは不要。`dynamic_agent_client`をexchangeに使わない。
- `invalid_grant`はcodeを破棄し、保持しているissued client IDで新しいauthorizeをやり直す。

### ID tokenとscopeの検証

- ID tokenの署名をOpenAIの公開JWKSに対して検証する。
- issuer、発行済みclient IDと一致するaudience、expiry、attemptのnonceを検証する。
- 検証済み`sub`をaccount identityとする。emailと`sub`はworkspace identifierではない。
- 発行済みclient IDと検証済みidentityの組で登録を分離する。
- token responseのgranted scopeに`chatgpt.tokens.use.direct`があることを確認してからChatGPT plan usageを有効とする。有効なID tokenだけではplan usageを許可しない。

### Credentialの保存とrefresh

- 公式文書はapp-definedな保護file（例: `~/.config/...`、Unix `0600`）を例示する。hernessはこれより厳しく、**macOS Keychainだけ**にaccess/refresh/ID tokenを保存し、平文file・DB・event・logへfallbackしない。
- issued client IDと検証済みaccount identityごとに別のcredential recordを保つ。同じemailでも登録を混ぜない。
- 検証済みidentity、token、granted scope、expiry、保持ID tokenを保存する。ID tokenは`id_token_hint`用に保持するが、通常のrequestへは使わない。
- refreshは`grant_type=refresh_token`、保存済みissued `client_id`、`refresh_token`、`resource=https://api.openai.com/v1`をform-encodedで送る。`scope`は省略してgrantを維持する。
- access token、expiry、granted scope、回転するrefresh tokenを一括で置き換える。同じsessionのrefreshを直列化する。
- 失敗時は古いmaterialを保持し、期限切れtokenをfreshとして使わない。

### Sign-out / revoke

- 公式文書は`https://auth.openai.com/.well-known/openid-configuration`の`revocation_endpoint`を使い、`token=<refresh_token>`、`token_type_hint=refresh_token`、issued `client_id`をform-encoded `POST`する。空のHTTP 200が成功。
- network failure/5xxはrefresh tokenが残っている間backoff retryする。確認できずにlocal sign-outする場合は、local tokenを消し、**remote revocationを確認できなかった**と利用者へ伝える。ChatGPT Settingsからdisconnectできる。revokeはregistered client自体を削除しない。
- Task 8はOIDC discoveryもrevocation endpointも取得していない。`TokenTransport::revoke`は境界だけを定義し、結果は`RemoteRevokeStatus::{NotAttempted, RequestAcceptedUnverified, FailedUnverified}`のいずれかで、`confirmed`を返さない。local credential（access/refresh/ID token）は削除する。

## 実装上の差分・未確認事項

- **実HTTPなし:** token exchange、refresh、revoke、JWKS取得は注入trait。Task 9が実transportを接続する。Task 8のtestはscripted mockと合成署名鍵だけを使う。
- **JWKS URI:** 公式ページは「OpenAIの公開JWKS」とだけ記載し、このtaskではdiscovery/JWKS取得を実行していない。issuerは`https://auth.openai.com`として検証する。実際のJWKS URIとkey rotationはTask 9/13で確認する。
- **revocation discovery:** 未取得。sign-outはremote revokeを未確認と報告する。
- **host ID:** `urn:uuid:<UUIDv4>`を使う。公式が推奨する`urn:ietf:params:oauth:jwk-thumbprint:...`は「optional、private key possessionは検証されない」とされているため採用しない。UUID形式は公式にsupported alternativeと明記されている。
- **agent name:** 公式はappの実際の名前を一貫して使うよう求める。Task 8は設定値`agent_name`を初回登録だけに送る。Task 11で実際の製品名を設定する。
- **account mappingの永続化:** 発行済みclient ID・検証済みsubject・emailの非secret mappingはTask 8ではin-memory。Task 10/11で既存storeへ永続化する。secretはKeychainだけに置く。
- **redirect port:** defaultはOS割当。固定port競合時は別portへfallbackし、scheme/host/pathは変えない。
- **logoutのlocal削除:** Keychain itemの削除を確認してから成功を返す。削除失敗時は成功と表示しない。

## 既知事実のcross-check結果

| 確認項目 | 結果 |
| --- | --- |
| authorize endpoint `https://auth.openai.com/api/accounts/authorize` | 公式sign-inページで確認 |
| token endpoint `https://auth.openai.com/api/accounts/oauth/token` | 公式sign-in/profilesページで確認 |
| 初回`dynamic_agent_client` + `agent_name_hint` + `ext_agent_host_id` | 確認 |
| 発行済みclient IDの再利用、再認可で`agent_name_hint`省略 | 確認 |
| `id_token_hint` / `login_hint` | 確認（任意、同じaccountのhint） |
| `response_type=code` | 確認 |
| `127.0.0.1` loopback、scheme/host/path固定・portのみ可変、listener先行、同一URIでexchange、`localhost`不可 | 確認 |
| scope `openid profile email offline_access resource.invoke chatgpt.tokens.use.direct` | 確認 |
| `resource=https://api.openai.com/v1` | 確認 |
| fresh `state`・`nonce`・PKCE S256 | 確認 |
| callbackの`code`・`state`・issued `client_id`、`dynamic_agent_client`を保存しない | 確認 |
| form-encoded `authorization_code` grant、secret不要、issued client ID使用 | 確認 |
| ID tokenの署名・issuer・audience・expiry・nonce検証、`sub`がidentity | 確認 |
| granted scopeに`chatgpt.tokens.use.direct`が必要 | 確認 |
| issued client ID + verified identityごとのcredential分離 | 確認 |
| 回転refresh tokenの一括置換、session単位の直列化 | 確認 |
| sign-out時のrevocation endpointと未確認表示 | 確認（endpoint自体は未取得） |
| open-source / locally hosted向け、paid/remoteはinterest form | 確認 |
| license/distribution gate | **未決定**。local unpublished useだけを許可し、公開・商用・remoteはclosed |

## 参照

- OpenAI, Sign in with ChatGPT — Overview: https://developers.openai.com/siwc/token-sharing-open-source
- OpenAI, Registration and sign-in: https://developers.openai.com/siwc/token-sharing-open-source/sign-in
- OpenAI, Accounts and sessions: https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions
- OpenAI, Models and inference: https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- OpenAI interest form: https://openai.com/form/sign-in-with-chatgpt-interest/
