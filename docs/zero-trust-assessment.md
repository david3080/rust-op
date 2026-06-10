# Zero Trust 自己評価 ＋ 前提台帳（Phase0）

rust-op を Anthropic「[Zero Trust for AI Agents](https://claude.com/blog/zero-trust-for-ai-agents)」（2026-05, 全36ページ）の枠組みに突き合わせた**自己評価**と、rust-op が安全のために前提としている **load-bearing な条件の台帳**。

二つの目的を1つにまとめる:
1. **前提の明示**（本プロジェクトの本来ゴール）= rust-op の安全性が「何が成り立てば」保証されるのかを表に出し、そこから**必要な運用要件を導出**する。
2. **Zero Trust 自己評価** = 枠組みの各 control に対し rust-op がどこまで、どの検証層で担保しているかを正直に並べる。

> **これは自己評価であって第三者保証ではない。** 下表の ✓ は「**その層で**検証済み」を意味し、「rust-op のコード全体が正しいと証明された」を意味**しない**。とくに L1（Tamarin）は*モデル*を、L3（Kani）は*ごく少数の純粋述語*を検証するに留まる。広範なコード↔モデルのギャップは**未検証**である（[GAP の節](#gap-検証していないこと)を必ず参照）。

---

## 0. 検証層の定義と「✓」の読み方

| 層 | 何を検証/担保するか | 限界（✓ が意味しないこと） |
|---|---|---|
| **L1 Tamarin** | プロトコル**モデル**が、明示した前提の下で Dolev-Yao 攻撃者に耐える | 実 Rust コードがモデルに一致することは示さない |
| **L2 暗号/ライブラリ** | 署名・ハッシュ・base64・定数時間比較を**正しいと仮定**（p256/sha2/base64/subtle） | この層は rust-op では**証明していない**（CryptoVerif/EasyCrypt の範囲） |
| **L3 Kani** | 実コードの**ごく少数の純粋述語**を全入力で機械検証（panic/オーバーフロー/論理） | 約11k 行のうち橋を架けた数述語のみ。残りは未検証 |
| **L4 運用** | 分散原子性・鍵秘匿・TLS など**運用で担保**する前提 | コードの外。運用が崩れれば上位層の前提が崩れる |

「✓ L1」=「モデルでは証明、コードは別」。「✓ L3」=「この述語だけはコードでも証明」。**全層が揃って初めて end-to-end**であり、現状は揃っていない。

---

## 1. rust-op の load-bearing 前提台帳（本評価の核心）

「これが破れると安全性が崩れる」条件と、そこから**導出される運用要件**。各前提は、対応する Tamarin lemma の**成立前提**でもある（＝モデルが「この条件下で」と置いたもの）。

| ID | 前提 | 層 | 破れると | 導出される運用要件 / 担保 |
|---|---|---|---|---|
| **A1** | **Firestore CAS の原子性**（code/jti/CIBA/refresh の単回消費を `cas_take`＝updateTime 条件付き削除で実現） | L4 | 認可コード/トークンの二重発行・リプレイ | Firestore のリージョン/SLA 維持、`cas_take` 経路を全消費に適用、回帰テスト `store::code_reuse_revokes_issued_tokens`。L1 では Tamarin `Once`／linear fact で単回性を証明済（モデル） |
| **A2** | **KMS 署名鍵がプロセス外で非展開**（ES256/RS256, Cloud KMS） | L4 | 全署名の偽造 → OP なりすまし（Tamarin の `RevealOP` が**起きない**前提） | KMS 権限最小化・鍵ローテ・fail-closed（鍵不在は起動拒否）。Secret Manager / 起動時一時鍵への fallback は監査対象 |
| **A3** | **TLS 終端の機密性**（Cloud Run / Firebase Hosting） | L4 | トークン平文窃取が容易（Tamarin は「鍵への暗号化」で抽象化） | TLS 強制・HSTS・証明書管理。issuer=`https://oidc.sonrisa.co.jp/oidc` |
| **A4** | **暗号/エンコーディングライブラリの正当性**（p256, sha2, rsa, ed25519, base64, subtle `ct_eq`） | **L2** | 署名検証バイパス・タイミング漏洩等 | [`docs/crypto-assumptions.md`](./crypto-assumptions.md) で3分解: **(a) 設計安全性＝文献で確立・引用可（ECDSA/EdDSA/RSA の EUF-CMA, SHA-256 ROM/CR）/ (b) 実装正しさ＝クレート監査・テストベクタに依拠（深掘りは hax/Aeneas）/ (c) 定数時間＝subtle に依拠**。cargo-deny（SHA ピン）で供給網監査。残余 (b)(c) は GAP |
| **A5** | **DPoP 時刻スキュー ≤60s / jti TTL 有界** | L4＋L3 | リプレイ窓の拡大・jti 保持の無限肥大 | clock 同期。jti 保持窓は **L3 `jti_ttl_is_bounded` で ≤3600s 有界を証明済** |
| **A6** | **試験面の本番排除**（`CONFORMANCE_CLIENTS_ENABLED` / `FIDO_CONFORMANCE_ENABLED`） | L4 | 試験用クライアント/エンドポイントが本番で有効化 | 本番デプロイで両フラグ無効を確認（現リビジョンで `/fido/*`=404、試験クライアント排除） |
| **A7** | **client_assertion exp 上限（3600s）＋ jti 単回** | L3＋L1 | 長命 assertion のリプレイ | **L3 `exp_in_window` で窓検査＋オーバーフロー安全を証明済**。jti 単回は A1 に依存 |

> この台帳が「前提を明示し、必要な運用を導出する」という本来ゴールの中身。**proof は前提付き**であり、前提（A1–A7）は運用（L4）と仮定（L2）で支える、という構造を崩さないこと。

### 1.1 トークン/資格情報の寿命（実測 2026-06-09）

枠組みは「token lifetimes **measured in minutes**」を求める。実コードの値:

| 種別 | TTL | 場所 | 評価（ZT「分単位」） |
|---|---|---|---|
| **access token** | **900s = 15分** | `firestore_store.rs ACCESS_TTL` / `grants.rs expires_in:900` | ○ 分単位を満たす |
| **id_token** | **900s = 15分**（`exp = iat + 900`） | `grants.rs:78` | ○ |
| client_assertion exp 上限 | 3600s（＋jti 単回） | `client_auth.rs MAX_ASSERTION_LIFETIME_SECS`（L3 `exp_in_window` 検証済） | ○ 一度きりの認証材料ゆえ可 |
| DPoP proof jti | 300s = 5分 | `dpop.rs JTI_TTL` | ○ |
| PAR request_uri | 60s | `par.rs TTL_SECS` | ○ |
| CIBA auth_req | 300s = 5分 | `ciba.rs TTL_SECS` | ○ |
| refresh token | 14日 | `firestore_store.rs REFRESH_TTL` | 標準（短命 access の更新用。単回回転＋**DPoP 鍵束縛**＋盗難検知は A1 に依存） |
| session cookie | 7日 | `firestore_store.rs SESSION_TTL` | ブラウザセッション。トークンではない |

→ **bearer/proof 系はすべて分単位**で枠組みの bar を満たす。長命なのは refresh（14日）と session（7日）のみで、いずれも bearer access ではない。refresh は短命 access を更新する設計上の長命であり、その安全性は A1（単回消費の CAS 原子性）に依存する。

> **2026-06-10 発見・修正（DPoP sender-binding の refresh への適用漏れ）**: refresh token が DPoP 鍵に束縛されていなかった（`RefreshToken` に jkt 無し）。public client（`token_endpoint_auth_method: none`）の refresh を窃取すると、攻撃者が自鍵の proof を作るだけで被害者アカウントの sender-bound access token を取得でき、DPoP（RFC 9449）が refresh 経路で完全バイパスされていた。`mobile-rp`/`demo-rp`（ともに public + `dpop_bound`）が該当。**修正**: `RefreshToken.jkt` を追加し発行時に束縛、`RefreshTokenGrant` で消費前に提示 proof の jkt と照合（不一致は `invalid_dpop_proof`、被害者 RT は消費しない＝DoS も防止）、ローテーションで束縛を継承、束縛なし RT は public client で拒否。回帰テスト: `grants::tests::regression_stolen_refresh_token_cannot_rebind_to_attacker_key` ほか。これは authorization_code 経路（`grants.rs:180-189` で既に jkt 照合）との非対称を解消したもの。

---

## 2. Zero Trust Part III（6制御領域）× rust-op × 層

枠組みの層は **Foundation / Enterprise / Advanced**。rust-op は OAuth/OIDC **認可サーバ**＝枠組みが Foundation で必須とする「**identity provider / 短命資格情報基盤**」そのもの（原文 Part III Service authentication / Phase 5–6 が名指し）。

| ZT 領域 | rust-op の充足 | 層タグ | 検証アーティファクト | 依存前提 | 評価 |
|---|---|---|---|---|---|
| **1. Identity & authentication** | OAuth IdP として短命トークン発行（F 直撃）。private_key_jwt+JWKS で暗号クライアント ID（E 相当）。DPoP で sender-bound。passkey で人間認証 F バー。KMS で鍵非展開 | L1＋L3＋L2 | Tamarin #1/#4/#5、Kani `pkce_method_no_downgrade`/`redirect_uri_match_is_exact`/`exp_in_window` | A2,A4 | **F 完全＋E 相当をモデル/述語で裏打ち**（コード全体ではない） |
| **2. Access control / least agency** | RAR mandate scoping、scope/aud 制限、DPoP cnf（鍵保持者のみ）、redirect 完全一致、単回コード、step_up | L1＋L3 | Tamarin #2/#3、Kani `redirect_uri_match_is_exact` | A1,A4 | **資格情報側の scoping を裏打ち**。実行時 sandbox/網分離は管轄外 |
| **3. Observability & auditing** | `tracing` 構造化ログ＋**全リクエストに request_id 付与・ドメインログ（`event=token_issued` 等）に連鎖**（`web::request_trace`）。異常検知/不変監査(E/A)は未 | L4 | `web::request_trace`（Request-ID 連鎖, Foundation tier） | — | **Foundation covered（Request-ID 連鎖）。E/A は未着手** |
| **4. Behavioral monitoring & response** | アラート可能イベント（`client_auth_failed`/`login_failed`/`kms_sign_failed`/http 5xx 等）を構造化 emit 済。閾値・期待ベースライン・アラートポリシーを `docs/observability-alerts.md` に定義（実適用はゲート）。自動 triage/統計的異常検知/SOAR は未 | L4 | [`docs/observability-alerts.md`](./observability-alerts.md)＋既存イベント | — | **Foundation（信号＋閾値定義）covered。実適用ゲート、E/A 未** |
| **5. Input validation & output** | プロトコル入力堅牢性は一部（JAR/PAR・exp/nonce/jti・htu 正規化）。**output-control: ログ内 sub を擬似化**（`web::pseudonymize_sub`、平文メール非残留）。LLM 向け classifier は別物 | L3 | Kani `strip_query_fragment_safe`/`exp_in_window`、`web::pseudonymize_sub` | A4 | **入力堅牢性＋ログ PII 擬似化○、classifier は別スコープ** |
| **6. Integrity & recovery** | 全 JWT/JWS 署名検証（偽造不能を*モデルで*証明）、KMS fail-closed、Cloud Run リビジョン rollback、cargo-deny。手書き変換 `pad32` は **L3 検証済**（panic/下溢れ非発生＋正当性） | L1＋L3＋L4 | Tamarin 偽造不能、Kani `pad32_safe`、過去修正 | A2,A4 | **部分一致（`pad32` は L3 verified）** |

---

## 3. Zero Trust Part IV（8フェーズ）対応（要約）

| フェーズ | rust-op との関係 | 状態 |
|---|---|---|
| 1. Identify requirements | **本ドキュメント（前提台帳）がこれ** | 着手（本書） |
| 2. Manage supply chain | cargo-deny SHA ピン CI。AI-BOM/Scorecard/reachability 無 | 部分 |
| 3. Define agent boundaries | rust-op は agent でない。agent を縛る scoped 資格情報を**発行する側** | N/A（供給側） |
| 4. Defend prompt injection | LLM 層。別スコープ | 管轄外 |
| 5. Secure tool access | 「agent identity に束縛した短命トークン」＝**DPoP を供給** | **直撃**（L1 #2） |
| 6. Protect agent credentials | 短命 IdP 発行・per-client ID・埋め込み無し・失効（DCR register/revoke-client） | **直撃**（L1 #1, A2） |
| 7. Safeguard memory | agent memory は別。rust-op 自身の状態リプレイ防止＝単回 CAS（A1） | 管轄外（※A1 が類似機構） |
| 8. Measure what matters | Request-ID 相関の土台あり（`web::request_trace`）。dwell time/異常検知は未 | Foundation 着手 |

---

## 4. GAP（検証していないこと）

**最重要の節。** ✓ の裏で**何が未検証か**を明示する。枠組み自身が「不確かなら foundational controls はまだ work が要る」と言う姿勢に従う。

- **広範なコード↔モデルのギャップ**: L3（Kani）は5述語のみ橋を架けた。残る約11k 行は Kani 未検証。L1 が証明するのは*モデル*であって実コードではない。
- **L2 暗号は仮定**（A4, [`docs/crypto-assumptions.md`](./crypto-assumptions.md) で3分解）。**(a) 設計安全性は文献で確立・引用可**だが、**(b) クレートの実装正しさ**（深掘りは hax/Aeneas）と **(c) 定数時間**（subtle 依拠）は残余。rust-op 内で機械証明はしていない。
- **検知・対応層**: 領域3 Observability は **Foundation（Request-ID 連鎖）実装済**（Step3）、領域4 Behavioral monitoring も **Foundation（アラート信号＋閾値定義）まで**（`docs/observability-alerts.md`）。**残**: アラートポリシーの実適用（通知先選択ゆえユーザ gate）、不変監査ログ・統計的異常検知・自動応答・agentic SOAR（Enterprise/Advanced・Part V）。
- **agent 固有領域**（prompt injection・tool access・memory poisoning）= rust-op の管轄外。ただし rust-op の scoped・sender-bound・単回な資格情報は、これらが起きても**blast radius を封じ込める**。
- **AI-BOM / attestation / self-healing**（領域6 Advanced）未着手。
- **rate-limit は friction であって barrier ではない**（枠組み Phase 5 が明言: 「buy time but do not stop a determined agentic attacker」）。DCR の rate-limit は補助であり load-bearing にしない。
- ~~アクセストークン実 TTL の「分単位」posture が未文書化~~ → **測定・文書化済（§1.1）**: access token・id_token とも 900s=15分で枠組みの「minutes」を満たす。長命は refresh（14日）/session（7日）のみで bearer access ではない。
- **Foundation の "automated first-pass triage"** は純粋に運用側で未構築。

---

## 5. Step が flip する行（本評価と実装の連動）

本評価を起点に、後続 Step が**特定の gap を covered に変える**:

- **Step2 ✓ 完了**（Integrity 変換コードの Kani 橋, Kani `pad32_safe`）→ §2 領域6 の「手書き変換 `pad32` 未検証」を **L3 verified** に flip 済（`32 - b.len()` の usize 下溢れ非発生＋スライス長一致＋左ゼロ埋め/末尾保存を全入力で証明）。b64url は base64 クレート委譲＝**ライブラリ（A4 で仮定、検証対象外）**、thumbprint は固定フォーマット＋SHA256＝**構成上正しい（lock）**、と正直に区別した（手書き変換は pad32 のみ）。
- **Step3 ✓ 完了**（L4 ランタイムモニタ Foundation, `web::request_trace`）→ §2 領域3・§3 フェーズ8 の「Observability gap」を **Request-ID 連鎖（Foundation tier）covered** に flip 済。全リクエストに request_id を付与し、span でハンドラを囲んで既存ドメインログ（`event=token_issued` 等）に request_id を継承、応答に method/path/status/latency を1行記録、応答ヘッダにも返す。**秘密非ログを厳守**: query を含めず path のみ、ヘッダ/ボディ/Authorization/DPoP proof/トークンは一切記録しない。**閾値アラート（threshold/異常検知）と SOAR は対象外（Enterprise/Advanced）**。将来そこを足すなら `event=http_request` の status/latency_ms と `token_issued` 等を集計点（dwell time/coverage）として hook する。
  - **span 継承は単体テストで確認済**（`web::obs_tests`、本番と同じ `fmt().json()` 構成で span の request_id がドメインログに出ることを検証）。型検査では分からない核心挙動なので明示テスト。デプロイ時は実 `/token` で `http_request` と `token_issued` の両行に同一 request_id が出ることをスモークで確認すること。
  - **path パラメータ（`/login/{uid}`・`/ciba/{auth_req_id}/...` の uid/auth_req_id）は意図的にログする**＝識別子であって資格情報ではない（CIBA の auth_req_id はハンドル）。秘密が乗る query は除外済。誤記載でなく観測のための判断。
  - **未対応（follow-up・本 PR では広げない）**: Cloud Run/Firebase は `X-Cloud-Trace-Context`（W3C `traceparent`）を出すが本実装は `X-Request-Id` のみ踏襲＝本番ではほぼ毎回 uuid 採番でプラットフォーム側ログと ID が揃わない。内部相関（rust-op 自身のログ）は成立。プラットフォーム相関が要るならトレースヘッダ読取りを追加。

---

## 参照

- 概念の梯子と検証アーキテクチャ: [`docs/security-ladder.md`](./security-ladder.md)
- L1 Tamarin モデルと前提→機構対応: [`formal/README.md`](../formal/README.md)
- L3 Kani ハーネス: [`src/kani_harness.rs`](../src/kani_harness.rs)
