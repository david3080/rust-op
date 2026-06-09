# formal/ — rust-op のプロトコルを Tamarin で検証する

[`docs/security-ladder.md`](../docs/security-ladder.md) の「検証アーキテクチャ」の実体。
**プロトコル論理層**を記号的（Dolev-Yao 攻撃者）に検証し、各性質を支える**前提を表に出す**。
前提（抽象）→ rust-op の担保（具体）への対応づけが、この層の成果物。

## 実行

```sh
brew install tamarin-prover          # maxima/graphviz 等も入る
tamarin-prover --prove formal/oauth_code_pkce.spthy
# 対話GUIで眺める場合:
tamarin-prover interactive formal/oauth_code_pkce.spthy   # → http://127.0.0.1:3001
```

第一版は `sources`/`reuse` 補題が要る場合がある（open-chain や非終了が出たら追加して iterate）。
**「Tamarin が詰まる = 足りない前提が見える」こと自体が収穫**であって、最初から完璧な証明である必要はない。

## モデル #1: 認可コード + PKCE + クライアント認証 → トークン

対象は confidential client（private_key_jwt 相当 = DCR/FAPI クライアント）。フロー:

1. クライアントが `~v`(code_verifier) を生成し、`h(~v)`(code_challenge) を**フロントチャネル**（攻撃者可視）で送る
2. AS が認可コード `~code` を発行し redirect（攻撃者は code を**横取りできる**）
3. クライアントが code + `~v` + 署名(client_assertion) で**トークン要求**
4. AS が **code 単回消費 + クライアント認証 + PKCE(`h(v)=challenge`)** を検査し、トークンを**クライアント鍵へ暗号化(TLS抽象)** して配送

### 検証する性質（lemma）
| lemma | 主張 | 意味 |
|---|---|---|
| `executable` | 正直な実行が完了しうる | モデルが死んでいないことの健全性チェック |
| `code_single_use` | 同じ code から2トークンは出ない | 認可コードの単回性 |
| `token_secrecy` | 攻撃者は honest client のトークンを知り得ない（鍵漏洩がなければ） | 回線支配攻撃者への耐性 |

## 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-06-09 実測）

- `tamarin-prover --prove --auto-sources formal/oauth_code_pkce.spthy`
  → **3 lemma すべて verified**（処理 ~0.6s、wellformedness 全合格、追加 sources 補題は不要）。
  = 前提集合 {P-SINGLEUSE, P-VERIFIER, P-CKEY, P-REG, P-TLS} の下で、回線支配攻撃者に対し性質が**十分**に成り立つ。
  `token_secrecy` の証明は「攻撃者がトークンを知る唯一の道はクライアント鍵の Reveal」を示す＝**P-CKEY の必要性**を裏取り。
- **必要性の実験**: `oauth_code_NEG_no_singleuse.spthy`（`AS_Code` を persistent にして単回消費を外した変種）
  → `code_single_use` が **falsified（攻撃トレース発見）**、`token_secrecy` は verified のまま。
  = **原子的単回消費（P-SINGLEUSE）は“必要”**。外すと同一コードから2トークン（トークン要求のリプレイ）。
    単回性の役割は**コード再利用の阻止に特定**される（token_secrecy には影響しない）。
  = 段0「引換券は一度きり」の、**機械検証された必要十分**。
- **public client 変種** `oauth_code_pkce_public.spthy`（demo-rp / mobile-rp 相当 = `none` + PKCE、クライアント認証なし）
  → 3 lemma すべて verified。**PKCE が唯一の防御**として機能。
- **必要性の実験(PKCE)** `oauth_code_public_NEG_no_pkce.spthy`（public client から PKCE 検査を外す）
  → `token_secrecy` が **falsified（コード横取り攻撃トレース発見）**。
  = public client では **PKCE は“個別に必要”**。外すと攻撃者が横取りした code をそのまま交換しトークンを得る。
- **まとめ（#1 の前提導出が完成、nuance まで機械検証）**:
  - **confidential client**（private_key_jwt = DCR/FAPI）: クライアント認証 と PKCE は**冗長な多層防御**（各々単独で攻撃を阻止）。
  - **public client**（none = demo-rp / mobile-rp）: **PKCE が単独で必要**（外すと code 横取りが成立）。
  - **単回消費**（P-SINGLEUSE）は両者で必要。

## 表に出た前提 → rust-op の担保（本層の成果物）

| ID | モデルが要求する前提（抽象） | rust-op の担保（具体） |
|---|---|---|
| P-SINGLEUSE | 認可コードは**原子的に単回消費**される（`AS_Code` が linear） | store の code 消費（単回）。回帰テスト `store::code_reuse_revokes_issued_tokens` |
| P-CODEFRESH | 認可コードは**推測不能**（CSPRNG = Fr） | code 生成（乱数） |
| P-VERIFIER | PKCE の verifier は**秘密**で、`h(verifier)=challenge` を AS が検査 | `CheckPkce`（S256 のみ受理、`auth_checks.rs`） |
| P-CKEY | クライアント秘密鍵は**秘匿**（漏れると token_secrecy が破れる） | private_key_jwt（`client_auth.rs`）。rust-op は**公開鍵のみ保持** |
| P-REG | クライアントは**事前登録**され AS が公開鍵を知る | `with_client` / DCR（`clients` 登録、`resolve_client`） |
| P-TLS | トークン配送路は**機密**で正しいクライアントへ届く（モデルでは鍵への暗号化で抽象化） | TLS（Firebase Hosting / Cloud Run）＋ token endpoint |
| （攻撃者モデル） | In/Out を完全支配する回線攻撃者に耐える | — |

→ 「**`token_secrecy` は、攻撃者X(回線支配)に対し、前提 {P-SINGLEUSE, P-VERIFIER, P-CKEY, P-REG, P-TLS} の下で成り立つ**」。
これが目標「前提の明示」の1行。

## このモデルが示す“設計の洞察”

- **confidential client では、クライアント認証 と PKCE の両方が攻撃を止め、どちらか一方でも交換を阻止できる（多層防御）。**
  PKCE が**主役（必要）になるのは public client（クライアント認証なし）**の場合。→ 次版で public client を別 variant としてモデル化すると「PKCE の必要性」が見える。
- **単回性の必要性**は `token_secrecy` ではなく `code_single_use` に現れる。`AS_Code` を persistent にすると `code_single_use` が破れる（手元で試すと良い）。
- redirect_uri 完全一致は本版では未モデル（code 横取りは前提し、交換を client 認証+PKCE で阻止）。次版で redirect を明示するとコード**配送先**の制御が入る。

## 既知の限界 / 次版（ロードマップ）

- ユーザ認証/同意は抽象化（**WebAuthn は roadmap #4**）。
- public client（client auth 無し・PKCE 主役）は別 variant（次版）。
- TLS は「クライアント鍵への暗号化」で抽象化（実 TLS はサーバ認証）。次版で TLS セッションを明示。
- 第一版の lemma は `sources`/`reuse` 補題が要る場合あり。

ロードマップ（[`docs/security-ladder.md`](../docs/security-ladder.md) の「Tamarin モデリング・ロードマップ」）:
**#1 認可コード+PKCE（本ファイル）→ #2 DPoP 送り主束縛 → #3 CIBA+RAR マンデート → #4 WebAuthn → #5 ID token → #6 合成**。
各モデルが「防げる攻撃＋必要前提」を1セット産み、積むほど rust-op の前提集合が埋まる。

---

## モデル #2: DPoP 送り主束縛（RFC 9449）

`dpop_binding.spthy` — トークンの**利用フェーズ**（リソースサーバ RS での検証）に焦点。発行は #1 から抽象化。
**「盗まれた bearer アクセストークンは DPoP 秘密鍵なしには使えない」** を検証する。

フロー: AS が token に `cnf.jkt = h(DPoP公開鍵)` を束縛して発行 → クライアントは token + DPoP proof
（DPoP 鍵で署名、htm/htu/jti/ath を含む）を RS に提示 → RS は cnf.jkt 一致・proof 署名・jti 単回 を検査して許可。
攻撃者は token を窃取できる（`Steal_Token`）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
- `dpop_binding.spthy` → `executable` / `dpop_sender_constraining` **verified**（処理 ~0.8s）。
- 必要性の実験 `dpop_NEG_no_cnf.spthy`（cnf.jkt 検査を外す）→ `dpop_sender_constraining` **falsified（攻撃トレース発見）**。
  = **cnf.jkt 束縛検査は必要**。外すと攻撃者が盗んだ token に**自分の鍵の proof** を付けて RS を通せる。

### 表に出た前提 → rust-op の担保
| ID | 前提（抽象） | rust-op の担保 |
|---|---|---|
| P-DKEY | DPoP 秘密鍵は秘匿（漏れると束縛が無効） | クライアント側保持。rust-op は proof を検証するだけで**鍵を持たない** |
| P-CNF | RS は「proof の鍵 thumbprint = token の cnf.jkt」を検査 | `authenticate_token`（`at.jkt` と proof の jkt 一致）。introspection が cnf.jkt 公開 |
| P-PROOFSIG | DPoP proof の署名検証（ES256） | `Es256Dpop`（`dpop.rs`） |
| P-JTI | DPoP proof の jti 単回（リプレイ防止） | jti 単回ストア（`NonceStore` / Firestore 分散） |

→ 導出された運用要件: **RS は token の cnf.jkt と DPoP proof の鍵 thumbprint の一致を検査せよ**（外すと盗難トークンが通る）。

### 限界 / 次版
- トークン発行は #1 から抽象化（**#6 合成**で #1×#2 を繋ぐ）。
- htm/htu は payload に持たせる（厳密一致は部分モデル）。jti 単回は含むが「proof 非リプレイ」の個別 lemma は別途。

---

## モデル #3: CIBA（切り離し承認）+ RAR マンデート

`ciba_rar.spthy` — rust-op 固有・学術的にも手薄。中心の脅威は**「ユーザが見たものと違う要求を承認させられる」**。
登場人物: クライアント（消費デバイス = ciba-rp）/ AS / ユーザ（認証デバイス, passkey）。
攻撃者は**ユーザへの通知チャネルを操作できる**（表示すり替えの脅威）。

検証する性質: **binding 完全性**（(arid,m) のトークン発行 ⇒ ユーザは“まさにその”(arid,m) を承認していた）と
**マンデート単回**（同じ auth_req_id から2トークンは出ない）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `ciba_rar.spthy` | `executable` / `binding_integrity` / `mandate_single_use` **verified** |
| `ciba_NEG_no_binding.spthy`（承認の mandate 束縛を外す）| `binding_integrity` **falsified（表示すり替え攻撃トレース）** |
| `ciba_NEG_no_singleuse.spthy`（Pending を persistent に）| `mandate_single_use` **falsified（リプレイ）** |

→ **束縛検査が必要**（外すとユーザが承認した mandate と発行 mandate が食い違う＝CIBA 中心の脅威）。
→ **マンデート単回が必要**（外すと同一 auth_req_id から複数トークン）。

### 表に出た前提 → rust-op の担保
| ID | 前提（抽象） | rust-op の担保 |
|---|---|---|
| P-BIND | ユーザ承認は**具体的 mandate に commit** し、AS は承認された mandate のみ発行 | binding_message + authorization_details を auth_req_id に紐付け表示・承認、token に approved mandate |
| P-UREAD | **ユーザが binding_message を読む**（モデル外の人間前提） | UI で binding_message/mandate を提示（"見たものに commit" を前提） |
| P-MSINGLE | マンデート(auth_req_id) は**単回消費** | `mandate_consumed` CAS（/oauth/mandate/consume）+ CIBA store の単回 |
| P-CAUTH | backchannel と poll で**クライアント認証** | ciba-rp Basic（live e2e で実機確認済） |
| P-UAUTH | 承認は**ユーザ認証**（passkey） | fido2demo アプリで passkey 承認 |
| （反スパム） | 無認証トリガの**レート制限** | `ciba_rate`（**記号的検証の対象外**＝量的性質） |

→ 導出された運用要件: **ユーザ承認を具体的 mandate に暗号的に束縛し、AS は承認された mandate のみ発行せよ**（外すと表示すり替え）。**マンデートは単回消費せよ**。

### 限界
- 「ユーザが読む」は記号的に捉えられない人間前提（P-UREAD）。モデルは「ユーザは見た m に commit する」までを表現。
- 反スパム（量的）は Tamarin の対象外（rust-op は `ciba_rate` で対処）。

---

## モデル #4: WebAuthn / FIDO2 ユーザ認証（passkey）

`webauthn.spthy` — 段1〜3 の「認証」の正体。OAuth/CIBA の中で AS がユーザを認証する所。
攻撃者は**ユーザを任意のオリジンへ誘導できる**（フィッシングを表現）。

検証する性質: **認証**（偽造不能）+ **オリジン束縛**（anti-phishing, passkey の核）+ **challenge 単回**（anti-replay）。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `webauthn.spthy` | `executable` / `authentication` / `challenge_single_use` **verified** |
| `webauthn_NEG_no_origin.spthy`（origin 検査を外す）| `authentication` **falsified（フィッシング攻撃トレース）** |
| `webauthn_NEG_no_singleuse.spthy`（Pending を persistent に）| `challenge_single_use` **falsified（リプレイ）** |

→ **オリジン束縛が必要**（外すと偽オリジンのアサーションを本物 RP が受理＝フィッシング）。
→ **challenge 単回が必要**（外すとアサーション再送）。

### 表に出た前提 → rust-op の担保
| ID | 前提（抽象） | rust-op の担保 |
|---|---|---|
| P-AKEY | 認証器 credential 鍵は秘匿 | secure enclave。rust-op は**公開鍵のみ保持** |
| P-ORIGIN | RP は origin/rpId == 自分 を検査 | `webauthn::verify_authentication`（origin + rpIdHash） |
| P-CHAL | challenge 新鮮 + 単回 | `create/consume_webauthn_challenge`（単回） |
| P-SIG | 登録公開鍵で署名検証 | `webauthn::verify_authentication` |
| （anti-clone） | signCount 単調増加 | signcount 検査（**記号的モデル対象外**＝異常検知） |

→ 導出された運用要件: **RP は origin/rpId が自分のものか検査せよ**（外すとフィッシング）／**challenge は単回**。

### 限界
- signCount（anti-clone）は「偽造防止」でなく「クローン異常検知」で、記号的モデルの対象外。
- ブラウザの SOP（rpId=origin 強制）を「認証器は文脈の o に署名」で抽象化。

---

## モデル #5: OIDC ID token（フェデレーションの原子）

`id_token.spthy` — OP がユーザの身元を RP に主張（署名付き）。複数 RP（aud 束縛が効く）。
攻撃者は**悪意 RP として被害 RP の nonce を自分の OP ログインに転送できる**（audience-confusion / cut-and-paste）。

検証する性質: **偽造不能** + **aud 束縛**（RP1 宛 token を RP2 で使えない）+ **nonce 新鮮**（古い token 再送防止）を `idtoken_integrity` に集約。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `id_token.spthy` | `executable` / `idtoken_integrity` **verified** |
| `id_token_NEG_no_aud.spthy`（aud 検査を外す）| `idtoken_integrity` **falsified（audience confusion）** |
| `id_token_NEG_no_nonce.spthy`（nonce 検査を外す）| `idtoken_integrity` **falsified（replay）** |

→ **aud 束縛が必要**（外すと RP1 宛 token を RP2 が受理）／**nonce 新鮮が必要**（外すと古い token 再送）。

### 表に出た前提 → rust-op の担保
| ID | 前提（抽象） | rust-op の担保 |
|---|---|---|
| P-OPKEY | OP 署名鍵は秘匿 | ES256 / Cloud KMS（鍵をプロセスに展開しない） |
| P-AUD | RP は aud == 自分の client_id を検査 | OP 側: token に aud=client_id。RP 側(fido2demo/oidc): aud 検証 |
| P-NONCE | nonce 新鮮 + RP が一致検査 | OP: 認可要求の nonce を token へ。RP: nonce 検証 |
| P-SIG | RP は OP の JWKS で署名検証 | discovery / JWKS 公開、RP が検証 |
| P-ISS | iss（発行者）確認（IdP mix-up 防止） | token の iss=OP。RP は OP の鍵で検証（モデルは OP 鍵束縛で表現） |

→ 導出された運用要件: **RP は aud==自分・nonce==自 flow・iss==期待 OP・署名を検査せよ**（外すと audience confusion / replay / mix-up）。

### 限界
- ユーザ認証/同意は #4 で抽象化（**#6 合成**で繋ぐ）。
- iss/mix-up は OP 鍵束縛で部分表現（明示的な mix-up 実験は別途）。

---

## モデル #6: 合成（#1 認可コード+PKCE+クライアント認証 × #2 DPoP × #4 ユーザ同意）

`composition_code_dpop.spthy` — rust-op の FAPI2 ログイン（confidential client = DCR/FAPI）。
**エンドツーエンドのリソース秘匿**: 正規ユーザの保護リソースは、DPoP 鍵もユーザ鍵も漏れない限り攻撃者に漏れない。

### ★ 合成は一筋縄ではいかなかった（formal verification が隠れた前提を炙り出した）
最初の合成は **2度 falsify** され、抽象化で落としていた前提を Tamarin が強制的に明示させた:
1. **ユーザ同意の束縛が必要**: コードは「ユーザが“その特定クライアント”に同意した」ときだけ出るべき。
   無いと誰のクライアントでもユーザの認可を得られる（1度目の falsify）。→ `U_Consent` を追加。
2. **public client は client_id 詐称で乗っ取れる**（本来 **redirect_uri 完全一致** が防ぐもの）。
   モデルが redirect_uri を抽象化していた（2度目の falsify）。→ confidential client（クライアント認証）に切替。
3. さらに `executable` が falsify（no trace）→ token-use メッセージ形式の不一致という**モデルのバグ**を発見・修正。

これは「個々に安全でも合成は別物」「証明が完成しないと前提を隠せない」の生きた実例。

### 検証結果（Tamarin 1.12.0, 2026-06-09 実測）
| モデル | 結果 |
|---|---|
| `composition_code_dpop.spthy` | `executable` / `comp_resource_secrecy` **verified**（空虚でない＝honest flow が通る） |
| `composition_NEG_no_cnf.spthy`（cnf を外す, #2）| `comp_resource_secrecy` **falsified（盗難トークンが RS を通る）** |
| `composition_NEG_no_clientauth.spthy`（クライアント認証を外す, #1）| `comp_resource_secrecy` **falsified（攻撃者が盗んだコードを償還）** |

→ **#2(cnf) と #1(クライアント認証) は各々個別に必要**（外すとエンドツーエンドが破れる）。
→ PKCE・consent は confidential client では**多層防御で冗長**（client auth が償還を守る）。
   これらの個別の必要性は **public client の文脈**で現れる（上記の 2 度の falsify がそれ）。

### 合成の結論
**#1（償還の保護）と #2（盗難トークンの無効化）が重なって初めて、エンドツーエンドの安全性が出る**:
- #1 だけ: トークンは正規クライアントに届くが、盗まれたら使える（#2 が無いと）。
- #2 だけ: 盗難トークンは無効だが、攻撃者が最初から償還できる（#1 が無いと）。
- 両方 + ユーザ同意: 攻撃者は正規ユーザの認可で RS に到達できない。

### 限界
- ID token(#5) の合成は別（本モデルはアクセストークンの送り主束縛に焦点）。
- public client の完全な合成（redirect_uri / プラットフォーム束縛込み）は follow-up。

---

## ロードマップ達成状況
**#1 ✅ #2 ✅ #3 ✅ #4 ✅ #5 ✅ #6 ✅** — 全モデルが Tamarin 1.12.0 で verified、各前提の必要性も
NEG 変種の falsify で実証。各モデルが「防げる攻撃 ＋ 必要前提（→ rust-op の運用要件）」を1セット産んだ。
合成(#6) は形式検証が隠れた前提（consent 束縛・redirect_uri 束縛）を炙り出した実例でもある。

---

## L3: コード↔モデル橋（Kani 0.67.0 / CBMC）

Tamarin（L1）は記号モデル上で前提が成り立てば性質が成り立つことを示す。が、**その前提を実コードが本当に担保しているか**、また
**記号モデルが見ない実装固有の落とし穴（整数オーバーフロー等）が無いか**は L1 では分からない。これを埋めるのが Kani による
有界モデル検査（L3）。`#[cfg(kani)] mod kani_harness`（`src/kani_harness.rs`）に置き、通常ビルド・テストからは除外される。

```sh
cargo install --locked kani-verifier && cargo kani setup
cargo kani                       # 全ハーネス
cargo kani --harness exp_in_window_spec
```

### 検証結果（Kani 0.67.0 / CBMC, 2026-06-09 実測）

| ハーネス | 検証した命題 | 結果 |
|---|---|---|
| `exp_in_window_spec` | `exp_in_window(exp,now,max)` は全 i64 で **panic せず**（saturating_add でオーバーフロー無し）、定義どおり `ok ⇔ now<exp≤now+max` | ✅ 4/4 checks |
| `jti_ttl_is_bounded` | 受理された exp に対し jti TTL = `exp-now` が **(0, 3600] に有界・溢れない** | ✅ SUCCESSFUL |

### 橋の意味（Tamarin の前提 → Kani が機械検証した実コード述語）

| Tamarin 側 | Kani 側の担保 |
|---|---|
| #1 の client_assertion 新鮮性の **時間有効性**の半分（リプレイ不能の半分は jti 単回ストアが担い、本ハーネス対象外） | `exp_in_window`（`client_auth.rs`）が窓検査を一点に集約し、Kani が全 i64 でオーバーフロー非発生＋定義一致を証明 |
| jti を覚える窓が有界であること（さもなくば保持無限肥大／TTL オーバーフロー） | `jti_ttl_is_bounded` が `exp-now ∈ (0,3600]` を機械保証。**exp_in_window は jti 単回防御を健全かつ有界にする load-bearing な前提**だと位置づく |

→ **記号モデルが算術を見ない死角（遠未来 exp による TTL オーバーフロー／jti 保持の無限肥大）を、Kani が実コード上で閉じた**。
これが「L1 の前提＝L3 の証明義務」を1つ履行した形。

### 追加の橋 #1〜#4（2026-06-09）— 階層を正直に分ける

候補4つを実コードに当たって精査すると、**Tamarin の前提が「比較(`==`)」か「変換/パース」か**で Kani の効き方が分かれた。
比較は言語意味論で厳密ゆえ Kani は**回帰ロック**止まり（恒真寄り）、変換は panic/正当性の**本物の検証面**になる。
4つを同列の「verified」と並べず、効能を正直に区別する。

**正直な結論: 4つのうち潜在バグを実際に発見したものは無い**。#1/#2/#4 は「既に安全なものを固定する回帰ロック」、#3 は層の割当（Kani 射程外）。
特に #4 は当初「本物のバグ狩り」と見積もったが**過大評価だった**: `strip_query_fragment` は `str::find` を使っており、`str::find` は
**文字境界を返す**契約ゆえ `&u[..end]` は構造的に panic しえない（クラッシュ事例は作ろうにも作れない）。安全イディオムが既に
適用済みで、Kani は「やはり起きない」を確認しただけ。**この見積もり違いのせいで、起こりえないクラッシュの記号探索に
状態爆発で時間を浪費した**（教訓として残す）。→ Kani が本当にバグ狩りになるのは、安全 API を使わず生バイト index 演算や
`unsafe`・ビット操作をする**変換コード**（`b64url`／thumbprint）であって、strip_query_fragment はそこではなかった。

| 橋 | 実コード | Kani の効能 | ハーネス / 結果 |
|---|---|---|---|
| #1 redirect_uri 完全一致 | `auth_checks::redirect_uri_registered`（`iter().any(\|u\| u==ru)`） | **回帰ロック**: 照合がバイト完全一致で正規化の抜け道が無いことを固定（`match ⟺ a==b`、空リストは不一致）。将来正規化が紛れ込むと破れる | `redirect_uri_match_is_exact` ✅ |
| #2 PKCE S256 | `auth_checks::pkce_method_is_s256`（`method.unwrap_or("plain")=="S256"`） | **回帰ロック**: `m`が`Some("S256")`ちょうどのみ受理＝None/plain/大小違いへのダウングレード不可を固定 | `pkce_method_no_downgrade` ✅ |
| #3 認可コード単回 | store の CAS 単回消費（Firestore `take_code`） | **Kani 射程外**（下記） | — |
| #4 DPoP htu 正規化 | `dpop::strip_query_fragment`（`&u[..u.find(['?','#'])..]`） | **回帰ロック**（当初「バグ狩り」と誤見積）: `str::find` が文字境界を返すゆえ `&u[..end]` は元から panic しえない。安全イディオム（`str::find`+slice）が保たれることを固定し、生 index 化等の危険な refactor を検出（入力は下記の通り有界化） | `strip_query_fragment_safe` ✅ |

**#3 は「スキップ」ではなく層の割当**: 認可コード単回は **Firestore の分散 CAS 原子性**に依存する。Kani は**単一プロセスの有界モデル検査器**で、
分散ストアの原子性は射程外（見えない）。この義務は **L1（Tamarin の `Once` ＝ #1 で verified 済）** と **L4（回帰テスト
`store::code_reuse_revokes_issued_tokens`）** で履行済み。「どの前提がどの層の責務か」を明示するのが、この演習の狙いそのもの。

**なぜ panic しえないか（#4 の核心）**: `strip_query_fragment` は `end = u.find(['?','#']).unwrap_or(u.len())` を使う。
`str::find` は **文字単位**で走査しマッチ文字の**先頭バイト位置**を返す契約なので、`end` は**常に文字境界**（`u.len()` も境界）。
ゆえに `&u[..end]` は構造的に文字の途中を割らず panic しえない。「区切りが多バイト文字を割る」クラッシュ事例は
`str::find` 経由では**構成不能**。Kani の役割はこの安全性の再確認＝**ロック**であって、潜在バグの発見ではない。

**カバレッジ境界（silent cap を作らない）**: それでも記号文字列で `find` を走らせるとパターンマッチャの UTF-8 デコードが
状態爆発する（この 8GB 環境では全 UTF-8 シンボリック化は収束しない）。そこで入力を `"é<tail>"`（先頭 2 バイト文字 `é` を
具体値固定、`tail` は ASCII 全域の記号バイト）に有界化し、`tail` が `?`/`#` のとき `&u[..2]`（`é` 直後＝多バイト境界）で切れることを
検証した。**任意の先頭文字長・任意長文字列の全証明ではない**点を明示する（そもそも上記契約より全入力で安全なので、ここは確認）。

### 次に橋を架ける候補
JWK thumbprint（RFC 7638 正準化＝**変換**ゆえ本物の Kani 面）、`b64url`（ビット操作・アルファベット/パディング＝変換）、
id_token `aud`/`nonce` 照合（比較＝ロック）。比較系はロック、変換/パース系は panic/正当性。新しい橋もこの判別則で仕分ける。
