# 暗号前提（A4）のスコーピング: 何を仮定し、何が証明可能か

[Zero Trust 自己評価](./zero-trust-assessment.md) の前提 **A4（暗号/エンコーディングライブラリの正当性）** を、
「盲目的な仮定」から「**根拠と残余ギャップを明示した仮定**」へ引き上げる。これは backlog#4（L2 暗号, CryptoVerif/EasyCrypt）の **着手**。

> **正直な前置き**: CryptoVerif / EasyCrypt は**プリミティブ/プロトコルの設計安全性**（ECDSA の EUF-CMA 等）を
> 計算量的に証明する道具であって、**Rust クレートの実装が正しいことを証明する道具ではない**。後者は hax/Aeneas や
> 監査・テストベクタの領域。本書は「A4 を3つの異なるギャップに分解し、各々に既存結果と正しい道具を割り当てる」もので、
> 機械証明そのものではない。偽の証明は作らない。

## なぜ A4 が load-bearing か

L1（Tamarin）は署名を**完全に偽造不能**な記号関数として抽象化する（`verify(sign(m,k), m, pk(k)) = true`、かつ
鍵を知らねば `sign` を作れない）。この抽象が現実で成り立つのは、**実際の署名方式が EUF-CMA を満たす**ときだけ。
同様にハッシュの一意性（thumbprint/at_hash/PKCE）は SHA-256 の衝突困難性・ROM 的性質に依存する。
つまり **A4 が崩れれば L1 の全 lemma の前提が崩れる**。

## A4 の分解: プリミティブ × 必要な安全性 × 依存箇所

| プリミティブ（クレート） | 必要な安全性概念 | rust-op の依存箇所 |
|---|---|---|
| **ECDSA P-256**（`p256` 0.13） | EUF-CMA（選択文書攻撃下の存在的偽造不能） | id_token(ES256) 署名、private_key_jwt クライアント認証、DPoP proof、WebAuthn ES256 検証 |
| **RSASSA-PKCS1-v1_5**（`rsa` 0.9） | EUF-CMA | id_token(RS256) 署名（RS256 クライアント向け） |
| **EdDSA Ed25519**（`ed25519-dalek` 2） | EUF-CMA | WebAuthn Ed25519 認証器の検証 |
| **SHA-256**（`sha2` 0.10） | 衝突困難性 ＋ ROM/PRF 的性質 | JWK thumbprint(RFC7638)、at_hash、PKCE S256、nonce/jti 導出 |
| **base64url**（`base64` 0.22） | （安全性概念でなく）**全単射エンコード**の正しさ | JWS/JWT・JWK・thumbprint の wire 表現 |
| **定数時間比較**（`subtle` 2 `ct_eq`） | **タイミング非依存**（サイドチャネル特性） | client_secret 比較等 |

## 3つの異なるギャップ（ここが本書の肝）

A4 の「正しさ」は実は**別物の3つ**で、それぞれ道具が違う。一括りにすると誤解する。

### (a) プリミティブの設計安全性 — CryptoVerif/EasyCrypt/文献の領域。**ほぼ確立**。
- **ECDSA EUF-CMA**: 標準的な理想化（generic group model / bijective ROM）の下で証明されている（広く引用される結果）。
- **RSASSA-PKCS1-v1_5**: RSA 仮定の下で EUF-CMA が議論されている（PSS の方が証明はクリーン。v1_5 は条件付きで「安全と信じられる」）。
- **EdDSA(Ed25519)**: EUF-CMA が証明されている（Brendel 他の解析）。
- **SHA-256**: 衝突/原像攻撃は知られておらず、ROM/CR 仮定として標準的に引用可能。
- EasyCrypt は多数の方式を、CryptoVerif は実プロトコル（TLS1.3・Signal 等）を計算量的に検証してきた実績がある。
- → **このギャップは「文献の確立結果を引用する」ことで A4 を盲目から脱せる**（rust-op で再証明する価値は低い）。

### (b) Rust クレートの実装正しさ — **CryptoVerif の対象外**。hax/Aeneas/監査の領域。
- 「p256 クレートが ECDSA を*正しく*実装しているか（曲線演算・nonce 生成・点検証のバグが無いか）」は (a) とは別問題。
- 正しい道具: **hax**（Cryspen, Rust→F*/ProVerif）や **Aeneas**（Rust→Lean）でセキュリティ核を抽出して関数的正しさを証明、
  あるいはクレート自身のテストベクタ（NIST CAVP 等）・fuzzing・監査に依拠する。
- 現状の担保: RustCrypto/dalek は広く使われ、テストベクタ・継続 CI を持つ。cargo-deny（SHA ピン）で供給網を監査。
- → **rust-op はここを「クレートの監査/テストベクタに依拠」と明示し、深掘りは hax で別途**（大規模）。

### (c) サイドチャネル（定数時間） — また別。`subtle`/`ct` と専用解析の領域。
- `ct_eq` のタイミング非依存は計算量的安全性とは別の性質。検証は dudect 的測定や専用の定数時間解析。
- CryptoVerif/EasyCrypt の主対象ではない（EasyCrypt にはサイドチャネル拡張の研究はある）。
- → **「定数時間は subtle に依拠」と明示**。KMS 署名はそもそもプロセス外（A2）なので署名鍵のサイドチャネルは Cloud KMS 側。

## 着手の成果（本書）と現実的な次手

**本書が達成すること**: A4 を「p256/sha2/base64/subtle が正しい、と一括で盲目的に仮定」から、
**「(a) 設計安全性＝文献で確立・引用可 / (b) 実装正しさ＝クレート監査に依拠・深掘りは hax / (c) 定数時間＝subtle に依拠」**
へ分解し、各ギャップに正しい道具と現状の担保を割り当てた。これが「前提の明示」の A4 版。

**深い保証が要るときの次手（順に重い）**:
1. **CryptoVerif の計算量モデル**（中規模）: rust-op の署名利用（id_token/DPoP/client-auth）を計算量モデルに起こし、
   L1 の*記号的*偽造不能を*計算量的*偽造不能へ格上げする。Tamarin #5（ID token）の計算量版に相当。
   ※ CryptoVerif は未インストール（現状 tamarin/maude/kani のみ）。導入＋モデル作成が必要。
2. **hax 抽出**（大規模）: 署名/検証のセキュリティ核を Rust→F*/ProVerif へ抽出し実装正しさへ踏み込む。
3. **定数時間解析**（局所）: `ct_eq` 利用箇所の定数時間を測定/解析。

いずれも「形式手法は銀の弾丸でない」の実例: **(a) は引用で済み、(b)(c) が残余**。A4 はこの構造で運用する。

## 台帳との連動

[Zero Trust 自己評価](./zero-trust-assessment.md) の **A4** は本書により「盲目的仮定」から
**「設計＝引用で確立／実装＝クレート監査に依拠（深掘りは hax）／定数時間＝subtle」** へ更新。残余ギャップ (b)(c) は GAP 節に既出。
