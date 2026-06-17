//! Kani 証明ハーネス。`#[cfg(kani)]` で通常ビルド・テストからは完全に除外され、
//! `cargo kani` でのみ検証される。Tamarin（プロトコル層 L1）の前提が rust-op の実コードで
//! どの述語によって担保されているかを、コード層 L3 で機械検証する橋。
//!
//! 橋の対象は `client_auth::exp_in_window`。Tamarin #1（認可コード+PKCE+クライアント認証）の
//! 「client_assertion 新鮮性」前提のうち、**時間有効性**の半分に対応する。
//! 新鮮性のもう半分＝リプレイ不能は jti 単回ストアが担い、本ハーネスの対象外である点に注意。
//!
//! exp_in_window の真の役割は「jti 単回防御を健全かつ有界にする load-bearing な前提」:
//!   - jti は exp まで覚える必要がある。`now < exp <= now + 3600` を強制することで
//!     (a) ストアの保持窓は高々 3600 秒に有界化され、
//!     (b) 攻撃者が exp を遠未来に設定して jti 保持を無限肥大／TTL をオーバーフローさせる
//!         ことを防ぐ。
//! Tamarin は記号モデル上 exp を抽象トークンとして扱い算術を見ない。整数オーバーフローという
//! 実装固有の落とし穴は Kani 側でしか塞げない。これが L1↔L3 ギャップの具体である。

/// `exp_in_window` がオーバーフロー非発生（全 i64 で panic しない）かつ定義どおりの述語
/// （ok ⇔ now < exp ≤ now + max）であることを機械検証する。
/// 健全性/完全性の各 assert は関数定義のほぼ写しで恒真に近い。Kani がここで実際に足す価値は
/// saturating_add によるオーバーフロー非発生を全 i64 領域で保証する点にある。
/// `max >= 0`（実コードでは定数 3600）を仮定。負の max は意味を持たないので対象外。
#[kani::proof]
fn exp_in_window_spec() {
    let exp: i64 = kani::any();
    let now: i64 = kani::any();
    let max: i64 = kani::any();
    kani::assume(max >= 0);

    let ok = crate::client_auth::exp_in_window(exp, now, max);

    // 健全性: 受理したなら確かに窓の内側。
    if ok {
        assert!(exp > now, "受理 ⇒ exp は now より未来");
        assert!(exp <= now.saturating_add(max), "受理 ⇒ exp は上限以内");
    }
    // 完全性: 窓の外なら必ず拒否（取りこぼしがない）。
    if exp <= now {
        assert!(!ok, "exp <= now（期限切れ/同時刻）は拒否されねばならない");
    }
    if exp > now.saturating_add(max) {
        assert!(!ok, "上限を超える未来 exp は拒否されねばならない");
    }
}

/// jti 単回防御の有界性の橋: 受理された exp に対し、jti TTL = `exp - now` が
/// (0, MAX_ASSERTION_LIFETIME_SECS] に収まりオーバーフロー（panic）しないこと。
/// これにより「jti を覚える窓は高々 3600 秒」が機械保証され、保持窓の有界性が確定する。
#[kani::proof]
fn jti_ttl_is_bounded() {
    let exp: i64 = kani::any();
    let now: i64 = kani::any();
    let max = crate::client_auth::MAX_ASSERTION_LIFETIME_SECS;

    if crate::client_auth::exp_in_window(exp, now, max) {
        // 受理後、実コードは (exp - now) を jti の TTL に使う。これが溢れず有界なこと。
        let ttl = exp.checked_sub(now);
        assert!(ttl.is_some(), "受理された exp に対し exp - now は溢れない");
        let ttl = ttl.unwrap();
        assert!(ttl > 0 && ttl <= max, "jti TTL は (0, 3600] に有界");
    }
}

/// 長さ可変の実 UTF-8 文字列を `[u8; N]` の前方 len バイトから記号的に生成する。
/// マルチバイト文字を含みうる入力空間にすること（ASCII 固定だと UTF-8 境界の検証が無意味になる）。
fn any_utf8<const N: usize>(buf: &[u8; N]) -> &str {
    let len: usize = kani::any();
    kani::assume(len <= N);
    let s = core::str::from_utf8(&buf[..len]);
    kani::assume(s.is_ok());
    s.unwrap()
}

/// 橋 #1（回帰ロック・恒真寄り）: redirect_uri 照合が **バイト完全一致** で、正規化・前方一致の
/// 抜け道が無いこと。`redirect_uri_registered(a,[b]) ⟺ a==b`、空リストは決して一致しない。
/// 将来の編集で正規化が紛れ込むと本ロックが破れる。バグ狩りではなく契約の固定。
#[kani::proof]
#[kani::unwind(6)]
fn redirect_uri_match_is_exact() {
    let ab: [u8; 5] = kani::any();
    let bb: [u8; 5] = kani::any();
    let a = any_utf8(&ab);
    let b = any_utf8(&bb);

    let registered = [b.to_string()];
    assert_eq!(
        crate::auth_checks::redirect_uri_registered(a, &registered),
        a == b,
        "単一登録値との一致は厳密にバイト等価（正規化なし）",
    );
    assert!(
        !crate::auth_checks::redirect_uri_registered(a, &[]),
        "空の登録リストは決して一致しない",
    );
}

/// 橋 #2（回帰ロック）: PKCE の code_challenge_method は **厳密に S256 のみ受理**。
/// method 省略(None→plain)・大小違い・末尾空白など S256 以外は全て拒否（ダウングレード不可）。
/// `pkce_method_is_s256(m) ⟺ m == Some("S256")` を全 method 上で固定する。
#[kani::proof]
#[kani::unwind(6)]
fn pkce_method_no_downgrade() {
    let is_some: bool = kani::any();
    let mb: [u8; 5] = kani::any();
    let m: Option<&str> = if is_some { Some(any_utf8(&mb)) } else { None };

    assert_eq!(
        crate::auth_checks::pkce_method_is_s256(m),
        m == Some("S256"),
        "S256 ちょうどのみ受理（None/plain/大小違い等は拒否）",
    );
}

/// 橋 #4（回帰ロック。当初「バグ狩り」と見積もったが過大評価だった）:
/// `strip_query_fragment` は `end = u.find(['?','#'])..` を使い、`str::find` は**文字境界**を返す契約
/// ゆえ `&u[..end]` は構造的に panic しえない（安全イディオム）。よって潜在バグは元から無く、本ハーネスは
/// その安全性の**確認＝ロック**（生 index 化等の危険な refactor を検出）。`str::find` を使わず生バイト
/// index 演算/`unsafe`/ビット操作をする変換コード（`b64url`/thumbprint）こそが Kani の本物のバグ狩り面。
///
/// 検証内容: 2 バイト文字 `é`(0xC3 0xA9) の直後に記号バイト 1 つ（ASCII 全域）を置いた `"é<tail>"` で、
/// `tail` が `?`/`#` のとき `&u[..2]`（`é` 直後＝多バイト境界）で切れて panic しない＋結果は接頭辞。
///
/// `str::find` を**記号文字列**で走らせるとパターンマッチャの UTF-8 デコードが状態爆発する（この 8GB
/// 環境では収束しない）。そこで**先頭文字を具体値に固定**しデコードを安くし、記号次元を「区切りの値」だけに絞る。
/// **カバレッジ境界**: 任意先頭文字長・任意長の全証明ではない（上記契約より全入力で安全なので、ここは確認）。
#[kani::proof]
#[kani::unwind(5)]
fn strip_query_fragment_safe() {
    let tail: u8 = kani::any();
    kani::assume(tail < 0x80); // ASCII は単独で妥当な UTF-8
    let buf = [0xC3u8, 0xA9, tail]; // "é" + tail
    let u = unsafe { core::str::from_utf8_unchecked(&buf) };

    let r = crate::dpop::strip_query_fragment(u); // 到達＝多バイト境界スライス panic 無し
    assert!(u.starts_with(r), "結果は入力の接頭辞");
    if tail == b'?' || tail == b'#' {
        assert_eq!(r.len(), 2, "区切りの直前＝多バイト境界(index 2)でちょうど切る");
    } else {
        assert_eq!(r.len(), 3, "区切りが無ければ全長を保つ");
        assert!(!r.contains('?') && !r.contains('#'), "本当に区切りを含まない");
    }
}

/// 橋（Integrity, 本物の変換コード）: `es256::pad32` は座標を 32 バイトに左ゼロ埋めする手書き変換。
/// `out[32 - b.len()..].copy_from_slice(b)` が、(a) `32 - b.len()` の **usize 下溢れ**を起こさない
/// （`b.len() > 32` の早期 return ガードが十分か）、(b) スライス長と copy 長が一致し panic しない、
/// (c) 結果は左ゼロ埋め＋末尾 len バイトが入力一致、を**全入力**で機械検証する。
/// b64url（base64 クレート委譲）と jwk_thumbprint（固定フォーマット＋SHA256）はライブラリ/構成上正しく
/// 検証対象外。pad32 のみが手書きの算術＋スライス＝本物の panic 面。整数/バイト論理ゆえ tractable。
#[kani::proof]
#[kani::unwind(34)]
fn pad32_safe() {
    const N: usize = 33; // 33 で len>32(=33) ガード経路も踏む。32 以下は全網羅
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let b = &buf[..len];

    match crate::es256::pad32(b) {
        Err(_) => assert!(len > 32, "Err となるのは len>32 のときのみ"),
        Ok(out) => {
            assert!(len <= 32, "Ok は len<=32 のときのみ");
            let pad = 32 - len;
            let mut i = 0;
            while i < pad {
                assert!(out[i] == 0, "左側 32-len バイトはゼロ");
                i += 1;
            }
            let mut j = 0;
            while j < len {
                assert!(out[pad + j] == b[j], "末尾 len バイトは入力を保存");
                j += 1;
            }
        }
    }
}

/// 橋（Integrity, 本物の手書きパーサ）: `verify::parse_auth_data` は WebAuthn authenticatorData を
/// 手動 index でスライスする（`ad[0..32]` / `ad[32]` / `ad[33..37]` / `ad[37..]`、ガードは `len < 37`）。
/// 攻撃者制御の生バイトを受けるので、(a) **全入力でスライス OOB panic を起こさない**、
/// (b) 長さガード `37` が後続の全 index に対して**過不足ない**（Err ⇔ len<37）、(c) 各フィールドが
/// 正しいバイト範囲を指す、を機械検証する。proptest（標本）の no-panic を**全 i 領域**へ格上げする。
/// pad32 と同型の「手書き算術＋スライス＝本物の panic 面」。SHA256/p256 等のライブラリ委譲は対象外。
#[kani::proof]
fn parse_auth_data_safe() {
    const N: usize = 40; // 37 境界 + rest 数バイト。len は 0..=N を記号的に動かす
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let ad = &buf[..len];

    match crate::fido::verify::parse_auth_data(ad) {
        // ガードの完全性: 拒否は len<37 のときに限る（37 が下限として過不足ない）。
        Err(_) => assert!(len < 37, "Err となるのは len<37 のときのみ"),
        Ok(adata) => {
            // 健全性: 受理は len>=37 のときに限る。到達＝後続スライスが全て OOB panic 無し。
            assert!(len >= 37, "Ok は len>=37 のときのみ");
            assert!(adata.rp_id_hash.len() == 32, "rp_id_hash は ad[0..32]＝32 バイト");
            assert!(adata.rest.len() == len - 37, "rest は ad[37..]＝残り全部");
            assert!(adata.flags == buf[32], "flags は ad[32]");
            // sign_count は ad[33..37] の big-endian（index 33..36 が読まれている証拠）。
            let sc = ((buf[33] as u32) << 24)
                | ((buf[34] as u32) << 16)
                | ((buf[35] as u32) << 8)
                | (buf[36] as u32);
            assert!(adata.sign_count == sc, "sign_count は ad[33..37] の big-endian");
        }
    }
}

/// 橋（Integrity, 本物の長さフィールド演算）: `verify::attested_cred_id_end` は authenticatorData の
/// attestedCredentialData から **2 バイトの credIdLen を読み、`rest[18..end]`/`rest[end..]` を切り出す**
/// 古典的な「長さフィールド → スライス」面。攻撃者が巨大 credIdLen を送っても、(a) `18 + credIdLen` が
/// **usize 桁あふれしない**、(b) `Some(end)` を返すなら `end <= rest.len()`＝後続 2 スライスが **OOB panic
/// しない**、(c) ガード（ヘッダ<18 / credId 超過）が過不足ない、を全入力で機械検証する。
/// proptest（標本）で no-panic を確認済みの経路を、Kani で**全 credIdLen 値**へ格上げする。
#[kani::proof]
fn attested_cred_id_end_safe() {
    const N: usize = 24; // 18B ヘッダ + 数バイト。credIdLen(buf[16],buf[17]) は 0..=65535 を記号探索
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let rest = &buf[..len];

    match crate::fido::verify::attested_cred_id_end(rest) {
        None => {
            // 拒否はヘッダ不足、または credId が rest を超えるときに限る。
            let n = ((buf[16] as usize) << 8) | (buf[17] as usize);
            assert!(len < 18 || len < 18 + n, "None はヘッダ<18 か credId 超過のときのみ");
        }
        Some(end) => {
            assert!(len >= 18, "Some はヘッダ>=18 が必要");
            let n = ((buf[16] as usize) << 8) | (buf[17] as usize);
            assert!(end == 18 + n, "end = 18 + credIdLen（桁あふれ無し）");
            // 受理⇒ end<=len。ゆえに rest[18..end] と rest[end..] は構造的に OOB panic しない。
            assert!(end <= len, "end <= rest.len()（後続スライスは安全）");
        }
    }
}

/// B-4 系列失効 `store::Store::revoke_refresh_family` の打ち切り付き連鎖走査の**停止性モデル**。
/// 実コードは `replaced_by`（HashMap/Firestore）を辿るが、ここでは next を index 配列に抽象化
/// する（モデル＝L1 寄りであり実コードそのものではない点に注意）。任意の next（自己参照・循環を
/// 含む）でも、終端 or guard により**有界ステップで必ず停止**する（無限ループ／ハングしない）
/// ことを全数検証する。実装の guard 定数は 64、本モデルは小定数で同一性質を示す。
#[kani::proof]
#[kani::unwind(12)]
fn refresh_family_walk_terminates() {
    const N: usize = 4; // 系列の最大ノード数（抽象）
    const MAX: usize = 8; // guard（実コードは 64）

    let next: [usize; N] = kani::any();
    let mut i = 0;
    while i < N {
        kani::assume(next[i] <= N); // N は終端（replaced_by = None 相当）
        i += 1;
    }

    let mut cur: usize = kani::any();
    kani::assume(cur < N);

    let mut steps: usize = 0;
    while cur < N {
        steps += 1;
        if steps >= MAX {
            break; // guard: 循環していても必ず打ち切る
        }
        cur = next[cur];
    }
    assert!(steps <= MAX, "guard により有界ステップで停止する（ハングしない）");
}
