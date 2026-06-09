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
