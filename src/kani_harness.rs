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
