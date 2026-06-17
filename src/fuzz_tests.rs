//! 攻撃者制御のバイト列に晒れる自前 crypto / WebAuthn パーサの **panic 安全性**を
//! proptest で網羅検証する（Tier3: 自前 crypto 検証強化）。
//!
//! 核となる不変条件: **いかなる入力でも panic しない**（パーサの panic = リクエストハンドラ
//! 内 panic = 500/中断 = DoS）。各 target は Result を返すだけで、Ok/Err は問わない。
//! proptest は panic を最小化入力つきの失敗として報告するので、退行検出器として働く。
//!
//! ピュア Rust crypto は rust-op の差別化点であると同時に最大のリスク面（peer は
//! webauthn-rs/ring/openssl 等の枯れた実装に委譲する）。ここを継続的に締める。

use crate::es256;
use crate::fido::verify;
use ciborium::value::Value as Cbor;
use proptest::prelude::*;

/// 任意バイト列を base64url(URL_SAFE_NO_PAD) に包む。b64 decode を必ず通し、
/// 下流（CBOR / authData / COSE）パーサへランダムバイトを届けるための strategy。
fn b64_of_bytes(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..max).prop_map(|b| es256::b64url_encode(b))
}

/// 1 階層までの「それらしい CBOR 値」。ランダムバイトだと大半が CBOR decode 前に
/// 落ちるため、構造化した値を encode して post-parse ロジックの深い経路を突く。
fn arb_cbor() -> impl Strategy<Value = Cbor> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(|i| Cbor::Integer(i.into())),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Cbor::Bytes),
        ".*".prop_map(Cbor::Text),
        any::<bool>().prop_map(Cbor::Bool),
        Just(Cbor::Null),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Cbor::Array),
            prop::collection::vec((inner.clone(), inner), 0..6).prop_map(Cbor::Map),
        ]
    })
}

/// CBOR 値を DER ならぬ CBOR バイト列へ。
fn cbor_to_bytes(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    // ciborium の into_writer は無限ループしない。失敗時は空（テストは panic 不在のみ問う）。
    let _ = ciborium::into_writer(v, &mut out);
    out
}

/// AT flag 付き authData を内包する **構造化された attestation object**（base64url）。
/// fmt/authData/attStmt の CBOR マップを組むので、登録検証が check_client_data を通った後の
/// 「attestation 解析 → credId 長さ抽出 → COSE 鍵解析」という最深経路へ実際に到達する。
/// rest（attestedCredentialData + COSE）はランダムなので credId 長さの境界も突かれる。
fn at_attestation_object() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(any::<u8>(), 32..=32), // rp_id_hash(32)
        any::<u8>(),                                 // 追加フラグビット
        any::<u32>(),                                // sign_count
        prop::collection::vec(any::<u8>(), 0..220),  // aaguid|credIdLen|credId|COSE（乱）
        ".*",                                        // fmt
    )
        .prop_map(|(h, fl, sc, rest, fmt)| {
            let mut ad = h;
            ad.push(fl | 0x41); // UP(0x01)+AT(0x40) を強制
            ad.extend_from_slice(&sc.to_be_bytes());
            ad.extend_from_slice(&rest);
            let v = Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text(fmt)),
                (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            ]);
            es256::b64url_encode(cbor_to_bytes(&v))
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    // --- 生バイトを直接受けるパーサ群 ---

    #[test]
    fn parse_auth_data_never_panics(b in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = verify::parse_auth_data(&b);
    }

    #[test]
    fn parse_cose_key_raw_never_panics(b in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = verify::parse_cose_key(&b);
    }

    #[test]
    fn parse_attestation_object_raw_never_panics(b in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = verify::parse_attestation_object(&b);
    }

    // --- 構造化 CBOR を encode して深い経路を突く ---

    #[test]
    fn parse_cose_key_structured_never_panics(v in arb_cbor()) {
        let _ = verify::parse_cose_key(&cbor_to_bytes(&v));
    }

    #[test]
    fn parse_attestation_object_structured_never_panics(v in arb_cbor()) {
        let _ = verify::parse_attestation_object(&cbor_to_bytes(&v));
    }

    // --- 署名・座標プリミティブ（長さ不正でも panic しないこと） ---

    #[test]
    fn pad32_never_panics(b in prop::collection::vec(any::<u8>(), 0..128)) {
        let _ = es256::pad32(&b);
    }

    #[test]
    fn b64url_decode_never_panics(s in ".*") {
        let _ = es256::b64url_decode(&s);
    }

    #[test]
    fn verify_es256_raw_never_panics(
        x in prop::collection::vec(any::<u8>(), 0..80),
        y in prop::collection::vec(any::<u8>(), 0..80),
        msg in prop::collection::vec(any::<u8>(), 0..128),
        sig in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let _ = verify::verify_es256_raw(&x, &y, &msg, &sig);
    }

    #[test]
    fn verify_rs256_never_panics(
        n in prop::collection::vec(any::<u8>(), 0..400),
        e in prop::collection::vec(any::<u8>(), 0..8),
        msg in prop::collection::vec(any::<u8>(), 0..128),
        sig in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        let _ = crate::sig::verify_rs256(&n, &e, &msg, &sig);
    }

    #[test]
    fn verify_ed25519_never_panics(
        pk in prop::collection::vec(any::<u8>(), 0..64),
        msg in prop::collection::vec(any::<u8>(), 0..128),
        sig in prop::collection::vec(any::<u8>(), 0..96),
    ) {
        let _ = crate::sig::verify_ed25519(&pk, &msg, &sig);
    }

    // --- end-to-end（有効 base64 のランダムバイトで全鎖を通す） ---

    #[test]
    fn verify_registration_never_panics(
        cd in b64_of_bytes(256),
        ao in b64_of_bytes(512),
        ch in ".*",
        origin in ".*",
        rp in ".*",
    ) {
        let _ = crate::webauthn::verify_registration(&cd, &ao, &ch, &origin, &rp);
    }

    #[test]
    fn verify_authentication_never_panics(
        cd in b64_of_bytes(256),
        adb in b64_of_bytes(256),
        sig in b64_of_bytes(96),
        ch in ".*",
        origin in ".*",
        rp in ".*",
        x in b64_of_bytes(40),
        y in b64_of_bytes(40),
        sc in any::<u32>(),
        uv in any::<bool>(),
    ) {
        let _ = crate::webauthn::verify_authentication(
            &cd, &adb, &sig, &ch, &origin, &rp, &x, &y, sc, uv,
        );
    }

    // --- 登録検証 deep: clientData を一致させて attestation 最深経路まで通す ---

    #[test]
    fn verify_registration_deep_never_panics(
        ch in "[A-Za-z0-9_-]{0,64}",
        origin in "[a-z]{1,12}",
        ao in at_attestation_object(),
    ) {
        // challenge/origin が一致する clientDataJSON を組むと check_client_data を通過し、
        // parse_attestation_object → parse_auth_data(AT) → credId 抽出 → parse_cose_key へ到達。
        let cd_json =
            format!(r#"{{"type":"webauthn.create","challenge":"{ch}","origin":"{origin}"}}"#);
        let cd = es256::b64url_encode(cd_json.as_bytes());
        let _ = crate::webauthn::verify_registration(&cd, &ao, &ch, &origin, &origin);
    }

    // --- challenge 抽出（clientDataJSON b64） ---

    #[test]
    fn extract_challenge_never_panics(s in ".*") {
        let _ = crate::webauthn::extract_challenge(&s);
    }
}
