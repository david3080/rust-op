//! WebAuthn (FIDO2) 本番ログイン/登録の検証アダプタ。
//!
//! 検証ロジックは **conformance 認定済みコア `crate::fido::verify` に委譲**する
//! （= FIDO Conformance 155/155 で検証したコードがそのまま本番ログインを処理する）。
//! ここは OIDC 向けの薄いアダプタで、既存の I/F（RegOutcome の pubX/pubY 文字列、
//! accounts/{email} 保存、login/register/CIBA の呼び出し）を維持する。
//! 本番 passkey は ES256 / none attestation。

use crate::es256::{b64url_decode as b64d, b64url_encode};
use crate::fido::verify::{self, CredKey};

/// 登録検証の成果（Firestore accounts/{email} に保存する）。
pub struct RegOutcome {
    pub credential_id: String, // b64url
    pub pub_x: String,         // b64url(32)
    pub pub_y: String,         // b64url(32)
    pub sign_count: u32,
}

pub fn b64e(b: &[u8]) -> String {
    b64url_encode(b)
}

/// clientDataJSON(b64url) から challenge 文字列を取り出す（Firestore 引き当て用）。
pub fn extract_challenge(client_data_json_b64: &str) -> Option<String> {
    let raw = b64d(client_data_json_b64).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("challenge")?.as_str().map(|s| s.to_string())
}

/// 登録レスポンス検証（none attestation 前提）。検証は認定済みコアに委譲。
pub fn verify_registration(
    client_data_json_b64: &str,
    attestation_object_b64: &str,
    expected_challenge: &str,
    origin: &str,
    rp_id: &str,
) -> Result<RegOutcome, String> {
    verify::check_client_data(client_data_json_b64, "webauthn.create", expected_challenge, origin)?;
    let att = b64d(attestation_object_b64)?;
    let ao = verify::parse_attestation_object(&att)?;
    let ad = verify::parse_auth_data(&ao.auth_data)?;
    verify::check_rp_id_hash(ad.rp_id_hash, rp_id)?;
    if ad.flags & verify::FLAG_UP == 0 {
        return Err("UP flag not set".into());
    }
    if ad.flags & verify::FLAG_AT == 0 {
        return Err("AT flag not set (no attested credential data)".into());
    }
    // attestedCredentialData: aaguid(16) | credIdLen(2) | credId | COSE
    let rest = ad.rest;
    if rest.len() < 18 {
        return Err("attestedCredentialData too short".into());
    }
    let cred_id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    if rest.len() < 18 + cred_id_len {
        return Err("credId length overflow".into());
    }
    let cred_id = &rest[18..18 + cred_id_len];
    let (key, _consumed) = verify::parse_cose_key(&rest[18 + cred_id_len..])?;
    let (x, y) = match key {
        CredKey::Es256 { x, y } => (x, y),
        _ => return Err("OIDC passkey must be ES256".into()),
    };
    Ok(RegOutcome {
        credential_id: b64e(cred_id),
        pub_x: b64e(&x),
        pub_y: b64e(&y),
        sign_count: ad.sign_count,
    })
}

/// 認証レスポンス検証。検証は認定済みコアに委譲。成功で新しい signCount を返す。
#[allow(clippy::too_many_arguments)]
pub fn verify_authentication(
    client_data_json_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
    expected_challenge: &str,
    origin: &str,
    rp_id: &str,
    pub_x_b64: &str,
    pub_y_b64: &str,
    stored_sign_count: u32,
) -> Result<u32, String> {
    let client_data =
        verify::check_client_data(client_data_json_b64, "webauthn.get", expected_challenge, origin)?;
    let auth_data = b64d(authenticator_data_b64)?;
    let ad = verify::parse_auth_data(&auth_data)?;
    verify::check_rp_id_hash(ad.rp_id_hash, rp_id)?;
    if ad.flags & verify::FLAG_UP == 0 {
        return Err("UP flag not set".into());
    }
    let key = CredKey::Es256 {
        x: b64d(pub_x_b64)?,
        y: b64d(pub_y_b64)?,
    };
    verify::verify_assertion(&key, &auth_data, &client_data, &b64d(signature_b64)?)?;
    // signCount: 受信が 0 なら無視。0 でなければ単調増加を要求。
    if ad.sign_count != 0 && ad.sign_count <= stored_sign_count {
        return Err("signCount did not increase (possible clone)".into());
    }
    Ok(ad.sign_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es256::b64url_encode as b64e2;
    use crate::fido::verify::test_support::*;
    use crate::fido::verify::{FLAG_AT, FLAG_UP};
    use ciborium::value::Value as Cbor;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest, Sha256};

    const RP: &str = "example.com";
    const ORIGIN: &str = "https://example.com";
    const CH: &str = "Y2hhbGxlbmdl";

    /// none attestation の attestationObject(b64url) と公開鍵を作る。
    fn make_registration(key: &SigningKey, cred_id: &[u8], sign_count: u32) -> (String, String) {
        let (x, y) = ec_xy(key);
        let cose = cose_es256(&x, &y);
        let acd = attested_cred_data(cred_id, &cose);
        let auth_data = build_auth_data(RP, FLAG_UP | FLAG_AT, sign_count, Some(&acd));
        let att = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]);
        let cdj = client_data_json("webauthn.create", CH, ORIGIN);
        (b64e2(cbor_to_vec(&att)), b64e2(&cdj))
    }

    #[test]
    fn registration_none_roundtrip() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let cred_id = b"my-credential-id";
        let (att_b64, cdj_b64) = make_registration(&key, cred_id, 0);
        let out = verify_registration(&cdj_b64, &att_b64, CH, ORIGIN, RP).unwrap();
        assert_eq!(out.credential_id, b64e2(cred_id));
        let (x, y) = ec_xy(&key);
        assert_eq!(out.pub_x, b64e2(&x));
        assert_eq!(out.pub_y, b64e2(&y));
        assert_eq!(out.sign_count, 0);
    }

    #[test]
    fn registration_rejects_wrong_origin_and_challenge() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (att_b64, cdj_b64) = make_registration(&key, b"cid", 0);
        assert!(verify_registration(&cdj_b64, &att_b64, CH, "https://evil.com", RP).is_err());
        assert!(verify_registration(&cdj_b64, &att_b64, "wrong-challenge", ORIGIN, RP).is_err());
        // rpId 不一致 → rpIdHash 不一致。
        assert!(verify_registration(&cdj_b64, &att_b64, CH, ORIGIN, "evil.com").is_err());
    }

    /// 認証セレモニーの (authenticatorData_b64, signature_b64, clientDataJSON_b64)。
    fn make_authentication(key: &SigningKey, sign_count: u32) -> (String, String, String) {
        let auth_data = build_auth_data(RP, FLAG_UP, sign_count, None);
        let cdj = client_data_json("webauthn.get", CH, ORIGIN);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: Signature = key.sign(&signed);
        (b64e2(&auth_data), b64e2(sig.to_der().as_bytes()), b64e2(&cdj))
    }

    #[test]
    fn authentication_roundtrip_returns_new_signcount() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let (ad, sig, cdj) = make_authentication(&key, 5);
        let new_count =
            verify_authentication(&cdj, &ad, &sig, CH, ORIGIN, RP, &b64e2(&x), &b64e2(&y), 1).unwrap();
        assert_eq!(new_count, 5);
    }

    #[test]
    fn authentication_rejects_clone_signcount_not_increasing() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let (ad, sig, cdj) = make_authentication(&key, 5);
        // stored=5、受信=5 → 増えていない → クローン疑い。
        let r = verify_authentication(&cdj, &ad, &sig, CH, ORIGIN, RP, &b64e2(&x), &b64e2(&y), 5);
        assert!(r.is_err());
    }

    #[test]
    fn authentication_rejects_signature_from_other_key() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let other = SigningKey::random(&mut rand_core::OsRng);
        let (ox, oy) = ec_xy(&other);
        let (ad, sig, cdj) = make_authentication(&key, 5);
        // 別鍵 (other) の (x,y) で検証 → 署名検証で落ちる。
        let r = verify_authentication(&cdj, &ad, &sig, CH, ORIGIN, RP, &b64e2(&ox), &b64e2(&oy), 1);
        assert!(r.is_err());
    }

    #[test]
    fn authentication_zero_signcount_is_accepted() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let (ad, sig, cdj) = make_authentication(&key, 0);
        // 受信 signCount=0 は「カウンタ非対応」として stored に関わらず許容。
        let r = verify_authentication(&cdj, &ad, &sig, CH, ORIGIN, RP, &b64e2(&x), &b64e2(&y), 9);
        assert!(r.is_ok());
    }

    #[test]
    fn extract_challenge_reads_clientdata() {
        let cdj = b64e2(client_data_json("webauthn.get", CH, ORIGIN));
        assert_eq!(extract_challenge(&cdj).as_deref(), Some(CH));
    }
}
