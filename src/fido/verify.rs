//! FIDO2 Conformance 用の検証コア（ピュア Rust）。
//! Step 2/3 = none attestation + ES256(-7) の登録/認証検証。
//! Step 4 以降で attestation 形式・アルゴリズムをここに足していく。
//!
//! 失敗はどの段で落ちたか文字列で返す（"invalid" 一語にしない）。

use crate::es256::{self, b64url_decode as b64d};
use ciborium::value::Value as Cbor;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::der::asn1::{ObjectIdentifier, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;

/// ecdsa-with-SHA256
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

pub const FLAG_UP: u8 = 0x01; // User Present
pub const FLAG_UV: u8 = 0x04; // User Verified
pub const FLAG_AT: u8 = 0x40; // Attested credential data included
pub const FLAG_ED: u8 = 0x80; // Extension data included

pub struct AuthData<'a> {
    pub rp_id_hash: &'a [u8],
    pub flags: u8,
    pub sign_count: u32,
    pub rest: &'a [u8],
}

/// clientDataJSON(b64url) を検証し raw バイトを返す（type / challenge / origin）。
pub fn check_client_data(
    client_data_json_b64: &str,
    expected_type: &str,
    expected_challenge: &str,
    origin: &str,
) -> Result<Vec<u8>, String> {
    let raw = b64d(client_data_json_b64)?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("clientData json: {e}"))?;
    if v.get("type").and_then(|x| x.as_str()) != Some(expected_type) {
        return Err(format!("clientData.type != {expected_type}"));
    }
    if v.get("challenge").and_then(|x| x.as_str()) != Some(expected_challenge) {
        return Err("clientData.challenge mismatch".into());
    }
    if v.get("origin").and_then(|x| x.as_str()) != Some(origin) {
        return Err(format!(
            "clientData.origin mismatch (got {:?}, want {origin})",
            v.get("origin")
        ));
    }
    // tokenBinding は任意だが、存在する場合は形が決まっている（F-15/16/17）。
    if let Some(tb) = v.get("tokenBinding") {
        let obj = tb
            .as_object()
            .ok_or("clientData.tokenBinding must be an object")?;
        match obj.get("status").and_then(|s| s.as_str()) {
            Some("present") | Some("supported") | Some("not-supported") => {}
            _ => return Err("clientData.tokenBinding.status invalid".into()),
        }
    }
    Ok(raw)
}

/// attStmt の x5c から DER 証明書列を取り出す（無ければ空）。MDS 照合用。
pub fn att_x5c_ders(att_stmt: &Cbor) -> Vec<Vec<u8>> {
    if let Cbor::Map(m) = att_stmt {
        if let Some(Cbor::Array(a)) = cbor_text_get(m, "x5c") {
            return a.iter().filter_map(|c| cbor_bytes(c).map(|b| b.to_vec())).collect();
        }
    }
    Vec::new()
}

/// fmt="none" の attStmt は空マップでなければならない（F-1: full packed を fmt none で送る）。
pub fn require_empty_att_stmt(att_stmt: &Cbor) -> Result<(), String> {
    match att_stmt {
        Cbor::Map(m) if m.is_empty() => Ok(()),
        _ => Err("none attestation must have an empty attStmt".into()),
    }
}

pub fn parse_auth_data(ad: &[u8]) -> Result<AuthData<'_>, String> {
    if ad.len() < 37 {
        return Err("authData too short".into());
    }
    Ok(AuthData {
        rp_id_hash: &ad[0..32],
        flags: ad[32],
        sign_count: u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]),
        rest: &ad[37..],
    })
}

pub fn check_rp_id_hash(rp_id_hash: &[u8], rp_id: &str) -> Result<(), String> {
    if rp_id_hash != Sha256::digest(rp_id.as_bytes()).as_slice() {
        return Err("rpIdHash mismatch".into());
    }
    Ok(())
}

/// UP は常に必須。UV は require_uv のときだけ必須。
pub fn check_flags(flags: u8, require_uv: bool) -> Result<(), String> {
    if flags & FLAG_UP == 0 {
        return Err("UP flag not set".into());
    }
    if require_uv && flags & FLAG_UV == 0 {
        return Err("UV required but not set".into());
    }
    Ok(())
}

fn cose_get_int(m: &[(Cbor, Cbor)], key: i128) -> Option<&Cbor> {
    m.iter()
        .find(|(k, _)| matches!(k, Cbor::Integer(i) if i128::from(*i) == key))
        .map(|(_, v)| v)
}

fn cbor_bytes(v: &Cbor) -> Option<&[u8]> {
    match v {
        Cbor::Bytes(b) => Some(b),
        _ => None,
    }
}

/// 登録された credential 公開鍵（COSE 由来）。検証アルゴリズム別。
#[derive(Clone)]
pub enum CredKey {
    Es256 { x: Vec<u8>, y: Vec<u8> },
    Rs256 { n: Vec<u8>, e: Vec<u8> },
    Rs1 { n: Vec<u8>, e: Vec<u8> },
    Ed25519 { pk: Vec<u8> },
}

impl CredKey {
    pub fn cose_alg(&self) -> i32 {
        match self {
            CredKey::Es256 { .. } => -7,
            CredKey::Rs256 { .. } => -257,
            CredKey::Rs1 { .. } => -65535,
            CredKey::Ed25519 { .. } => -8,
        }
    }

    /// fido-u2f は EC P-256 のみ。EC 鍵なら (x,y) を返す。
    pub fn ec_xy(&self) -> Option<(&[u8], &[u8])> {
        match self {
            CredKey::Es256 { x, y } => Some((x, y)),
            _ => None,
        }
    }

    /// RSA 鍵なら (n,e) を返す（tpm の pubArea 一致確認に使う）。
    pub fn rsa_ne(&self) -> Option<(&[u8], &[u8])> {
        match self {
            CredKey::Rs256 { n, e } | CredKey::Rs1 { n, e } => Some((n, e)),
            _ => None,
        }
    }

    /// signed（= authData || SHA256(clientDataJSON)）に対する署名検証。
    /// ES256 は DER 署名、RS256/RS1 は raw RSA、Ed25519 は raw 64byte。
    pub fn verify(&self, signed: &[u8], signature: &[u8]) -> Result<(), String> {
        match self {
            CredKey::Es256 { x, y } => verify_es256_raw(x, y, signed, signature),
            CredKey::Rs256 { n, e } => crate::sig::verify_rs256(n, e, signed, signature),
            CredKey::Rs1 { n, e } => crate::sig::verify_rs1(n, e, signed, signature),
            CredKey::Ed25519 { pk } => crate::sig::verify_ed25519(pk, signed, signature),
        }
    }
}

/// COSE_Key をパースして CredKey と消費バイト数を返す。
/// 消費数は authData の余剰バイト検出（F-12）に使う。
pub fn parse_cose_key(cose_bytes: &[u8]) -> Result<(CredKey, usize), String> {
    let mut cur = Cursor::new(cose_bytes);
    let cose: Cbor =
        ciborium::from_reader(&mut cur).map_err(|e| format!("COSE cbor: {e}"))?;
    let consumed = cur.position() as usize;
    let m = match &cose {
        Cbor::Map(m) => m,
        _ => return Err("COSE key is not a map".into()),
    };
    let int = |k| {
        cose_get_int(m, k).and_then(|v| match v {
            Cbor::Integer(i) => Some(i128::from(*i)),
            _ => None,
        })
    };
    let bytes = |k| cose_get_int(m, k).and_then(cbor_bytes);
    let kty = int(1);
    let alg = int(3);
    match kty {
        Some(2) => {
            // EC2 / ES256 / P-256: crv(-1)=1, x(-2), y(-3)
            if alg != Some(-7) {
                return Err(format!("COSE EC2 alg != ES256 ({alg:?})"));
            }
            let x = bytes(-2).ok_or("COSE missing x")?;
            let y = bytes(-3).ok_or("COSE missing y")?;
            let xb = es256::pad32(x)?.to_vec();
            let yb = es256::pad32(y)?.to_vec();
            es256::verifying_key_from_xy(&xb, &yb)?; // 曲線上の点か検証
            Ok((CredKey::Es256 { x: xb, y: yb }, consumed))
        }
        Some(3) => {
            // RSA: n(-1), e(-2)
            let n = bytes(-1).ok_or("COSE RSA missing n")?.to_vec();
            let e = bytes(-2).ok_or("COSE RSA missing e")?.to_vec();
            match alg {
                Some(-257) => Ok((CredKey::Rs256 { n, e }, consumed)),
                Some(-65535) => Ok((CredKey::Rs1 { n, e }, consumed)),
                _ => Err(format!("COSE RSA alg unsupported ({alg:?})")),
            }
        }
        Some(1) => {
            // OKP / Ed25519: crv(-1)=6, x(-2)
            if alg != Some(-8) {
                return Err(format!("COSE OKP alg != EdDSA ({alg:?})"));
            }
            if int(-1) != Some(6) {
                return Err(format!("COSE OKP crv != Ed25519 ({:?})", int(-1)));
            }
            Ok((
                CredKey::Ed25519 {
                    pk: bytes(-2).ok_or("COSE OKP missing x")?.to_vec(),
                },
                consumed,
            ))
        }
        other => Err(format!("COSE kty unsupported ({other:?})")),
    }
}

/// assertion 署名検証（signed = authData || SHA256(clientDataJSON)）。
pub fn verify_assertion(
    key: &CredKey,
    auth_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&signed, signature)
}

/// 任意メッセージに対する ES256(DER) 署名検証（内部で SHA-256）。
pub fn verify_es256_raw(
    pub_x: &[u8],
    pub_y: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<(), String> {
    let vk = es256::verifying_key_from_xy(pub_x, pub_y)?;
    let sig = Signature::from_der(signature_der).map_err(|e| format!("sig der: {e}"))?;
    vk.verify(message, &sig).map_err(|_| "invalid signature".to_string())
}

/// authData || SHA256(clientDataJSON) に対する ES256 署名検証（assertion / packed 共通）。
pub fn verify_es256_signature(
    pub_x: &[u8],
    pub_y: &[u8],
    auth_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
) -> Result<(), String> {
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    verify_es256_raw(pub_x, pub_y, &signed, signature_der)
}

pub struct AttestationObject {
    pub fmt: String,
    pub auth_data: Vec<u8>,
    pub att_stmt: Cbor,
}

fn cbor_text_get<'a>(m: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    m.iter()
        .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
        .map(|(_, v)| v)
}

/// attestationObject(CBOR) から fmt / authData / attStmt を取り出す。
pub fn parse_attestation_object(att: &[u8]) -> Result<AttestationObject, String> {
    let obj: Cbor =
        ciborium::from_reader(Cursor::new(att)).map_err(|e| format!("attObj cbor: {e}"))?;
    let m = match &obj {
        Cbor::Map(m) => m,
        _ => return Err("attestationObject not a map".into()),
    };
    let fmt = match cbor_text_get(m, "fmt") {
        Some(Cbor::Text(s)) => s.clone(),
        _ => return Err("attestationObject missing fmt".into()),
    };
    let auth_data = cbor_text_get(m, "authData")
        .and_then(cbor_bytes)
        .ok_or("attestationObject missing authData")?
        .to_vec();
    let att_stmt = cbor_text_get(m, "attStmt").cloned().unwrap_or(Cbor::Map(vec![]));
    Ok(AttestationObject {
        fmt,
        auth_data,
        att_stmt,
    })
}

const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// id-fido-gen-ce-aaguid
const OID_FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

fn ec_p256_xy_from_parsed(cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pk = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or("spki bitstring not byte-aligned")?;
    if pk.len() == 65 && pk[0] == 0x04 {
        Ok((pk[1..33].to_vec(), pk[33..65].to_vec()))
    } else {
        Err(format!("cert key not uncompressed P-256 (len {})", pk.len()))
    }
}

/// x5c leaf 証明書から EC P-256 公開鍵座標 (x,y) 生 32 バイトを取り出す。
fn ec_p256_xy_from_cert(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert = Certificate::from_der(der).map_err(|e| format!("x5c parse: {e}"))?;
    ec_p256_xy_from_parsed(&cert)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// x5c 全証明書の有効期限チェック（F-6 期限切れ / F-7 未開始 / F-12 中間期限切れ）と
/// 内部チェーンの署名検証（F-9 チェーン不正）。trust anchor 照合は Step 6(MDS)。
fn check_cert_chain(ders: &[&[u8]]) -> Result<(), String> {
    let parsed: Vec<Certificate> = ders
        .iter()
        .map(|d| Certificate::from_der(d).map_err(|e| format!("x5c parse: {e}")))
        .collect::<Result<_, _>>()?;
    let now = now_secs();
    for c in &parsed {
        let v = &c.tbs_certificate.validity;
        let nb = v.not_before.to_unix_duration().as_secs();
        let na = v.not_after.to_unix_duration().as_secs();
        if now < nb {
            return Err("certificate not yet valid".into());
        }
        if now > na {
            return Err("certificate expired".into());
        }
        // 自己署名証明書（= 信頼アンカー）を x5c に含めてはならない。
        // 信頼ストアを持たない以上、自己署名 root は信頼できず拒否する（F-2 / F-10）。
        let iss = c.tbs_certificate.issuer.to_der().map_err(|e| format!("issuer der: {e}"))?;
        let sub = c.tbs_certificate.subject.to_der().map_err(|e| format!("subject der: {e}"))?;
        if iss == sub {
            return Err("attestation x5c must not contain a self-signed certificate".into());
        }
    }
    // child[i] が parent[i+1] の鍵で署名されているか（EC P-256/SHA-256 のリンクのみ検証）。
    for i in 0..parsed.len().saturating_sub(1) {
        let child = &parsed[i];
        let parent = &parsed[i + 1];
        if child.signature_algorithm.oid != OID_ECDSA_SHA256 {
            continue;
        }
        let tbs = child
            .tbs_certificate
            .to_der()
            .map_err(|e| format!("tbs der: {e}"))?;
        let sig = child
            .signature
            .as_bytes()
            .ok_or("cert signature not byte-aligned")?;
        let (px, py) = ec_p256_xy_from_parsed(parent)?;
        verify_es256_raw(&px, &py, &tbs, sig).map_err(|_| "certificate chain signature invalid".to_string())?;
    }
    Ok(())
}

/// attestation 証明書の構造チェック（§8.2.1: Subject-OU / CA:false / AAGUID 拡張一致）。
/// trust anchor 照合は Step 6（MDS）。
fn check_attestn_cert(der: &[u8], aaguid: &[u8]) -> Result<(), String> {
    let cert = Certificate::from_der(der).map_err(|e| format!("x5c parse: {e}"))?;

    // §8.2.1 Subject 要件（self 偽装 full を弾く: F-2）。
    let subject = &cert.tbs_certificate.subject;
    let find = |oid: ObjectIdentifier| -> Option<Vec<u8>> {
        subject.0.iter().find_map(|rdn| {
            rdn.0
                .iter()
                .find(|atv| atv.oid == oid)
                .map(|atv| atv.value.value().to_vec())
        })
    };
    let ou = find(ObjectIdentifier::new_unwrap("2.5.4.11"));
    if ou.as_deref() != Some(b"Authenticator Attestation".as_slice()) {
        return Err("attestn cert Subject-OU != 'Authenticator Attestation'".into());
    }
    if find(ObjectIdentifier::new_unwrap("2.5.4.3")).is_none_or(|v| v.is_empty()) {
        return Err("attestn cert Subject-CN empty".into());
    }
    if find(ObjectIdentifier::new_unwrap("2.5.4.10")).is_none_or(|v| v.is_empty()) {
        return Err("attestn cert Subject-O empty".into());
    }
    if !matches!(find(ObjectIdentifier::new_unwrap("2.5.4.6")), Some(v) if v.len() == 2) {
        return Err("attestn cert Subject-C not a 2-char ISO 3166 code".into());
    }
    if cert.tbs_certificate.version != x509_cert::Version::V3 {
        return Err("attestn cert version != 3".into());
    }

    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == OID_BASIC_CONSTRAINTS {
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| format!("basicConstraints: {e}"))?;
                if bc.ca {
                    return Err("attestn cert basicConstraints CA must be false".into());
                }
            } else if ext.extn_id == OID_FIDO_AAGUID {
                // 値は 16 バイト AAGUID を包む OCTET STRING。
                let inner = OctetString::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| format!("aaguid ext: {e}"))?;
                if inner.as_bytes() != aaguid {
                    return Err("AAGUID extension mismatch".into());
                }
            }
        }
    }
    Ok(())
}

/// packed attestation（self / full）の検証。ES256(-7) のみ。
/// verificationData = authData || SHA256(clientDataJSON) を署名対象とする。
pub fn verify_packed(
    att_stmt: &Cbor,
    auth_data: &[u8],
    client_data_json: &[u8],
    cred_key: &CredKey,
    aaguid: &[u8],
) -> Result<(), String> {
    let m = match att_stmt {
        Cbor::Map(m) => m,
        _ => return Err("packed attStmt not a map".into()),
    };
    let alg = match cbor_text_get(m, "alg") {
        Some(Cbor::Integer(i)) => i128::from(*i) as i32,
        _ => return Err("packed attStmt missing alg".into()),
    };
    let sig = cbor_text_get(m, "sig")
        .and_then(cbor_bytes)
        .ok_or("packed attStmt missing sig")?;
    match cbor_text_get(m, "x5c") {
        Some(Cbor::Array(certs)) if !certs.is_empty() => {
            // full attestation: attestation cert で検証（現状 EC P-256/ES256 のみ）。
            if alg != -7 {
                return Err(format!("packed full alg {alg} not supported yet"));
            }
            let ders: Vec<&[u8]> = certs
                .iter()
                .map(cbor_bytes)
                .collect::<Option<_>>()
                .ok_or("x5c entry not bytes")?;
            let leaf = ders[0];
            let (x, y) = ec_p256_xy_from_cert(leaf)?;
            verify_es256_signature(&x, &y, auth_data, client_data_json, sig)?;
            check_attestn_cert(leaf, aaguid)?;
            check_cert_chain(&ders)
        }
        Some(_) => Err("packed x5c invalid".into()),
        None => {
            // self attestation: alg は credential 公開鍵の alg と一致必須、その鍵で検証。
            if alg != cred_key.cose_alg() {
                return Err(format!(
                    "packed self alg {alg} != credential alg {}",
                    cred_key.cose_alg()
                ));
            }
            verify_assertion(cred_key, auth_data, client_data_json, sig)
        }
    }
}

/// fido-u2f attestation の検証（WebAuthn §8.6）。ES256/P-256 固定。
/// 署名対象 = 0x00 || rpIdHash || SHA256(clientDataJSON) || credentialId || (0x04||x||y)。
pub fn verify_u2f(
    att_stmt: &Cbor,
    rp_id_hash: &[u8],
    client_data_json: &[u8],
    cred_id: &[u8],
    cred_pub_x: &[u8],
    cred_pub_y: &[u8],
) -> Result<(), String> {
    let m = match att_stmt {
        Cbor::Map(m) => m,
        _ => return Err("u2f attStmt not a map".into()),
    };
    let sig = cbor_text_get(m, "sig")
        .and_then(cbor_bytes)
        .ok_or("u2f attStmt missing sig")?;
    let leaf = match cbor_text_get(m, "x5c") {
        Some(Cbor::Array(c)) if c.len() == 1 => cbor_bytes(&c[0]).ok_or("u2f x5c[0] not bytes")?,
        Some(Cbor::Array(_)) => return Err("u2f x5c must hold exactly one cert".into()),
        _ => return Err("u2f attStmt missing x5c".into()),
    };
    let (cert_x, cert_y) = ec_p256_xy_from_cert(leaf)?;

    let mut vd = Vec::with_capacity(1 + 32 + 32 + cred_id.len() + 65);
    vd.push(0x00);
    vd.extend_from_slice(rp_id_hash);
    vd.extend_from_slice(&Sha256::digest(client_data_json));
    vd.extend_from_slice(cred_id);
    vd.push(0x04);
    vd.extend_from_slice(cred_pub_x);
    vd.extend_from_slice(cred_pub_y);

    verify_es256_raw(&cert_x, &cert_y, &vd, sig)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! WebAuthn セレモニーのフィクスチャ生成（verify.rs / webauthn.rs のテスト共用）。
    use super::*;
    use ciborium::value::Integer;
    use p256::ecdsa::SigningKey;

    pub fn cbor_to_vec(v: &Cbor) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).unwrap();
        buf
    }

    pub fn ec_xy(key: &SigningKey) -> (Vec<u8>, Vec<u8>) {
        let pt = key.verifying_key().to_encoded_point(false);
        (pt.x().unwrap().to_vec(), pt.y().unwrap().to_vec())
    }

    /// ES256 の COSE_Key（kty=2, alg=-7, x=-2, y=-3）。
    pub fn cose_es256(x: &[u8], y: &[u8]) -> Cbor {
        Cbor::Map(vec![
            (Cbor::Integer(Integer::from(1)), Cbor::Integer(Integer::from(2))),
            (Cbor::Integer(Integer::from(3)), Cbor::Integer(Integer::from(-7))),
            (Cbor::Integer(Integer::from(-1)), Cbor::Integer(Integer::from(1))),
            (Cbor::Integer(Integer::from(-2)), Cbor::Bytes(x.to_vec())),
            (Cbor::Integer(Integer::from(-3)), Cbor::Bytes(y.to_vec())),
        ])
    }

    /// authData を組み立てる。attested は登録時の attestedCredentialData(なければ None)。
    pub fn build_auth_data(rp_id: &str, flags: u8, sign_count: u32, attested: Option<&[u8]>) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        ad.push(flags);
        ad.extend_from_slice(&sign_count.to_be_bytes());
        if let Some(a) = attested {
            ad.extend_from_slice(a);
        }
        ad
    }

    /// aaguid(16) || credIdLen(2) || credId || COSE。
    pub fn attested_cred_data(cred_id: &[u8], cose: &Cbor) -> Vec<u8> {
        let mut out = vec![0u8; 16]; // AAGUID = 全0（none）
        out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(&cbor_to_vec(cose));
        out
    }

    pub fn client_data_json(typ: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::json!({"type": typ, "challenge": challenge, "origin": origin})
            .to_string()
            .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const RP: &str = "example.com";
    const ORIGIN: &str = "https://example.com";
    const CH: &str = "Y2hhbGxlbmdl"; // "challenge" の b64url 相当文字列（等価比較のみ）

    fn b64(b: &[u8]) -> String {
        es256::b64url_encode(b)
    }

    #[test]
    fn parse_auth_data_rejects_too_short() {
        assert!(parse_auth_data(&[0u8; 36]).is_err());
        assert!(parse_auth_data(&[0u8; 37]).is_ok());
    }

    #[test]
    fn parse_auth_data_extracts_fields() {
        let ad = build_auth_data(RP, FLAG_UP | FLAG_AT, 42, None);
        let parsed = parse_auth_data(&ad).unwrap();
        assert_eq!(parsed.flags, FLAG_UP | FLAG_AT);
        assert_eq!(parsed.sign_count, 42);
        assert_eq!(parsed.rp_id_hash, &Sha256::digest(RP.as_bytes())[..]);
    }

    #[test]
    fn check_rp_id_hash_matches_and_mismatches() {
        let h = Sha256::digest(RP.as_bytes());
        assert!(check_rp_id_hash(&h, RP).is_ok());
        assert!(check_rp_id_hash(&h, "evil.com").is_err());
    }

    #[test]
    fn check_flags_enforces_up_and_uv() {
        assert!(check_flags(FLAG_UP, false).is_ok());
        assert!(check_flags(0, false).is_err()); // UP なし
        assert!(check_flags(FLAG_UP, true).is_err()); // UV 要求なのに未設定
        assert!(check_flags(FLAG_UP | FLAG_UV, true).is_ok());
    }

    #[test]
    fn check_client_data_validates_all_fields() {
        let cdj = b64(&client_data_json("webauthn.get", CH, ORIGIN));
        assert!(check_client_data(&cdj, "webauthn.get", CH, ORIGIN).is_ok());
        // type 不一致
        assert!(check_client_data(&cdj, "webauthn.create", CH, ORIGIN).is_err());
        // challenge 不一致
        assert!(check_client_data(&cdj, "webauthn.get", "other", ORIGIN).is_err());
        // origin 不一致
        assert!(check_client_data(&cdj, "webauthn.get", CH, "https://evil.com").is_err());
    }

    #[test]
    fn check_client_data_rejects_bad_token_binding() {
        let raw = serde_json::json!({
            "type": "webauthn.get", "challenge": CH, "origin": ORIGIN,
            "tokenBinding": {"status": "bogus"}
        })
        .to_string();
        let cdj = b64(raw.as_bytes());
        assert!(check_client_data(&cdj, "webauthn.get", CH, ORIGIN).is_err());
    }

    #[test]
    fn parse_cose_key_es256_roundtrips() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let bytes = cbor_to_vec(&cose_es256(&x, &y));
        let (ck, consumed) = parse_cose_key(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match ck {
            CredKey::Es256 { x: kx, y: ky } => {
                assert_eq!(kx, x);
                assert_eq!(ky, y);
            }
            _ => panic!("expected Es256"),
        }
    }

    #[test]
    fn parse_cose_key_rejects_ec_with_wrong_alg() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let mut m = match cose_es256(&x, &y) {
            Cbor::Map(m) => m,
            _ => unreachable!(),
        };
        // alg(3) を -257(RS256) に書き換え → EC2 なのに alg 不一致で拒否。
        m[1].1 = Cbor::Integer(ciborium::value::Integer::from(-257));
        assert!(parse_cose_key(&cbor_to_vec(&Cbor::Map(m))).is_err());
    }

    #[test]
    fn parse_cose_key_rejects_unsupported_kty() {
        use ciborium::value::Integer;
        let m = Cbor::Map(vec![
            (Cbor::Integer(Integer::from(1)), Cbor::Integer(Integer::from(99))),
            (Cbor::Integer(Integer::from(3)), Cbor::Integer(Integer::from(-7))),
        ]);
        assert!(parse_cose_key(&cbor_to_vec(&m)).is_err());
    }

    #[test]
    fn parse_cose_key_rejects_off_curve_point() {
        use ciborium::value::Integer;
        // kty=2, alg=-7 だが x,y が曲線上に乗らない → verifying_key_from_xy が拒否。
        let m = Cbor::Map(vec![
            (Cbor::Integer(Integer::from(1)), Cbor::Integer(Integer::from(2))),
            (Cbor::Integer(Integer::from(3)), Cbor::Integer(Integer::from(-7))),
            (Cbor::Integer(Integer::from(-2)), Cbor::Bytes(vec![0xff; 32])),
            (Cbor::Integer(Integer::from(-3)), Cbor::Bytes(vec![0xff; 32])),
        ]);
        assert!(parse_cose_key(&cbor_to_vec(&m)).is_err());
    }

    #[test]
    fn parse_attestation_object_extracts_fmt_and_authdata() {
        let ad = build_auth_data(RP, FLAG_UP, 0, None);
        let att = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(ad.clone())),
        ]);
        let parsed = parse_attestation_object(&cbor_to_vec(&att)).unwrap();
        assert_eq!(parsed.fmt, "none");
        assert_eq!(parsed.auth_data, ad);
        assert!(require_empty_att_stmt(&parsed.att_stmt).is_ok());
    }

    #[test]
    fn require_empty_att_stmt_rejects_nonempty() {
        let non_empty = Cbor::Map(vec![(Cbor::Text("alg".into()), Cbor::Integer(ciborium::value::Integer::from(-7)))]);
        assert!(require_empty_att_stmt(&non_empty).is_err());
    }

    #[test]
    fn verify_assertion_accepts_valid_es256_and_rejects_tampered() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let cred = CredKey::Es256 { x: x.clone(), y: y.clone() };
        let auth_data = build_auth_data(RP, FLAG_UP, 1, None);
        let cdj = client_data_json("webauthn.get", CH, ORIGIN);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: Signature = key.sign(&signed);
        let der = sig.to_der();
        assert!(verify_assertion(&cred, &auth_data, &cdj, der.as_bytes()).is_ok());
        // clientData を改竄 → 署名検証で落ちる。
        let bad_cdj = client_data_json("webauthn.get", "tampered", ORIGIN);
        assert!(verify_assertion(&cred, &auth_data, &bad_cdj, der.as_bytes()).is_err());
    }

    #[test]
    fn verify_packed_self_attestation_roundtrip() {
        use ciborium::value::Integer;
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let cred = CredKey::Es256 { x, y };
        let auth_data = build_auth_data(RP, FLAG_UP | FLAG_AT, 0, None);
        let cdj = client_data_json("webauthn.create", CH, ORIGIN);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: Signature = key.sign(&signed);
        // self attestation: x5c なし、alg=-7、credential 鍵で署名。
        let att = Cbor::Map(vec![
            (Cbor::Text("alg".into()), Cbor::Integer(Integer::from(-7))),
            (Cbor::Text("sig".into()), Cbor::Bytes(sig.to_der().as_bytes().to_vec())),
        ]);
        assert!(verify_packed(&att, &auth_data, &cdj, &cred, &[0u8; 16]).is_ok());
    }

    #[test]
    fn verify_packed_self_rejects_alg_mismatch() {
        use ciborium::value::Integer;
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let cred = CredKey::Es256 { x, y };
        let auth_data = build_auth_data(RP, FLAG_UP | FLAG_AT, 0, None);
        let cdj = client_data_json("webauthn.create", CH, ORIGIN);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: Signature = key.sign(&signed);
        // alg を -257 と偽る → credential alg(-7) と不一致で拒否。
        let att = Cbor::Map(vec![
            (Cbor::Text("alg".into()), Cbor::Integer(Integer::from(-257))),
            (Cbor::Text("sig".into()), Cbor::Bytes(sig.to_der().as_bytes().to_vec())),
        ]);
        assert!(verify_packed(&att, &auth_data, &cdj, &cred, &[0u8; 16]).is_err());
    }
}
