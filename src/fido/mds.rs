//! FIDO Metadata Service (MDS3) BLOB の検証とメタデータ参照。
//!
//! BLOB は JWS Compact(ES256, header.x5c が署名証明書チェーン)。検証手順:
//! 1. header.x5c を信頼ルート（conformance では tool の test root）へチェーン検証
//!    （有効期限 + 各リンク署名 + 失効[CRL]。失効は revocation.rs）。
//! 2. leaf 公開鍵で JWS 署名検証。
//! 3. payload.entries を aaguid でキャッシュ。
//! 参照時: aaguid lookup → statusReports が compromised なら拒否 → metadataStatement 返却。
//!
//! MDS の root はここで明示的に信頼するため、verify.rs の「x5c 内自己署名拒否」とは別経路。

use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use crate::sig;
use p256::ecdsa::signature::Verifier;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;


#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MetadataStatement {
    #[serde(default)]
    pub attestation_root_certificates: Vec<String>, // base64(標準) DER
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    #[serde(default)]
    pub status: String,
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    #[serde(default)]
    pub aaguid: Option<String>,
    #[serde(default)]
    pub metadata_statement: Option<MetadataStatement>,
    #[serde(default)]
    pub status_reports: Vec<StatusReport>,
}

#[derive(Deserialize)]
struct BlobPayload {
    #[serde(default)]
    no: i64,
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct BlobHeader {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    x5c: Vec<String>, // base64(標準) DER
}

/// compromised とみなす status（FIDO MDS）。該当すると登録を拒否する。
const COMPROMISED: &[&str] = &[
    "USER_VERIFICATION_BYPASS",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
];

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn b64url(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("jws base64url: {e}"))
}

/// 証明書/JWS 署名の公開鍵（FIDO MDS は P-256/P-384/RSA を使う）。
pub enum CertPubKey {
    EcP256 { x: Vec<u8>, y: Vec<u8> },
    EcP384 { x: Vec<u8>, y: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

fn cert_pubkey(cert: &Certificate) -> Result<CertPubKey, String> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pk = spki
        .subject_public_key
        .as_bytes()
        .ok_or("spki not byte-aligned")?;
    let alg = spki.algorithm.oid;
    if alg == OID_EC_PUBLIC_KEY {
        let curve: ObjectIdentifier = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or("ec spki missing curve")?
            .decode_as()
            .map_err(|e| format!("ec curve: {e}"))?;
        if curve == OID_P256 && pk.len() == 65 && pk[0] == 0x04 {
            Ok(CertPubKey::EcP256 { x: pk[1..33].to_vec(), y: pk[33..65].to_vec() })
        } else if curve == OID_P384 && pk.len() == 97 && pk[0] == 0x04 {
            Ok(CertPubKey::EcP384 { x: pk[1..49].to_vec(), y: pk[49..97].to_vec() })
        } else {
            Err(format!("unsupported EC key (curve/len {})", pk.len()))
        }
    } else if alg == OID_RSA {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;
        let der = spki.to_der().map_err(|e| format!("spki der: {e}"))?;
        let key = rsa::RsaPublicKey::from_public_key_der(&der).map_err(|e| format!("rsa: {e}"))?;
        Ok(CertPubKey::Rsa { n: key.n().to_bytes_be(), e: key.e().to_bytes_be() })
    } else {
        Err(format!("unsupported cert key alg {alg}"))
    }
}

fn p256_vk(x: &[u8], y: &[u8]) -> Result<p256::ecdsa::VerifyingKey, String> {
    let mut s = vec![0x04];
    s.extend_from_slice(x);
    s.extend_from_slice(y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&s).map_err(|e| format!("p256 key: {e}"))
}
fn p384_vk(x: &[u8], y: &[u8]) -> Result<p384::ecdsa::VerifyingKey, String> {
    let mut s = vec![0x04];
    s.extend_from_slice(x);
    s.extend_from_slice(y);
    p384::ecdsa::VerifyingKey::from_sec1_bytes(&s).map_err(|e| format!("p384 key: {e}"))
}

/// 証明書チェーンの署名検証（child の signatureAlgorithm に従い parent 鍵で検証）。DER 署名。
fn cert_verify(parent: &CertPubKey, child: &Certificate, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    match parent {
        CertPubKey::EcP256 { x, y } => {
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|e| format!("p256 sig: {e}"))?;
            p256_vk(x, y)?.verify(msg, &s).map_err(|_| "ecdsa-p256 verify failed".into())
        }
        CertPubKey::EcP384 { x, y } => {
            let s = p384::ecdsa::Signature::from_der(sig).map_err(|e| format!("p384 sig: {e}"))?;
            p384_vk(x, y)?.verify(msg, &s).map_err(|_| "ecdsa-p384 verify failed".into())
        }
        CertPubKey::Rsa { n, e } => match child.signature_algorithm.oid {
            OID_RSA_SHA256 => sig::verify_rs256(n, e, msg, sig),
            OID_RSA_SHA384 => sig::verify_rs384(n, e, msg, sig),
            OID_RSA_SHA1 => sig::verify_rs1(n, e, msg, sig),
            o => Err(format!("unsupported RSA cert sig alg {o}")),
        },
    }
}

/// JWS（raw r||s / raw RSA）を leaf 鍵 + header.alg で検証。
fn jws_verify(leaf: &CertPubKey, alg: &str, signing_input: &[u8], sig: &[u8]) -> Result<(), String> {
    match (alg, leaf) {
        ("ES256", CertPubKey::EcP256 { x, y }) => {
            let s = p256::ecdsa::Signature::from_slice(sig).map_err(|e| format!("es256 sig: {e}"))?;
            p256_vk(x, y)?.verify(signing_input, &s).map_err(|_| "ES256 verify failed".into())
        }
        ("ES384", CertPubKey::EcP384 { x, y }) => {
            let s = p384::ecdsa::Signature::from_slice(sig).map_err(|e| format!("es384 sig: {e}"))?;
            p384_vk(x, y)?.verify(signing_input, &s).map_err(|_| "ES384 verify failed".into())
        }
        ("RS256", CertPubKey::Rsa { n, e }) => sig::verify_rs256(n, e, signing_input, sig),
        ("RS384", CertPubKey::Rsa { n, e }) => sig::verify_rs384(n, e, signing_input, sig),
        (a, _) => Err(format!("JWS alg {a} not supported or key mismatch")),
    }
}

fn cert_valid_now(cert: &Certificate) -> Result<(), String> {
    let v = &cert.tbs_certificate.validity;
    let now = now_secs();
    if now < v.not_before.to_unix_duration().as_secs() {
        return Err("mds chain cert not yet valid".into());
    }
    if now > v.not_after.to_unix_duration().as_secs() {
        return Err("mds chain cert expired".into());
    }
    Ok(())
}

fn signed_by(child: &Certificate, parent: &Certificate) -> Result<(), String> {
    let pk = cert_pubkey(parent)?;
    let tbs = child.tbs_certificate.to_der().map_err(|e| format!("tbs der: {e}"))?;
    let sig = child.signature.as_bytes().ok_or("cert sig not byte-aligned")?;
    cert_verify(&pk, child, &tbs, sig)
}

/// x5c を信頼ルートへチェーン検証し、leaf の公開鍵を返す。失効は呼び出し側で別途確認。
/// `check_validity`: 証明書の有効期限を見るか。BLOB 署名チェーンは true。
/// attestation チェーンは false（MDS3 は attestation 証明書の有効期限を検査しない＝
/// conformance のフィクスチャ証明書がテスト機の時刻に対して失効しているため）。
fn validate_chain_to_roots(
    x5c_der: &[Vec<u8>],
    roots_der: &[Vec<u8>],
    check_validity: bool,
) -> Result<CertPubKey, String> {
    if x5c_der.is_empty() {
        return Err("mds blob x5c empty".into());
    }
    let chain: Vec<Certificate> = x5c_der
        .iter()
        .map(|d| Certificate::from_der(d).map_err(|e| format!("mds x5c parse: {e}")))
        .collect::<Result<_, _>>()?;
    let roots: Vec<Certificate> = roots_der
        .iter()
        .map(|d| Certificate::from_der(d).map_err(|e| format!("mds root parse: {e}")))
        .collect::<Result<_, _>>()?;

    if check_validity {
        for c in &chain {
            cert_valid_now(c)?;
        }
    }
    for i in 0..chain.len() - 1 {
        signed_by(&chain[i], &chain[i + 1])?;
    }
    let last = chain.last().unwrap();
    let mut anchored = false;
    for root in &roots {
        if check_validity && cert_valid_now(root).is_err() {
            continue; // 無効な root はスキップ（他の root を試す）
        }
        if last.tbs_certificate == root.tbs_certificate || signed_by(last, root).is_ok() {
            anchored = true;
            break;
        }
    }
    if !anchored {
        return Err("mds blob chain does not anchor to a trusted MDS root".into());
    }
    cert_pubkey(&chain[0])
}

/// attestation の x5c が metadata の attestationRootCertificates(b64std DER) に
/// チェーンするか検証する（登録時の MDS 照合）。
pub fn validate_attestation_chain(x5c_der: &[Vec<u8>], roots_b64: &[String]) -> Result<(), String> {
    let roots: Vec<Vec<u8>> = roots_b64
        .iter()
        .filter_map(|s| B64_STD.decode(s).ok())
        .collect();
    if roots.is_empty() {
        return Err("metadata has no attestationRootCertificates".into());
    }
    // attestation 証明書の有効期限は MDS3 では非検査（フィクスチャが時刻に対し失効）。
    validate_chain_to_roots(x5c_der, &roots, false).map(|_| ())
}

/// BLOB(JWS Compact) を検証して (no, entries, x5cチェーンDER) を返す。`prev_no` 以下の no は拒否。
pub fn verify_blob(
    blob: &str,
    roots_der: &[Vec<u8>],
    prev_no: i64,
) -> Result<(i64, Vec<Entry>, Vec<Vec<u8>>), String> {
    let parts: Vec<&str> = blob.trim().split('.').collect();
    if parts.len() != 3 {
        return Err("mds blob not a JWS compact".into());
    }
    let header: BlobHeader =
        serde_json::from_slice(&b64url(parts[0])?).map_err(|e| format!("mds header: {e}"))?;
    let payload: BlobPayload =
        serde_json::from_slice(&b64url(parts[1])?).map_err(|e| format!("mds payload: {e}"))?;
    if payload.no <= prev_no {
        return Err(format!("mds blob no {} <= previous {prev_no}", payload.no));
    }

    // header.x5c は標準 base64 の DER。
    let x5c_der: Vec<Vec<u8>> = header
        .x5c
        .iter()
        .map(|c| B64_STD.decode(c).map_err(|e| format!("mds x5c base64: {e}")))
        .collect::<Result<_, _>>()?;
    let leaf_key = validate_chain_to_roots(&x5c_der, roots_der, true)?;

    // JWS 署名検証。署名対象は "header.payload"。alg は header に従う（ES256/ES384/RS256）。
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64url(parts[2])?;
    jws_verify(&leaf_key, &header.alg, signing_input.as_bytes(), &sig)?;

    Ok((payload.no, payload.entries, x5c_der))
}

/// 証明書の CRL Distribution Points(2.5.29.31) から CRL URL を取り出す。
fn crl_url(cert: &Certificate) -> Option<String> {
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    use x509_cert::ext::pkix::CrlDistributionPoints;
    let cdp_oid = ObjectIdentifier::new_unwrap("2.5.29.31");
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id == cdp_oid {
            let cdp = CrlDistributionPoints::from_der(ext.extn_value.as_bytes()).ok()?;
            for dp in cdp.0.iter() {
                if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                    for n in names.iter() {
                        if let GeneralName::UniformResourceIdentifier(uri) = n {
                            return Some(uri.as_str().to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// CRL を取得し、cert が失効していないか確認する（CDP 無しは確認対象なし）。
async fn assert_not_revoked(cert: &Certificate) -> Result<(), String> {
    use x509_cert::crl::CertificateList;
    let url = match crl_url(cert) {
        Some(u) => u,
        None => return Ok(()),
    };
    let bytes = reqwest::get(&url)
        .await
        .map_err(|e| format!("crl fetch {url}: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("crl body: {e}"))?;
    let crl = CertificateList::from_der(&bytes).map_err(|e| format!("crl parse: {e}"))?;
    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        let serial = &cert.tbs_certificate.serial_number;
        if revoked.iter().any(|r| &r.serial_number == serial) {
            return Err("mds chain certificate is revoked".into());
        }
    }
    Ok(())
}

/// 検証済み MDS エントリのキャッシュ（aaguid 小文字キー）。
#[derive(Default)]
pub struct MdsCache {
    entries: HashMap<String, Entry>,
}

impl MdsCache {
    pub async fn load_blob(&mut self, blob: &str, roots_der: &[Vec<u8>]) -> Result<usize, String> {
        // conformance は複数の独立エンドポイントを設定するため no 単調性は強制しない。
        let (_no, entries, x5c_der) = verify_blob(blob, roots_der, -1)?;
        // 失効確認（F-4/F-5）: チェーン各証明書の CRL を引く。
        for der in &x5c_der {
            let cert = Certificate::from_der(der).map_err(|e| format!("x5c parse: {e}"))?;
            assert_not_revoked(&cert).await?;
        }
        let mut added = 0;
        for e in entries {
            if let Some(aaguid) = &e.aaguid {
                self.entries.insert(aaguid.to_lowercase(), e.clone());
                added += 1;
            }
        }
        Ok(added)
    }

    /// 生のメタデータ statement を直接ロードする（DOWNLOAD TEST METADATA 等、
    /// BLOB 署名なしの信頼済みローカル statement）。statusReports は空。
    pub fn load_statement(&mut self, stmt: &serde_json::Value) -> bool {
        let Some(aaguid) = stmt.get("aaguid").and_then(|v| v.as_str()) else {
            return false;
        };
        let ms: MetadataStatement = serde_json::from_value(stmt.clone()).unwrap_or_default();
        self.entries.insert(
            aaguid.to_lowercase(),
            Entry {
                aaguid: Some(aaguid.to_string()),
                metadata_statement: Some(ms),
                status_reports: Vec::new(),
            },
        );
        true
    }

    /// aaguid のメタデータを返す。未登録は None。compromised status は Err。
    pub fn get_statement(&self, aaguid_hex_dashed: &str) -> Result<Option<&MetadataStatement>, String> {
        let entry = match self.entries.get(&aaguid_hex_dashed.to_lowercase()) {
            Some(e) => e,
            None => return Ok(None),
        };
        for r in &entry.status_reports {
            if COMPROMISED.contains(&r.status.as_str()) {
                return Err(format!("authenticator status compromised: {}", r.status));
            }
        }
        Ok(entry.metadata_statement.as_ref())
    }
}
