//! TPM attestation の検証（WebAuthn §8.3）。RSA AIK / SHA-256・SHA-1 のみ。ピュア Rust。

use crate::fido::verify::CredKey;
use crate::sig;
use ciborium::value::Value as Cbor;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage};
use x509_cert::Certificate;

const TPM_GENERATED: u32 = 0xFF54_4347;
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000B;

const OID_TCG_AIK: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.3");
const OID_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err("tpm: unexpected end of buffer".into());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// TPM2B = 2byte size + data。
    fn tpm2b(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn trim0(b: &[u8]) -> &[u8] {
    let mut s = b;
    while s.first() == Some(&0) {
        s = &s[1..];
    }
    s
}

fn hash_cose_alg(alg: i32, data: &[u8]) -> Result<Vec<u8>, String> {
    match alg {
        -257 => Ok(Sha256::digest(data).to_vec()),
        -65535 => Ok(Sha1::digest(data).to_vec()),
        _ => Err(format!("tpm alg {alg} not supported (RS256/RS1 only)")),
    }
}

fn hash_tpm_alg(name_alg: u16, data: &[u8]) -> Result<Vec<u8>, String> {
    match name_alg {
        TPM_ALG_SHA256 => Ok(Sha256::digest(data).to_vec()),
        TPM_ALG_SHA1 => Ok(Sha1::digest(data).to_vec()),
        a => Err(format!("tpm nameAlg {a:#06x} unsupported")),
    }
}

/// TPMT_PUBLIC（RSA）から (n, e, nameAlg) を取り出す。
fn parse_pubarea_rsa(pub_area: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u16), String> {
    let mut r = Reader::new(pub_area);
    let typ = r.u16()?;
    if typ != TPM_ALG_RSA {
        return Err(format!("tpm pubArea type {typ:#06x} != RSA"));
    }
    let name_alg = r.u16()?;
    let _object_attributes = r.u32()?;
    let _auth_policy = r.tpm2b()?;
    // TPMS_RSA_PARMS: symmetric / scheme / keyBits / exponent
    let symmetric = r.u16()?;
    if symmetric != TPM_ALG_NULL {
        // TPMT_SYM_DEF_OBJECT: keyBits + mode
        r.u16()?;
        r.u16()?;
    }
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        // TPMS_SCHEME_HASH: hashAlg
        r.u16()?;
    }
    let _key_bits = r.u16()?;
    let exponent = r.u32()?;
    // unique: TPM2B_PUBLIC_KEY_RSA = modulus
    let modulus = r.tpm2b()?;
    let e = if exponent == 0 {
        vec![0x01, 0x00, 0x01] // 既定 65537
    } else {
        exponent.to_be_bytes().to_vec()
    };
    Ok((modulus.to_vec(), e, name_alg))
}

struct CertInfo {
    magic: u32,
    typ: u16,
    extra_data: Vec<u8>,
    attested_name: Vec<u8>,
}

/// TPMS_ATTEST を解析。
fn parse_certinfo(cert_info: &[u8]) -> Result<CertInfo, String> {
    let mut r = Reader::new(cert_info);
    let magic = r.u32()?;
    let typ = r.u16()?;
    let _qualified_signer = r.tpm2b()?;
    let extra_data = r.tpm2b()?.to_vec();
    let _clock_info = r.take(17)?; // TPMS_CLOCK_INFO
    let _firmware_version = r.take(8)?;
    // TPMS_CERTIFY_INFO: name + qualifiedName
    let attested_name = r.tpm2b()?.to_vec();
    let _qualified_name = r.tpm2b()?;
    Ok(CertInfo {
        magic,
        typ,
        extra_data,
        attested_name,
    })
}

fn aik_rsa_ne(cert: &Certificate) -> Result<(Vec<u8>, Vec<u8>), String> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("aik spki der: {e}"))?;
    let key = rsa::RsaPublicKey::from_public_key_der(&spki)
        .map_err(|e| format!("aik rsa key: {e}"))?;
    Ok((key.n().to_bytes_be(), key.e().to_bytes_be()))
}

/// §8.3.1: AIK 証明書は tcg-kp-AIKCertificate EKU を持ち basicConstraints CA=false。
fn check_aik_cert(cert: &Certificate) -> Result<(), String> {
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or("aik cert has no extensions")?;
    let mut eku_ok = false;
    for ext in exts.iter() {
        if ext.extn_id == OID_EKU {
            let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                .map_err(|e| format!("eku: {e}"))?;
            if eku.0.iter().any(|o| *o == OID_TCG_AIK) {
                eku_ok = true;
            }
        } else if ext.extn_id == OID_BASIC_CONSTRAINTS {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                .map_err(|e| format!("basicConstraints: {e}"))?;
            if bc.ca {
                return Err("aik cert basicConstraints CA must be false".into());
            }
        }
    }
    if !eku_ok {
        return Err("aik cert missing tcg-kp-AIKCertificate EKU".into());
    }
    Ok(())
}

pub fn verify_tpm(
    att_stmt: &Cbor,
    auth_data: &[u8],
    client_data_json: &[u8],
    cred_key: &CredKey,
) -> Result<(), String> {
    let m = match att_stmt {
        Cbor::Map(m) => m,
        _ => return Err("tpm attStmt not a map".into()),
    };
    let get = |k: &str| {
        m.iter()
            .find(|(kk, _)| matches!(kk, Cbor::Text(t) if t == k))
            .map(|(_, v)| v)
    };
    let bytes = |k: &str| match get(k) {
        Some(Cbor::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    };

    match get("ver") {
        Some(Cbor::Text(v)) if v == "2.0" => {}
        _ => return Err("tpm ver != 2.0".into()),
    }
    let alg = match get("alg") {
        Some(Cbor::Integer(i)) => i128::from(*i) as i32,
        _ => return Err("tpm attStmt missing alg".into()),
    };
    let sig = bytes("sig").ok_or("tpm attStmt missing sig")?;
    let cert_info = bytes("certInfo").ok_or("tpm attStmt missing certInfo")?;
    let pub_area = bytes("pubArea").ok_or("tpm attStmt missing pubArea")?;
    let aik_der = match get("x5c") {
        Some(Cbor::Array(a)) if !a.is_empty() => match &a[0] {
            Cbor::Bytes(b) => b.as_slice(),
            _ => return Err("tpm x5c[0] not bytes".into()),
        },
        _ => return Err("tpm attStmt missing x5c".into()),
    };

    // 1. pubArea の鍵が credential 公開鍵と一致するか。
    let (pa_n, pa_e, name_alg) = parse_pubarea_rsa(pub_area)?;
    let (cn, ce) = cred_key.rsa_ne().ok_or("tpm credential key is not RSA")?;
    if trim0(&pa_n) != trim0(cn) || trim0(&pa_e) != trim0(ce) {
        return Err("tpm pubArea key != credential key".into());
    }

    // 2. certInfo の検証。
    let ci = parse_certinfo(cert_info)?;
    if ci.magic != TPM_GENERATED {
        return Err("tpm certInfo magic invalid".into());
    }
    if ci.typ != TPM_ST_ATTEST_CERTIFY {
        return Err("tpm certInfo type != ATTEST_CERTIFY".into());
    }
    // extraData == hash_alg(authData || clientDataHash)
    let mut att_to_be_signed = auth_data.to_vec();
    att_to_be_signed.extend_from_slice(&Sha256::digest(client_data_json));
    if ci.extra_data != hash_cose_alg(alg, &att_to_be_signed)? {
        return Err("tpm certInfo.extraData mismatch".into());
    }
    // attested.name == nameAlg(2byte BE) || hash_nameAlg(pubArea)
    let mut expected_name = name_alg.to_be_bytes().to_vec();
    expected_name.extend_from_slice(&hash_tpm_alg(name_alg, pub_area)?);
    if ci.attested_name != expected_name {
        return Err("tpm certInfo attested name mismatch".into());
    }

    // 3. AIK 証明書で certInfo の署名を検証。
    let aik = Certificate::from_der(aik_der).map_err(|e| format!("aik cert parse: {e}"))?;
    check_aik_cert(&aik)?;
    let (an, ae) = aik_rsa_ne(&aik)?;
    match alg {
        -257 => sig::verify_rs256(&an, &ae, cert_info, sig),
        -65535 => sig::verify_rs1(&an, &ae, cert_info, sig),
        _ => Err(format!("tpm alg {alg} not supported (RS256/RS1 only)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_take_is_bounds_checked() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(2).unwrap(), &[1, 2]);
        assert!(r.take(2).is_err()); // 残り1バイトに2要求 → パニックせずエラー
    }

    #[test]
    fn reader_u16_u32_tpm2b_truncation() {
        assert!(Reader::new(&[0x00]).u16().is_err());
        assert!(Reader::new(&[0x00, 0x00, 0x00]).u32().is_err());
        // TPM2B: size=4 だが本体3バイトしかない。
        assert!(Reader::new(&[0x00, 0x04, 0xaa, 0xbb, 0xcc]).tpm2b().is_err());
    }

    #[test]
    fn parse_pubarea_rejects_non_rsa_type() {
        // type=0x0023(ECC) → RSA でないので拒否（パニックしない）。
        let pa = [0x00, 0x23, 0x00, 0x0b];
        assert!(parse_pubarea_rsa(&pa).is_err());
    }

    #[test]
    fn parse_pubarea_rejects_truncated() {
        // type=RSA だが以降が足りない。
        let pa = [0x00, 0x01];
        assert!(parse_pubarea_rsa(&pa).is_err());
    }

    #[test]
    fn parse_pubarea_rsa_minimal_valid() {
        // type=RSA, nameAlg=SHA256, objAttr=0, authPolicy(len0),
        // symmetric=NULL, scheme=NULL, keyBits=2048, exponent=0(=65537),
        // unique(modulus) TPM2B len=4。
        let mut pa = Vec::new();
        pa.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        pa.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        pa.extend_from_slice(&0u32.to_be_bytes()); // objectAttributes
        pa.extend_from_slice(&0u16.to_be_bytes()); // authPolicy TPM2B len=0
        pa.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
        pa.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
        pa.extend_from_slice(&2048u16.to_be_bytes()); // keyBits
        pa.extend_from_slice(&0u32.to_be_bytes()); // exponent=0
        pa.extend_from_slice(&4u16.to_be_bytes()); // modulus TPM2B len=4
        pa.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let (n, e, name_alg) = parse_pubarea_rsa(&pa).unwrap();
        assert_eq!(n, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(e, vec![0x01, 0x00, 0x01]); // exponent=0 → 既定 65537
        assert_eq!(name_alg, TPM_ALG_SHA256);
    }

    #[test]
    fn verify_tpm_rejects_non_map_and_missing_fields() {
        let cred = CredKey::Rs256 { n: vec![1], e: vec![1, 0, 1] };
        assert!(verify_tpm(&Cbor::Null, b"ad", b"cdj", &cred).is_err());
        // ver が無い空マップ。
        assert!(verify_tpm(&Cbor::Map(vec![]), b"ad", b"cdj", &cred).is_err());
    }
}
