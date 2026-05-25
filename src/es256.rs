//! ES256 / P-256 の共通プリミティブ。
//!
//! 署名（jws.rs: 自鍵で id_token）と検証（webauthn.rs: DER 署名 / dpop.rs: raw r||s 署名）
//! は用途が分かれるため 1 関数化はしないが、以下は同一なので集約する:
//! - 公開鍵 (x,y) → VerifyingKey の組み立て（座標 32byte 左パディング込み）
//! - JWK Thumbprint (RFC 7638)
//! - base64url enc/dec

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::VerifyingKey;
use p256::EncodedPoint;
use sha2::{Digest, Sha256};

pub fn b64url_encode(b: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// pad/標準アルファベット混在を許容してデコード。
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim().replace('+', "-").replace('/', "_");
    URL_SAFE_NO_PAD
        .decode(t.trim_end_matches('='))
        .map_err(|e| format!("base64: {e}"))
}

/// 座標を 32 バイト固定に左ゼロ埋め（authenticator が 31 バイトで返す場合がある）。
pub fn pad32(b: &[u8]) -> Result<[u8; 32], String> {
    if b.len() > 32 {
        return Err("coordinate > 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

/// 非圧縮アフィン座標 (x,y) から P-256 公開鍵を作る。曲線上に乗っているかも検証される。
pub fn verifying_key_from_xy(x: &[u8], y: &[u8]) -> Result<VerifyingKey, String> {
    let xb = pad32(x)?;
    let yb = pad32(y)?;
    let pt = EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&xb),
        p256::FieldBytes::from_slice(&yb),
        false,
    );
    VerifyingKey::from_encoded_point(&pt).map_err(|e| format!("bad EC point: {e}"))
}

/// RFC 7638 EC(P-256) Thumbprint。x,y は base64url 文字列のまま使う
/// （canonical JSON はキー昇順 crv,kty,x,y）。
pub fn jwk_thumbprint_p256(x_b64: &str, y_b64: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
    b64url_encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    #[test]
    fn b64url_roundtrip_and_padding_lenient() {
        let enc = b64url_encode([0xff, 0x00, 0x10]);
        assert_eq!(b64url_decode(&enc).unwrap(), vec![0xff, 0x00, 0x10]);
        // 標準アルファベット + パディングも許容
        let std = "+/A=".to_string(); // '+' '/' を含む
        assert!(b64url_decode(&std).is_ok());
    }

    #[test]
    fn pad32_left_pads_short_coordinate() {
        let out = pad32(&[0x01, 0x02]).unwrap();
        assert_eq!(out[30], 0x01);
        assert_eq!(out[31], 0x02);
        assert!(out[..30].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad32_rejects_oversized() {
        assert!(pad32(&[0u8; 33]).is_err());
    }

    #[test]
    fn verifying_key_from_xy_accepts_real_point_rejects_garbage() {
        // 本物の P-256 公開鍵座標は曲線上に乗る。
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let pt = sk.verifying_key().to_encoded_point(false);
        let x = pt.x().unwrap();
        let y = pt.y().unwrap();
        assert!(verifying_key_from_xy(x, y).is_ok());
        // 全 0xff は曲線上に乗らない。
        assert!(verifying_key_from_xy(&[0xff; 32], &[0xff; 32]).is_err());
    }

    #[test]
    fn thumbprint_is_stable_known_vector() {
        // canonical {"crv":"P-256","kty":"EC","x":"AA","y":"BB"} の SHA-256(b64url)。
        // 値が変わったら canonical JSON の生成が壊れたサイン（リグレッション固定）。
        let got = jwk_thumbprint_p256("AA", "BB");
        let expected = {
            let canonical = r#"{"crv":"P-256","kty":"EC","x":"AA","y":"BB"}"#;
            b64url_encode(Sha256::digest(canonical.as_bytes()))
        };
        assert_eq!(got, expected);
        assert_eq!(got.len(), 43); // SHA-256 → 32byte → b64url no-pad 43 文字
    }

    #[test]
    fn thumbprint_differs_for_different_coordinates() {
        assert_ne!(jwk_thumbprint_p256("AA", "BB"), jwk_thumbprint_p256("AA", "CC"));
    }
}
