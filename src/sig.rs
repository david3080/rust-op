//! 形式非依存の署名検証プリミティブ（ピュア Rust / RustCrypto）。
//!
//! 鍵は「生バイトの構成要素」で受け取り、COSE / JWK / cert など出所に依らず使える。
//! ここでは検証のみ（id_token の署名は jws.rs）。現状の利用者は FIDO 検証。
//! DPoP / private_key_jwt も将来ここを呼べるが、今は ES256 のまま（配線しない）。

use ed25519_dalek::{Signature as EdSignature, Verifier as EdVerifier, VerifyingKey as EdKey};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

fn rsa_key(n: &[u8], e: &[u8]) -> Result<RsaPublicKey, String> {
    RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
        .map_err(|e| format!("rsa key: {e}"))
}

/// RS256 = RSASSA-PKCS1-v1.5 over SHA-256。
pub fn verify_rs256(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = rsa_key(n, e)?;
    let hashed = Sha256::digest(message);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)
        .map_err(|_| "invalid RS256 signature".to_string())
}

/// RS384 = RSASSA-PKCS1-v1.5 over SHA-384。
pub fn verify_rs384(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    use sha2::Sha384;
    let key = rsa_key(n, e)?;
    let hashed = Sha384::digest(message);
    key.verify(Pkcs1v15Sign::new::<Sha384>(), &hashed, signature)
        .map_err(|_| "invalid RS384 signature".to_string())
}

/// RS1 = RSASSA-PKCS1-v1.5 over SHA-1（Conformance の RS1 用）。
pub fn verify_rs1(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key = rsa_key(n, e)?;
    let hashed = Sha1::digest(message);
    key.verify(Pkcs1v15Sign::new::<Sha1>(), &hashed, signature)
        .map_err(|_| "invalid RS1 signature".to_string())
}

/// Ed25519（PureEdDSA, メッセージを直接署名）。
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let pk: [u8; 32] = public_key.try_into().map_err(|_| "ed25519 pubkey != 32 bytes")?;
    let key = EdKey::from_bytes(&pk).map_err(|e| format!("ed25519 key: {e}"))?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| "ed25519 sig != 64 bytes")?;
    key.verify(message, &EdSignature::from_bytes(&sig))
        .map_err(|_| "invalid Ed25519 signature".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    fn rsa_keypair() -> (RsaPrivateKey, Vec<u8>, Vec<u8>) {
        // 1024bit: テスト高速化用（本番鍵長の検証ではなくロジック検証が目的）。
        let sk = RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let pk = sk.to_public_key();
        (sk, pk.n().to_bytes_be(), pk.e().to_bytes_be())
    }

    #[test]
    fn rs256_accepts_valid_rejects_tampered() {
        let (sk, n, e) = rsa_keypair();
        let msg = b"attestation-to-be-signed";
        let sig = sk
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(msg))
            .unwrap();
        assert!(verify_rs256(&n, &e, msg, &sig).is_ok());
        assert!(verify_rs256(&n, &e, b"different message", &sig).is_err());
        let mut bad = sig.clone();
        bad[0] ^= 0xff;
        assert!(verify_rs256(&n, &e, msg, &bad).is_err());
    }

    #[test]
    fn rs384_accepts_valid_rejects_tampered() {
        use sha2::Sha384;
        let (sk, n, e) = rsa_keypair();
        let msg = b"sha384-signed";
        let sig = sk
            .sign(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(msg))
            .unwrap();
        assert!(verify_rs384(&n, &e, msg, &sig).is_ok());
        assert!(verify_rs384(&n, &e, b"different", &sig).is_err());
        // SHA-256 で署名したものは RS384 検証に通らない。
        let sig256 = sk
            .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(msg))
            .unwrap();
        assert!(verify_rs384(&n, &e, msg, &sig256).is_err());
    }

    #[test]
    fn rs1_accepts_valid_rejects_wrong_hash_alg() {
        let (sk, n, e) = rsa_keypair();
        let msg = b"sha1-signed";
        let sig = sk
            .sign(Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(msg))
            .unwrap();
        assert!(verify_rs1(&n, &e, msg, &sig).is_ok());
        // SHA-1 で署名したものは RS256 検証に通らない。
        assert!(verify_rs256(&n, &e, msg, &sig).is_err());
    }

    #[test]
    fn rsa_key_rejects_empty_modulus() {
        // n=空 → 鍵構築でエラー（パニックしない）。
        assert!(verify_rs256(&[], &[1, 0, 1], b"m", b"sig").is_err());
    }

    #[test]
    fn ed25519_accepts_valid_rejects_tampered() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let msg = b"ed25519 message";
        let sig = sk.sign(msg).to_bytes();
        assert!(verify_ed25519(&pk, msg, &sig).is_ok());
        assert!(verify_ed25519(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn ed25519_rejects_wrong_length_inputs() {
        assert!(verify_ed25519(&[0u8; 31], b"m", &[0u8; 64]).is_err()); // pubkey 短い
        assert!(verify_ed25519(&[0u8; 32], b"m", &[0u8; 63]).is_err()); // sig 短い
    }
}
