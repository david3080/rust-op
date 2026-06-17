//! 自前 COSE 鍵パーサ(`parse_cose_key`)を、独立実装 `coset`（ピュア Rust の RFC 8152
//! 実装, openssl/ring 非依存）と突き合わせる**差分テスト**。
//!
//! 方向: coset が COSE_Key をエンコード → rust-op がパース。独立ライブラリが生成した
//! 構造を rust-op が同一の (x,y) として解釈できることを確認する。これは fuzz（panic 安全性）
//! では拾えない「ラベル取り違え・座標抽出ミス」のような**意味論バグ**を捕える。
//!
//! parse_cose_key は登録時に検証鍵そのものを取り出す最重要パーサ（ここが誤れば
//! 別人の鍵で署名検証が通る等の致命傷になりうる）なので、独立実装と一致を取る価値が高い。

use crate::fido::verify::{self, CredKey};
use coset::{iana, CborSerializable, CoseKeyBuilder};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand_core::OsRng;

/// coset がエンコードした EC2/ES256/P-256 の COSE_Key を rust-op がパースし、
/// 取り出した (x,y) が元の鍵と完全一致することを多数のランダム鍵で確認する。
#[test]
fn parse_cose_key_agrees_with_coset_oracle_es256() {
    for _ in 0..500 {
        let sk = SecretKey::random(&mut OsRng);
        let ep = sk.public_key().to_encoded_point(false);
        let x = ep.x().expect("ec x").to_vec(); // P-256 は固定 32byte
        let y = ep.y().expect("ec y").to_vec();

        // 独立実装で COSE_Key を組み立てる（map のラベル付けは coset の責務）。
        let bytes = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone())
            .algorithm(iana::Algorithm::ES256)
            .build()
            .to_vec()
            .expect("coset encode COSE_Key");

        // rust-op の手書きパーサが、独立実装の出力を同じ (x,y) として解釈すること。
        match verify::parse_cose_key(&bytes) {
            Ok((CredKey::Es256 { x: rx, y: ry }, _)) => {
                assert_eq!(rx, x, "x が coset オラクルと不一致（ラベル -2 の取り違え等）");
                assert_eq!(ry, y, "y が coset オラクルと不一致（ラベル -3 の取り違え等）");
            }
            Ok((other, _)) => panic!("ES256 を期待したが alg {}", other.cose_alg()),
            Err(e) => panic!("rust-op が coset 生成の正当な COSE_Key を拒否: {e}"),
        }
    }
}

/// coset がエンコードした OKP/EdDSA/Ed25519 の COSE_Key を rust-op が Ed25519 として
/// 解釈し、公開鍵バイトが一致すること（multi-alg 経路の差分）。
#[test]
fn parse_cose_key_agrees_with_coset_oracle_ed25519() {
    use ed25519_dalek::SigningKey;
    use rand_core::RngCore;
    for _ in 0..200 {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes().to_vec(); // 32byte

        let bytes = CoseKeyBuilder::new_okp_key()
            .param(
                iana::OkpKeyParameter::Crv as i64,
                ciborium::value::Value::from(iana::EllipticCurve::Ed25519 as i64),
            )
            .param(
                iana::OkpKeyParameter::X as i64,
                ciborium::value::Value::Bytes(pk.clone()),
            )
            .algorithm(iana::Algorithm::EdDSA)
            .build()
            .to_vec()
            .expect("coset encode OKP");

        match verify::parse_cose_key(&bytes) {
            Ok((CredKey::Ed25519 { pk: rpk }, _)) => {
                assert_eq!(rpk, pk, "Ed25519 公開鍵が coset オラクルと不一致");
            }
            Ok((other, _)) => panic!("Ed25519 を期待したが alg {}", other.cose_alg()),
            Err(e) => panic!("rust-op が coset 生成の OKP 鍵を拒否: {e}"),
        }
    }
}
