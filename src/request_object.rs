//! JAR (JWT-Secured Authorization Request, RFC 9101) の request object 検証。
//! 署名は ES256（client.jwks の登録鍵で検証）。private_key_jwt と同じ要領。
//!
//! 呼び出し側は先に client_id（URL/body）から Client を解決してから verify を呼ぶ。
//! 検証後の claims（= 認可リクエストパラメータ）を文字列マップで返す。

use crate::error::OAuthError;
use crate::model::Client;
use crate::nonce::NonceStore;
use std::collections::HashMap;

/// JWT envelope クレーム（パラメータとして扱わない）。
const ENVELOPE_CLAIMS: &[&str] = &["iss", "aud", "exp", "iat", "nbf", "jti"];

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// signed request object(JWT, ES256) を検証し、認可パラメータの文字列マップを返す。
/// jti は単回（リプレイ防止）: jti_store で claim し、有効期間(exp まで)覚える。
pub async fn verify(
    client: &Client,
    jwt: &str,
    issuer: &str,
    jti_store: &NonceStore,
) -> Result<HashMap<String, String>, OAuthError> {
    let bad = |m: &str| OAuthError::InvalidRequest(m.to_string());
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(bad("request object is not a compact JWS"));
    }
    let dec = |s: &str| crate::es256::b64url_decode(s).map_err(|_| bad("request object base64"));
    let header: serde_json::Value =
        serde_json::from_slice(&dec(parts[0])?).map_err(|_| bad("request object header"))?;
    // alg=none を含む ES256 以外は拒否（RFC 9101 §6.1 / FAPI）。
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(bad("request object alg must be ES256"));
    }
    let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("");

    // kid で client の登録鍵を選び ES256(raw r||s) 署名検証。
    let jwk = client
        .jwks
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| bad("no client key matches request object kid"))?;
    let vk = crate::es256::verifying_key_from_xy(&dec(&jwk.x)?, &dec(&jwk.y)?).map_err(|e| bad(&e))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = p256::ecdsa::Signature::from_slice(&dec(parts[2])?).map_err(|_| bad("request object sig"))?;
    use p256::ecdsa::signature::Verifier;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| bad("request object signature invalid"))?;

    let payload: serde_json::Value =
        serde_json::from_slice(&dec(parts[1])?).map_err(|_| bad("request object payload"))?;

    // iss は client_id と一致（RFC 9101 §10.2）。
    if payload.get("iss").and_then(|v| v.as_str()) != Some(client.client_id.as_str()) {
        return Err(bad("request object iss must equal client_id"));
    }
    // aud は issuer を含むこと。
    let aud_ok = match payload.get("aud") {
        Some(serde_json::Value::String(s)) => s == issuer,
        Some(serde_json::Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(issuer)),
        _ => false,
    };
    if !aud_ok {
        return Err(bad("request object aud must be the issuer"));
    }
    // FAPI: exp / nbf / iat / jti 必須。exp は 60 分以内、nbf は ±許容内。
    let now = now();
    let exp = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| bad("request object missing exp"))?;
    if exp <= now {
        return Err(bad("request object expired"));
    }
    if exp > now + 3600 {
        return Err(bad("request object exp is more than 60 minutes in the future"));
    }
    let nbf = payload
        .get("nbf")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| bad("request object missing nbf"))?;
    if nbf > now + 60 {
        return Err(bad("request object nbf is in the future"));
    }
    if nbf < now - 3600 {
        return Err(bad("request object nbf is more than 60 minutes in the past"));
    }
    if payload.get("iat").and_then(|v| v.as_i64()).is_none() {
        return Err(bad("request object missing iat"));
    }
    let jti = payload.get("jti").and_then(|v| v.as_str()).unwrap_or("");
    if jti.is_empty() {
        return Err(bad("request object missing jti"));
    }
    // jti 単回（リプレイ防止）。有効期間(exp まで)覚える。これが無いと署名済み request object を
    // exp までの窓でリプレイできる（PAR 経由なら request_uri 単回で緩和されるが、直接 JAR 経路は
    // ここでしか防げない）。jti TTL は exp 検証(<= now+3600)で上限が担保される。
    let jti_ttl = std::time::Duration::from_secs((exp - now).max(0) as u64);
    if !jti_store.claim(&format!("jar:{jti}"), jti_ttl).await {
        return Err(bad("request object jti replay"));
    }

    // クレームを認可パラメータとして取り出す（envelope は除く）。
    // 文字列はそのまま。authorization_details(RAR=JSON配列) や claims(JSONオブジェクト) 等の
    // 非文字列は JSON 文字列へシリアライズして保持する。as_str だけだと黙って欠落し、FAPI
    // クライアントの mandate(authorization_details) が署名経路で失われていた。非署名(フォーム)
    // 経路でもこれらは JSON 文字列で渡るため、ダウンストリームの扱いと整合する。
    let obj = payload.as_object().ok_or_else(|| bad("request object payload not an object"))?;
    let mut params = HashMap::new();
    for (k, v) in obj {
        if ENVELOPE_CLAIMS.contains(&k.as_str()) {
            continue;
        }
        match v {
            serde_json::Value::String(s) => {
                params.insert(k.clone(), s.clone());
            }
            serde_json::Value::Null => {}
            other => {
                if let Ok(s) = serde_json::to_string(other) {
                    params.insert(k.clone(), s);
                }
            }
        }
    }
    // client_id は必ず含める（claim に無くても解決済みの値で補完）。
    params
        .entry("client_id".to_string())
        .or_insert_with(|| client.client_id.clone());
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es256::b64url_encode as b64e;
    use crate::model::JwkPub;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use serde_json::{json, Value};

    const ISS: &str = "https://op.example/oidc";

    fn client_with_key(key: &SigningKey) -> Client {
        let pt = key.verifying_key().to_encoded_point(false);
        Client {
            client_id: "cli-1".into(),
            redirect_uris: vec!["https://rp/cb".into()],
            token_endpoint_auth_method: "private_key_jwt".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into()],
            post_logout_redirect_uris: vec![],
            dpop_bound: true,
            jwks: vec![JwkPub {
                kid: "k1".into(),
                x: b64e(pt.x().unwrap()),
                y: b64e(pt.y().unwrap()),
            }],
            require_par: true,
            require_pkce: true,
            id_token_signed_response_alg: None,
        }
    }

    fn sign(key: &SigningKey, header: &Value, payload: &Value) -> String {
        let si = format!("{}.{}", b64e(header.to_string()), b64e(payload.to_string()));
        let sig: Signature = key.sign(si.as_bytes());
        format!("{si}.{}", b64e(sig.to_bytes()))
    }

    fn now() -> i64 {
        super::now()
    }

    /// テスト用: 毎回新しい memory jti ストアで verify を同期実行するラッパ。
    fn verify_t(c: &Client, jwt: &str, issuer: &str) -> Result<HashMap<String, String>, OAuthError> {
        let store = NonceStore::memory();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(verify(c, jwt, issuer, &store))
    }

    fn good_payload() -> Value {
        json!({
            "iss": "cli-1", "aud": ISS, "exp": now() + 300, "nbf": now() - 5,
            "iat": now() - 5, "jti": "jti-1",
            "response_type": "code", "client_id": "cli-1",
            "redirect_uri": "https://rp/cb", "scope": "openid", "state": "s1"
        })
    }
    fn good_header() -> Value {
        json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": "k1"})
    }

    #[test]
    fn valid_request_object_returns_params() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let jwt = sign(&key, &good_header(), &good_payload());
        let p = verify_t(&c, &jwt, ISS).unwrap();
        assert_eq!(p.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(p.get("scope").map(String::as_str), Some("openid"));
        assert_eq!(p.get("state").map(String::as_str), Some("s1"));
        // envelope claims は含まれない。
        assert!(!p.contains_key("iss") && !p.contains_key("aud") && !p.contains_key("exp"));
    }

    #[test]
    fn preserves_non_string_claims_as_json() {
        // authorization_details(RAR=配列) / claims(オブジェクト) / max_age(数値) が
        // 署名経路でも欠落せず、JSON 文字列として保持されることを確認する（#5 回帰）。
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl["authorization_details"] = json!([{"type": "payment_initiation", "amount": 100}]);
        pl["claims"] = json!({"userinfo": {"email": null}});
        pl["max_age"] = json!(300);
        let p = verify_t(&c, &sign(&key, &good_header(), &pl), ISS).unwrap();
        // authorization_details は JSON 文字列として保持され、配列へパースし直せる。
        let ad: Value =
            serde_json::from_str(p.get("authorization_details").expect("authz_details preserved")).unwrap();
        assert_eq!(ad[0]["type"], "payment_initiation");
        assert_eq!(ad[0]["amount"], 100);
        // claims(オブジェクト)も保持される。
        let claims: Value = serde_json::from_str(p.get("claims").expect("claims preserved")).unwrap();
        assert!(claims["userinfo"].is_object());
        // 数値(max_age)も保持される。
        assert_eq!(p.get("max_age").map(String::as_str), Some("300"));
        // 文字列クレームは従来どおり。
        assert_eq!(p.get("scope").map(String::as_str), Some("openid"));
    }

    #[tokio::test]
    async fn rejects_jti_replay() {
        // 同一 jti の request object を同じストアで2回検証 → 2回目はリプレイ拒否（#7 回帰）。
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let store = NonceStore::memory();
        let jwt = sign(&key, &good_header(), &good_payload());
        assert!(verify(&c, &jwt, ISS, &store).await.is_ok());
        let jwt2 = sign(&key, &good_header(), &good_payload()); // 同じ jti "jti-1"
        assert!(verify(&c, &jwt2, ISS, &store).await.is_err());
    }

    #[test]
    fn rejects_alg_none() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut h = good_header();
        h["alg"] = json!("none");
        let jwt = sign(&key, &h, &good_payload());
        assert!(verify_t(&c, &jwt, ISS).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let jwt = sign(&key, &good_header(), &good_payload());
        let parts: Vec<&str> = jwt.split('.').collect();
        let forged = b64e(json!({"iss":"cli-1","aud":ISS,"exp":now()+300,"scope":"openid admin"}).to_string());
        let tampered = format!("{}.{}.{}", parts[0], forged, parts[2]);
        assert!(verify_t(&c, &tampered, ISS).is_err());
    }

    #[test]
    fn rejects_iss_mismatch() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl["iss"] = json!("other-client");
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
    }

    #[test]
    fn rejects_aud_mismatch() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl["aud"] = json!("https://evil.example");
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
    }

    #[test]
    fn rejects_expired() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl["exp"] = json!(now() - 10);
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
    }

    #[test]
    fn rejects_exp_more_than_60min_future() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl["exp"] = json!(now() + 3700); // > 60分
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
    }

    #[test]
    fn rejects_missing_or_future_or_old_nbf() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        // 欠落
        let mut pl = good_payload();
        pl.as_object_mut().unwrap().remove("nbf");
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
        // 未来
        let mut pl = good_payload();
        pl["nbf"] = json!(now() + 600);
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
        // 60分超過去
        let mut pl = good_payload();
        pl["nbf"] = json!(now() - 4000);
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
    }

    #[test]
    fn rejects_missing_iat_and_jti() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl.as_object_mut().unwrap().remove("iat");
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
        let mut pl = good_payload();
        pl.as_object_mut().unwrap().remove("jti");
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_err());
    }

    #[test]
    fn accepts_aud_as_array_containing_issuer() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut pl = good_payload();
        pl["aud"] = json!(["https://other", ISS]);
        assert!(verify_t(&c, &sign(&key, &good_header(), &pl), ISS).is_ok());
    }

    #[test]
    fn rejects_unknown_kid() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        let mut h = good_header();
        h["kid"] = json!("unknown");
        assert!(verify_t(&c, &sign(&key, &h, &good_payload()), ISS).is_err());
    }

    #[test]
    fn rejects_signature_from_other_key() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let other = SigningKey::random(&mut rand_core::OsRng);
        let c = client_with_key(&key);
        // 署名は other 鍵、kid は登録鍵 k1 → 検証失敗。
        assert!(verify_t(&c, &sign(&other, &good_header(), &good_payload()), ISS).is_err());
    }
}
