#!/usr/bin/env node
// DPoP × CIBA × RAR mandate の E2E デモ。
//   1) ES256 鍵を生成 → JWK / Thumbprint
//   2) CIBA backchannel-authentication (with authorization_details, DPoP proof)
//   3) iPhone で承認
//   4) /token を DPoP proof 付きで叩く → DPoP-bound access token
//   5) POST /payments を DPoP proof + ath 付きで叩く（一致/改ざん/再利用/別鍵）
//
//   node scripts/demo-dpop-mandate.mjs

import {
  generateKeyPairSync,
  createSign,
  createHash,
  randomUUID,
} from 'node:crypto';

const OP = 'https://oidc.sonrisa.co.jp/oidc';
const API = 'https://api.sonrisa.co.jp';
const CLIENT = 'ciba-rp';
const SECRET = 'ciba-rp-secret';
const BASIC = 'Basic ' + Buffer.from(`${CLIENT}:${SECRET}`).toString('base64');
const LOGIN_HINT = 'info@sonrisa.co.jp';

const err = (...a) => console.error(...a);
const ok = (label, body, code) =>
  console.log(`  [${label}] HTTP ${code} ${typeof body === 'string' ? body : JSON.stringify(body)}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64u = (s) =>
  Buffer.from(s).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const b64uBytes = (b) =>
  Buffer.from(b).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

function genKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }); // {kty, crv, x, y}
  return { privateKey, jwk };
}

function thumbprint(jwk) {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return b64uBytes(createHash('sha256').update(canonical).digest());
}

function makeProof({ privateKey, jwk, htm, htu, ath }) {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk };
  const payload = {
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(ath ? { ath } : {}),
  };
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  // dsaEncoding: 'ieee-p1363' で 64 byte concat (r||s) を直接得る
  const sig = createSign('SHA256').update(signingInput).sign({
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${h}.${p}.${b64uBytes(sig)}`;
}

function ath(accessToken) {
  return b64uBytes(createHash('sha256').update(accessToken).digest());
}

async function postForm(url, body, extraHeaders = {}) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...extraHeaders,
    },
    body: new URLSearchParams(body).toString(),
  });
  const text = await r.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: r.status, body: json };
}

async function postJson(url, body, headers) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: r.status, body: json };
}

async function main() {
  // 1) 鍵 (agent 用) と thumbprint
  const k = genKey();
  const jkt = thumbprint(k.jwk);
  err(`[setup] DPoP key jkt=${jkt}`);

  // 別鍵（攻撃者用シナリオで proof を作る）
  const evil = genKey();

  // 2) CIBA backchannel-authentication（authorization_details 付き）
  const ad = JSON.stringify([
    {
      type: 'payment',
      actions: ['create'],
      amount: '1500',
      currency: 'JPY',
      merchant: 'example-shop',
    },
  ]);
  err(`[ciba] backchannel-authentication...`);
  const init = await postForm(`${OP}/backchannel-authentication`, {
    login_hint: LOGIN_HINT,
    scope: 'openid profile',
    binding_message: 'DPoP+mandate: example-shop 1,500 円',
    authorization_details: ad,
  }, { authorization: BASIC });
  if (init.status !== 200) {
    err(`[ciba] backchannel failed ${init.status}: ${JSON.stringify(init.body)}`);
    process.exit(2);
  }
  const authReqId = init.body.auth_req_id;
  err(`[ciba] auth_req_id=${authReqId}. iPhone を確認して Face ID 承認してください...`);

  // 3) /token を DPoP proof 付きで poll
  const tokenUrl = `${OP}/token`;
  const deadline = Date.now() + (init.body.expires_in || 300) * 1000;
  let tok;
  let lastErr;
  while (Date.now() < deadline) {
    await sleep(2000);
    const proof = makeProof({
      privateKey: k.privateKey,
      jwk: k.jwk,
      htm: 'POST',
      htu: tokenUrl,
    });
    const t = await postForm(tokenUrl, {
      grant_type: 'urn:openid:params:grant-type:ciba',
      auth_req_id: authReqId,
    }, {
      authorization: BASIC,
      dpop: proof,
    });
    if (t.status === 200 && t.body.access_token) {
      tok = t.body;
      break;
    }
    if (t.body?.error === 'authorization_pending' || t.body?.error === 'slow_down') {
      err(`[ciba] pending...`);
      continue;
    }
    lastErr = t;
    break;
  }
  if (!tok) {
    err(`[ciba] token failed: ${JSON.stringify(lastErr || 'expired')}`);
    process.exit(3);
  }
  err(`[ciba] token_type=${tok.token_type}, expires_in=${tok.expires_in}`);
  err(`[ciba] authorization_details=${JSON.stringify(tok.authorization_details)}`);
  const accessToken = tok.access_token;

  console.log('\n=== (a) introspection で cnf.jkt を確認 ===');
  const intro = await postForm(`${OP}/introspect`, { token: accessToken }, {
    authorization: 'Basic ' + Buffer.from('oidf-basic-1:oidf-basic-secret-1').toString('base64'),
  });
  console.log('  ' + JSON.stringify(intro.body));

  // 4) POST /payments を DPoP proof + ath 付きで（一致）
  const payUrl = `${API}/payments`;
  console.log('\n=== (b) 一致 body + 正しい proof → 201 期待 ===');
  {
    const proof = makeProof({
      privateKey: k.privateKey,
      jwk: k.jwk,
      htm: 'POST',
      htu: payUrl,
      ath: ath(accessToken),
    });
    const r = await postJson(payUrl, {
      amount: 1500, currency: 'JPY', merchant: 'example-shop', memo: 'dpop+mandate',
    }, { authorization: `DPoP ${accessToken}`, dpop: proof });
    ok('b', r.body, r.status);
  }

  console.log('\n=== (c) proof 無し → 401 invalid_token 期待 ===');
  {
    const r = await postJson(payUrl, {
      amount: 1500, currency: 'JPY', merchant: 'example-shop',
    }, { authorization: `Bearer ${accessToken}` });
    ok('c', r.body, r.status);
  }

  console.log('\n=== (d) 別鍵で proof（jkt 不一致） → 401 期待 ===');
  {
    const proof = makeProof({
      privateKey: evil.privateKey,
      jwk: evil.jwk,
      htm: 'POST',
      htu: payUrl,
      ath: ath(accessToken),
    });
    const r = await postJson(payUrl, {
      amount: 1500, currency: 'JPY', merchant: 'example-shop',
    }, { authorization: `DPoP ${accessToken}`, dpop: proof });
    ok('d', r.body, r.status);
  }

  console.log('\n=== (e) 同 token + 正しい proof で再投 → 403 mandate.already_consumed 期待（single-use）===');
  {
    const proof = makeProof({
      privateKey: k.privateKey,
      jwk: k.jwk,
      htm: 'POST',
      htu: payUrl,
      ath: ath(accessToken),
    });
    const r = await postJson(payUrl, {
      amount: 1500, currency: 'JPY', merchant: 'example-shop',
    }, { authorization: `DPoP ${accessToken}`, dpop: proof });
    ok('e', r.body, r.status);
  }

  // cleanup
  console.log('\n=== 後片付け: payments を全削除（gcloud auth print-access-token 必要）===');
  const { execSync } = await import('node:child_process');
  const fb = execSync('gcloud auth print-access-token', { encoding: 'utf8' }).trim();
  const fs = `https://firestore.googleapis.com/v1/projects/fido2-8b943/databases/(default)/documents`;
  const list = await fetch(`${fs}/payments?pageSize=20`, {
    headers: { authorization: `Bearer ${fb}` },
  }).then((r) => r.json());
  for (const d of (list.documents || [])) {
    const id = d.name.split('/').pop();
    await fetch(`${fs}/payments/${id}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${fb}` },
    });
    console.log(`  deleted payments/${id}`);
  }
}

main().catch((e) => {
  err(e);
  process.exit(1);
});
