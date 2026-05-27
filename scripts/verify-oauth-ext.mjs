#!/usr/bin/env node
// 本番デプロイ済みの OAuth 拡張 (RFC 7662/7009/8707/9470) を end-to-end で検証する。
// confidential クライアント oidf-basic-1 を使い、パスワードログイン(a/a)で認可フローを
// 駆動 → token → introspect/revoke を確認する（passkey も DPoP も使わない）。
//
//   node scripts/verify-oauth-ext.mjs
//
// 検証項目:
//   ② Resource Indicators: introspection に aud=<resource> が出る
//   ③ Step-up:             introspection に acr / auth_time が出る
//   ① Revocation:          revoke 後に access が active=false / refresh で再発行不可

const OP = process.env.OP_BASE || 'https://oidc.sonrisa.co.jp/oidc';
const CLIENT = 'oidf-basic-1';
const SECRET = 'oidf-basic-secret-1';
const REDIRECT = 'https://www.certification.openid.net/test/a/rustop-basic/callback';
const RESOURCE = 'https://api.example.com';
const ACR = 'urn:mace:incommon:iap:bronze';
const BASIC = 'Basic ' + Buffer.from(`${CLIENT}:${SECRET}`).toString('base64');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log(`  PASS ${m}`)) : (fail++, console.log(`  FAIL ${m}`)); };

const form = (o) => new URLSearchParams(o).toString();
const cookieOf = (res) => {
  const arr = res.headers.getSetCookie?.() || [];
  const sid = arr.map((c) => c.split(';')[0]).find((c) => c.startsWith('sid='));
  return sid || '';
};

async function main() {
  console.log(`OP = ${OP}\n`);

  // 1) authorize（resource + acr_values + max_age）→ login interaction へ
  const authUrl = `${OP}/authorize?` + form({
    response_type: 'code',
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    scope: 'openid profile offline_access',
    state: 'verify-state',
    resource: RESOURCE,
    acr_values: ACR,
    max_age: '300',
  });
  let r = await fetch(authUrl, { redirect: 'manual' });
  const loc1 = r.headers.get('location') || '';
  const m = loc1.match(/\/interaction\/([^/?]+)/);
  ok(!!m, `authorize → interaction へリダイレクト (${r.status})`);
  if (!m) throw new Error(`unexpected authorize response: ${r.status} ${loc1}`);
  const uid = m[1];

  // 2) パスワードログイン (a/a) → sid cookie + resume へ
  r = await fetch(`${OP}/interaction/${uid}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ username: 'a', password: 'a' }),
    redirect: 'manual',
  });
  const sid = cookieOf(r);
  const resume = r.headers.get('location') || '';
  ok(!!sid && resume.includes('/authorize/resume'), `login → sid 発行 + resume へ (${r.status})`);

  // 3) resume → redirect_uri?code=... を捕捉（実際には follow しない）
  r = await fetch(`${OP}/authorize/resume?uid=${uid}`, {
    headers: { cookie: sid },
    redirect: 'manual',
  });
  const loc3 = r.headers.get('location') || '';
  const code = new URL(loc3).searchParams.get('code');
  ok(!!code, `resume → code 発行 (${r.status})`);

  // 4) token 交換（client_secret_basic, Bearer）
  r = await fetch(`${OP}/token`, {
    method: 'POST',
    headers: { authorization: BASIC, 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT }),
  });
  const tok = await r.json();
  ok(r.status === 200 && tok.access_token, `token 発行 (token_type=${tok.token_type})`);
  ok(!!tok.refresh_token, `refresh_token 発行 (offline_access)`);
  const at = tok.access_token, rt = tok.refresh_token;

  // 5) introspect → ②aud ③acr/auth_time
  const introspect = async (token) => {
    const res = await fetch(`${OP}/introspect`, {
      method: 'POST',
      headers: { authorization: BASIC, 'content-type': 'application/x-www-form-urlencoded' },
      body: form({ token }),
    });
    return res.json();
  };
  let i = await introspect(at);
  console.log('  introspection:', JSON.stringify(i));
  ok(i.active === true, 'introspect: active=true');
  ok(i.aud === RESOURCE, `② Resource Indicators: aud=${i.aud}`);
  ok(i.acr === ACR, `③ Step-up: acr=${i.acr}`);
  ok(typeof i.auth_time === 'number', `③ Step-up: auth_time=${i.auth_time}`);
  ok(i.sub && i.scope, `introspect: sub/scope あり (sub=${i.sub})`);

  // 6) ① access token を revoke → active=false
  r = await fetch(`${OP}/revoke`, {
    method: 'POST',
    headers: { authorization: BASIC, 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ token: at }),
  });
  ok(r.status === 200, `① revoke(access) → 200`);
  i = await introspect(at);
  ok(i.active === false, `① revoke 後: access が active=false`);

  // 7) ① refresh token を revoke → 再発行(refresh grant)が失敗する
  r = await fetch(`${OP}/revoke`, {
    method: 'POST',
    headers: { authorization: BASIC, 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ token: rt }),
  });
  ok(r.status === 200, `① revoke(refresh) → 200`);
  r = await fetch(`${OP}/token`, {
    method: 'POST',
    headers: { authorization: BASIC, 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'refresh_token', refresh_token: rt }),
  });
  ok(r.status !== 200, `① revoke 後: refresh による再発行が拒否 (${r.status})`);

  // 8) introspect は confidential 必須（無認証は弾く）
  r = await fetch(`${OP}/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ token: 'x' }),
  });
  ok(r.status === 401, `introspect 無認証 → 401`);

  console.log(`\n結果: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error('ERROR:', e); process.exit(1); });
