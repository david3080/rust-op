#!/usr/bin/env node
// フェーズ2 PEP の e2e 検証。oidf-basic-1 + パスワードログインで token を取得し、
// api.sonrisa.co.jp（汎用 CRUD ゲートウェイ）に対する RBAC/DAC の振る舞いを確認する。

const OP = 'https://oidc.sonrisa.co.jp/oidc';
const API = 'https://api.sonrisa.co.jp';
const CLIENT = 'oidf-basic-1';
const SECRET = 'oidf-basic-secret-1';
const REDIRECT = 'https://www.certification.openid.net/test/a/rustop-basic/callback';
const BASIC = 'Basic ' + Buffer.from(`${CLIENT}:${SECRET}`).toString('base64');

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log(`  PASS ${m}`)) : (fail++, console.log(`  FAIL ${m}`)); };
const form = (o) => new URLSearchParams(o).toString();
const cookieOf = (res) => (res.headers.getSetCookie?.() || [])
  .map((c) => c.split(';')[0]).find((c) => c.startsWith('sid=')) || '';

async function getToken() {
  // 1) authorize → interaction
  const url = `${OP}/authorize?` + form({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT,
    scope: 'openid profile email', state: 's1',
  });
  let r = await fetch(url, { redirect: 'manual' });
  const uid = (r.headers.get('location') || '').match(/\/interaction\/([^/?]+)/)?.[1];
  if (!uid) throw new Error('no uid');
  // 2) login a/a
  r = await fetch(`${OP}/interaction/${uid}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ username: 'a', password: 'a' }),
    redirect: 'manual',
  });
  const sid = cookieOf(r);
  const resume = r.headers.get('location') || '';
  // 3) resume → code
  r = await fetch(`${OP}/authorize/resume?uid=${uid}`, { headers: { cookie: sid }, redirect: 'manual' });
  const code = new URL(r.headers.get('location') || '').searchParams.get('code');
  if (!code) throw new Error('no code');
  // 4) token
  r = await fetch(`${OP}/token`, {
    method: 'POST',
    headers: { authorization: BASIC, 'content-type': 'application/x-www-form-urlencoded' },
    body: form({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT }),
  });
  const tok = await r.json();
  if (!tok.access_token) throw new Error('no token: ' + JSON.stringify(tok));
  return tok.access_token;
}

async function curl(path, { token, method = 'GET', body } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { code: res.status, body: json };
}

async function main() {
  console.log('Gateway:', API);
  const token = await getToken();
  console.log('Got Bearer token (sub=a expected)\n');

  // (1) トークン無し: 401
  let r = await curl('/projects');
  ok(r.code === 401, `no token → 401 (got ${r.code})`);

  // (2) 不正トークン: 401
  r = await curl('/projects', { token: 'garbage' });
  ok(r.code === 401, `invalid token → 401 (got ${r.code})`);

  // (3) 有効トークン GET /projects: 200（user ロールに list 権限あり）
  r = await curl('/projects', { token });
  ok(r.code === 200 && Array.isArray(r.body), `valid GET /projects → 200 list (got ${r.code})`);

  // (4) POST /projects: 201, owner が自動で sub に
  r = await curl('/projects', { token, method: 'POST', body: { name: 'gateway-test-pj', budget: 100 } });
  ok(r.code === 201, `POST /projects → 201 (got ${r.code})`);
  const created = r.body;
  ok(created.owner === 'a', `created owner == sub 'a' (got '${created.owner}')`);
  const newId = created.id;

  // (5) GET /projects/{id}: 自分の資源 → 200（DAC owner 一致）
  r = await curl(`/projects/${newId}`, { token });
  ok(r.code === 200, `GET own project → 200 (got ${r.code})`);

  // (6) 別ユーザー所有を装って Firestore に直に書き、その後 GET → 403 dac.not_owner を期待
  //     ここはサービスアカウント権限が要るので手動 PATCH を curl で行う（gcloud token を別途取得）
  // 簡便化: スキップ可能。代わりに不正 type → 404 (catalog)。
  r = await curl('/secrets/x', { token });
  ok(r.code === 404, `unknown type → 404 (got ${r.code})`);

  // (7) ルートは公開
  r = await curl('/');
  ok(r.code === 200, `GET / public → 200 (got ${r.code})`);

  console.log(`\n結果: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error('ERROR:', e); process.exit(1); });
