#!/usr/bin/env node
// CIBA (Pattern B) で access token を取得する CLI ヘルパ。
// fido2demo（指定 login_hint の端末）に承認プッシュが届く → Face ID 承認 → token。
//
//   node scripts/get-token-ciba.mjs [login_hint] [binding_message] [scope]
//   標準出力: access_token のみ（capture 用）／進捗は標準エラーに出す
//
// 例:
//   TOKEN=$(node scripts/get-token-ciba.mjs info@sonrisa.co.jp "projects API テスト用")
//   curl -H "Authorization: Bearer $TOKEN" https://api.sonrisa.co.jp/projects

const OP = process.env.OP_BASE || 'https://oidc.sonrisa.co.jp/oidc';
const CLIENT = process.env.CIBA_CLIENT_ID || 'ciba-rp';
const SECRET = process.env.CIBA_CLIENT_SECRET || 'ciba-rp-secret';
const BASIC = 'Basic ' + Buffer.from(`${CLIENT}:${SECRET}`).toString('base64');

const loginHint = process.argv[2] || 'info@sonrisa.co.jp';
const binding =
  process.argv[3] || 'API テスト用に projects コレクションへのアクセスを許可してください';
const scope = process.argv[4] || 'openid profile';

const err = (...a) => console.error(...a);
const form = (o) => new URLSearchParams(o).toString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  err(`[CIBA] OP=${OP}`);
  err(`[CIBA] login_hint=${loginHint}`);
  err(`[CIBA] binding="${binding}"`);
  err(`[CIBA] scope="${scope}"`);

  // 1) backchannel-authentication（client_secret_basic）
  const params = { login_hint: loginHint, scope, binding_message: binding };
  // RFC 9396: AUTH_DETAILS 環境変数（JSON 配列文字列）があれば mandate として送る
  if (process.env.AUTH_DETAILS) {
    params.authorization_details = process.env.AUTH_DETAILS;
    err(`[CIBA] authorization_details=${process.env.AUTH_DETAILS}`);
  }
  let r = await fetch(`${OP}/backchannel-authentication`, {
    method: 'POST',
    headers: {
      authorization: BASIC,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: form(params),
  });
  if (r.status !== 200) {
    err(`[CIBA] backchannel-authentication failed ${r.status}: ${await r.text()}`);
    process.exit(2);
  }
  const init = await r.json();
  const authReqId = init.auth_req_id;
  const expiresIn = init.expires_in ?? 300;
  const interval = (init.interval ?? 2) * 1000;
  err(`[CIBA] auth_req_id=${authReqId} expires_in=${expiresIn}s`);
  err(`[CIBA] fido2demo を確認して Face ID で承認してください（拒否で終了）...`);

  // 2) /token を poll
  const deadline = Date.now() + expiresIn * 1000;
  while (Date.now() < deadline) {
    await sleep(interval);
    const t = await fetch(`${OP}/token`, {
      method: 'POST',
      headers: {
        authorization: BASIC,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: form({
        grant_type: 'urn:openid:params:grant-type:ciba',
        auth_req_id: authReqId,
      }),
    });
    const body = await t.json().catch(() => ({}));
    if (t.status === 200 && body.access_token) {
      err('[CIBA] 承認完了。access_token を出力します。');
      process.stdout.write(body.access_token + '\n');
      return;
    }
    if (body.error === 'authorization_pending' || body.error === 'slow_down') {
      err(`[CIBA] pending… (${body.error})`);
      continue;
    }
    if (body.error === 'access_denied') {
      err('[CIBA] ユーザーが拒否しました。');
      process.exit(3);
    }
    err(`[CIBA] /token unexpected ${t.status}: ${JSON.stringify(body)}`);
    process.exit(4);
  }
  err('[CIBA] タイムアウトしました。');
  process.exit(1);
}

main().catch((e) => {
  err('ERROR:', e);
  process.exit(1);
});
