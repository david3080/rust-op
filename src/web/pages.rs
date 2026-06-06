use super::*;

/* ===== RP デモ（ブラウザ完結の authorization code + PKCE） ===== */

pub(super) async fn demo_start(State(p): State<Arc<Provider>>) -> Html<String> {
    let page = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>fido2demo</title>
<style>:root{--indigo:#3f51b5;--indigo-d:#303f9f}
body{font-family:Roboto,-apple-system,'Helvetica Neue',sans-serif;max-width:360px;margin:0 auto;padding:56px 24px;color:#1a1a1a;text-align:center}
.fp{width:72px;height:72px;color:var(--indigo)}
h1{font-size:1.3rem;font-weight:500;margin:18px 0 28px}
.filled{width:100%;padding:14px;font-size:16px;font-weight:500;background:var(--indigo);color:#fff;border:0;border-radius:24px;cursor:pointer}
.filled:active{background:var(--indigo-d)}
.hint{color:#9a9a9a;font-size:13px;margin-top:16px}</style></head><body>
<svg class="fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
<path d="M5.5 10a6.5 6.5 0 0 1 13 0v4a8 8 0 0 1-1 3.8"/><path d="M8 11a4 4 0 0 1 8 0v3a6 6 0 0 0 .8 3"/>
<path d="M12 11v4a7 7 0 0 0 1.4 4.3"/><path d="M12 19v.01"/></svg>
<h1>Passkey でサインイン</h1>
<button class="filled" onclick="start()">サインイン</button>
<script>
const ISSUER="__ISSUER__";
function b64url(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function start(){
  const v=b64url(crypto.getRandomValues(new Uint8Array(32)));
  sessionStorage.setItem('pkce_verifier',v);
  const dig=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v));
  const u=new URL(ISSUER+'/authorize');
  u.searchParams.set('client_id','demo-rp');
  u.searchParams.set('response_type','code');
  u.searchParams.set('scope','openid profile email offline_access');
  u.searchParams.set('redirect_uri',ISSUER+'/callback');
  u.searchParams.set('state',b64url(crypto.getRandomValues(new Uint8Array(16))));
  u.searchParams.set('nonce',b64url(crypto.getRandomValues(new Uint8Array(16))));
  u.searchParams.set('code_challenge',b64url(dig));
  u.searchParams.set('code_challenge_method','S256');
  location.href=u.toString();
}
</script></body></html>"##;
    Html(page.replace("__ISSUER__", &p.issuer))
}

pub(super) async fn demo_callback(State(p): State<Arc<Provider>>) -> Html<String> {
    let page = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>callback</title>
<style>:root{--indigo:#3f51b5}
body{font-family:Roboto,-apple-system,'Helvetica Neue',sans-serif;max-width:420px;margin:0 auto;padding:32px 20px;color:#1a1a1a}
h1{font-size:1.5rem;font-weight:500;margin:0}
.email{color:#00000088;margin:2px 0 20px}
.card{border:1px solid #00000022;border-radius:10px;padding:12px 14px;margin:10px 0}
.lbl{font-size:.8rem;color:var(--indigo);font-weight:600;margin-bottom:4px}
.val{font-size:1.05rem}.unset{color:#aaa}
.center{text-align:center;color:#888;padding:40px 0}
details{margin-top:24px;color:#888;font-size:12px}
pre{background:#f4f4f4;padding:10px;border-radius:6px;overflow:auto}
.logout{width:100%;margin-top:20px;padding:12px;font-size:16px;font-weight:500;background:#fff;color:#c5221f;border:1.5px solid #c5221f;border-radius:24px;cursor:pointer}</style></head><body>
<div id="cibaBox"></div>
<div id="out"><div class="center">サインイン処理中…</div></div>
<script>
const ISSUER="__ISSUER__";
const GENDER={male:'男性',female:'女性',other:'その他'};
function esc(s){return String(s).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
function field(label,val){return '<div class="card"><div class="lbl">'+label+'</div><div class="val">'+(val?esc(val):'<span class="unset">未設定</span>')+'</div></div>';}
let idTokenHint=null;
let lastUi=null,lastProf=null,lastTok=null;
function pf(){return (lastProf&&lastProf.profile)||{};}
// 編集 6 項目は /oidc/profile（保存済みのみ）から、email は userinfo から表示する。
function renderProfile(ui,prof,tok){
  idTokenHint=tok.id_token||null;lastUi=ui;lastProf=prof;lastTok=tok;
  const p=(prof&&prof.profile)||{};
  document.getElementById('out').innerHTML=
    '<h1>プロフィール</h1><div class="email">'+esc(ui.email||'')+'</div>'
    +field('氏名',p.name)+field('ニックネーム',p.nickname)
    +field('性別',GENDER[p.gender]||p.gender)+field('誕生日',p.birthdate)
    +field('タイムゾーン',p.zoneinfo)+field('ロケール',p.locale)
    +'<button class="logout" style="color:var(--indigo);border-color:var(--indigo)" onclick="editProfile()">編集</button>'
    +'<button class="logout" onclick="logout()">ログアウト</button>'
    +'<details><summary>トークン情報 (デバッグ)</summary><pre>'+esc(JSON.stringify({token_type:tok.token_type,scope:tok.scope,userinfo:ui,profile:p},null,2))+'</pre></details>';
}
function inputRow(label,name,val){return '<div class="card"><div class="lbl">'+label+'</div><input id="f_'+name+'" value="'+esc(val||'')+'" style="width:100%;font-size:1.05rem;border:none;outline:none"></div>';}
function editProfile(){
  const p=pf();
  document.getElementById('out').innerHTML=
    '<h1>プロフィール編集</h1><div class="email">'+esc((lastUi&&lastUi.email)||'')+'</div>'
    +inputRow('氏名','name',p.name)+inputRow('ニックネーム','nickname',p.nickname)
    +inputRow('性別 (male/female/other)','gender',p.gender)+inputRow('誕生日 (YYYY-MM-DD)','birthdate',p.birthdate)
    +inputRow('タイムゾーン','zoneinfo',p.zoneinfo)+inputRow('ロケール','locale',p.locale)
    +'<button class="logout" style="color:#fff;background:var(--indigo);border-color:var(--indigo)" onclick="saveProfile()">保存</button>'
    +'<button class="logout" onclick="renderProfile(lastUi,lastProf,lastTok)">キャンセル</button>';
}
const EDITABLE=['name','nickname','gender','birthdate','zoneinfo','locale'];
async function fetchProfile(){
  const t=getTokens();if(!t)return {profile:{}};
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('GET',ISSUER+'/me/profile',ath);
  const r=await fetch(ISSUER+'/me/profile',{headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  if(!r.ok)return {profile:{}};
  return await r.json();
}
async function saveProfile(){
  const t=getTokens();if(!t){fail('セッションが切れました');return;}
  const body={};EDITABLE.forEach(k=>{body[k]=document.getElementById('f_'+k).value;});
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('PUT',ISSUER+'/me/profile',ath);
  const r=await fetch(ISSUER+'/me/profile',{method:'PUT',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof,'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){fail('保存に失敗しました ('+r.status+')');return;}
  // PUT は更新後 profile を返すのでそれで再描画。
  const prof=await r.json();
  renderProfile(lastUi,prof,lastTok);
}
// RP-Initiated Logout: OP セッションを破棄して post_logout_redirect_uri(=/oidc/)へ。
function logout(){
  sessionStorage.removeItem('profile');
  sessionStorage.removeItem('tokens');
  try{indexedDB.deleteDatabase('dpop-keystore');}catch(_){}
  const u=new URL(ISSUER+'/end-session');
  u.searchParams.set('client_id','demo-rp');
  u.searchParams.set('post_logout_redirect_uri',ISSUER+'/');
  if(idTokenHint)u.searchParams.set('id_token_hint',idTokenHint);
  location.href=u.toString();
}
function fail(msg){document.getElementById('out').innerHTML='<div class="center">'+esc(msg)+'</div>';}
function b64u(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function jb64(o){return b64u(new TextEncoder().encode(JSON.stringify(o)));}
function b64ToBuf(b64){const s=atob(b64.replace(/-/g,'+').replace(/_/g,'/'));const a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a.buffer;}
// CIBA 承認依頼をプロフィール画面に通知表示し、その場で passkey 承認する（access token + DPoP）。
let cibaBusy=false;
async function fetchCibaPending(){
  const t=getTokens();if(!t)return [];
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('GET',ISSUER+'/ciba/pending',ath);
  const r=await fetch(ISSUER+'/ciba/pending',{headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  if(!r.ok)return [];
  return await r.json();
}
function renderCiba(items){
  const box=document.getElementById('cibaBox');
  if(!items||!items.length){box.innerHTML='';return;}
  box.innerHTML=items.map(it=>'<div class="card" style="border-color:var(--indigo)"><div class="lbl">ログイン承認の依頼</div><div class="val">'+esc(it.binding_message||'(no message)')+'</div><div style="color:#888;font-size:12px;margin-top:4px">from '+esc(it.client_id)+' / scope: '+esc(it.scope)+'</div><button class="logout" style="margin-top:10px;color:#fff;background:var(--indigo);border-color:var(--indigo)" onclick="approveCiba(\''+it.auth_req_id+'\')">承認 (passkey)</button><button class="logout" onclick="rejectCiba(\''+it.auth_req_id+'\')">拒否</button></div>').join('');
}
async function approveCiba(id){
  const t=getTokens();if(!t)return;cibaBusy=true;
  try{
    let ath=await sha256u(t.access_token);
    let proof=await dpopProof('POST',ISSUER+'/ciba/'+id+'/passkey-options',ath);
    const r=await fetch(ISSUER+'/ciba/'+id+'/passkey-options',{method:'POST',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof,'Content-Type':'application/json'},body:'{}'});
    if(!r.ok){alert(await r.text());cibaBusy=false;return;}
    const o=await r.json();
    const cred=await navigator.credentials.get({publicKey:{challenge:b64ToBuf(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:'required',allowCredentials:(o.allowCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id),transports:c.transports}))}});
    const body={id:cred.id,response:{clientDataJSON:b64u(cred.response.clientDataJSON),authenticatorData:b64u(cred.response.authenticatorData),signature:b64u(cred.response.signature)}};
    ath=await sha256u(t.access_token);
    proof=await dpopProof('POST',ISSUER+'/ciba/'+id+'/approve',ath);
    const v=await fetch(ISSUER+'/ciba/'+id+'/approve',{method:'POST',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof,'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!v.ok){alert(await v.text());}
  }catch(e){alert(e.message);}
  cibaBusy=false;pollCiba();
}
async function rejectCiba(id){
  const t=getTokens();if(!t)return;cibaBusy=true;
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('POST',ISSUER+'/ciba/'+id+'/reject',ath);
  await fetch(ISSUER+'/ciba/'+id+'/reject',{method:'POST',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  cibaBusy=false;pollCiba();
}
async function pollCiba(){ if(cibaBusy)return; try{renderCiba(await fetchCibaPending());}catch(e){} }
// DPoP 鍵は IndexedDB に非抽出のまま永続化（リロード/再訪でも同じ鍵＝同じ jkt）。
// これにより保存した access_token を継続利用できる（TS の dpop-keystore 相当）。
function idb(){return new Promise((res,rej)=>{const r=indexedDB.open('dpop-keystore',1);r.onupgradeneeded=()=>r.result.createObjectStore('keys');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}
let dpopKeyP=null;
async function getKey(){
  if(dpopKeyP)return dpopKeyP;
  dpopKeyP=(async()=>{
    const db=await idb();
    const existing=await new Promise(res=>{const t=db.transaction('keys','readonly').objectStore('keys').get('dpop');t.onsuccess=()=>res(t.result);t.onerror=()=>res(null);});
    if(existing)return existing;
    const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']); // 非抽出
    await new Promise((res,rej)=>{const tx=db.transaction('keys','readwrite');tx.objectStore('keys').put(kp,'dpop');tx.oncomplete=()=>res();tx.onerror=()=>rej(tx.error);});
    return kp;
  })();
  return dpopKeyP;
}
async function dpopProof(htm,htu,ath){
  const k=await getKey();
  const jwk=await crypto.subtle.exportKey('jwk',k.publicKey); // 公開鍵は非抽出でも export 可
  const header={typ:'dpop+jwt',alg:'ES256',jwk:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y}};
  const payload={jti:b64u(crypto.getRandomValues(new Uint8Array(16))),htm,htu,iat:Math.floor(Date.now()/1000)};
  if(ath)payload.ath=ath;
  const si=jb64(header)+'.'+jb64(payload);
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.privateKey,new TextEncoder().encode(si));
  return si+'.'+b64u(sig);
}
async function sha256u(s){return b64u(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));}
function saveTokens(t){sessionStorage.setItem('tokens',JSON.stringify({access_token:t.access_token,refresh_token:t.refresh_token,id_token:t.id_token,token_type:t.token_type,scope:t.scope}));}
function getTokens(){const s=sessionStorage.getItem('tokens');return s?JSON.parse(s):null;}
// userinfo を DPoP 付きで取得。401 なら refresh して 1 回だけリトライ。
async function fetchUserinfo(allowRefresh){
  let t=getTokens();if(!t)return null;
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('GET',ISSUER+'/userinfo',ath);
  const r=await fetch(ISSUER+'/userinfo',{headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  if(r.status===401&&allowRefresh&&t.refresh_token){
    const ok=await doRefresh();
    if(ok)return fetchUserinfo(false);
    return null;
  }
  if(!r.ok)return null;
  return {ui:await r.json(),tok:t};
}
// refresh_token で更新（DPoP 束縛・rotation）。
async function doRefresh(){
  const t=getTokens();if(!t||!t.refresh_token)return false;
  const proof=await dpopProof('POST',ISSUER+'/token');
  const r=await fetch(ISSUER+'/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','DPoP':proof},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:t.refresh_token,client_id:'demo-rp'})});
  const nt=await r.json();
  if(!nt.access_token)return false;
  nt.id_token=nt.id_token||t.id_token;
  saveTokens(nt);return true;
}
(async()=>{
  const q=new URLSearchParams(location.search);
  if(q.get('error')){fail('エラー: '+q.get('error')+' / '+(q.get('error_description')||''));return;}
  const code=q.get('code');
  if(code){
    // 初回: code 交換 → トークン保存 → URL から ?code 除去。
    const verifier=sessionStorage.getItem('pkce_verifier');
    const tproof=await dpopProof('POST',ISSUER+'/token');
    const r=await fetch(ISSUER+'/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','DPoP':tproof},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:ISSUER+'/callback',client_id:'demo-rp',code_verifier:verifier})});
    const tok=await r.json();
    if(tok.access_token){saveTokens(tok);try{history.replaceState({},'',location.pathname);}catch(_){}}
    // access_token が取れなかった場合(リロードで消費済み)は下の保存トークン経路へ。
  }
  // 保存トークンでライブに userinfo 取得（リロード/再訪でも継続アクセス）。
  const res=await fetchUserinfo(true);
  if(res){const prof=await fetchProfile();renderProfile(res.ui,prof,res.tok);pollCiba();setInterval(pollCiba,4000);return;}
  // トークンが無い/失効 → サインインへ。
  if(!getTokens()){location.href=ISSUER;return;}
  fail('セッションが切れました。再度サインインしてください。');
})();
</script></body></html>"##;
    Html(page.replace("__ISSUER__", &p.issuer))
}
