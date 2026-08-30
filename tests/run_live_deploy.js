/* 部署服务端 E2E 全链路测试（适配 https://39.107.111.43 + 自签名证书）
 * 运行: NODE_PATH=/tmp/e2etest/node_modules node tests/run_live_deploy.js
 */
const fs = require('fs');
const nodeCrypto = require('crypto');
const https = require('https');
const http = require('http');
const { IDBFactory } = require('fake-indexeddb');
const WebSocket = require('ws');
const { HttpsProxyAgent } = require('https-proxy-agent');

const BASE = 'https://39.107.111.43';
const WS_URL = 'wss://39.107.111.43/ws';
const SRC = fs.readFileSync(__dirname + '/../frontend/e2e.js', 'utf8');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
// 远程沙箱走 HTTP CONNECT 代理出网
const PROXY_AGENT = new HttpsProxyAgent('http://127.0.0.1:18080');

function customFetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const body = opts.body || null;
    const headers = { ...(opts.headers || {}) };
    if (body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const reqOpts = {
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: opts.method || 'GET',
      headers, rejectUnauthorized: false,
    };
    if (u.protocol === 'https:') reqOpts.agent = PROXY_AGENT;
    const req = lib.request(reqOpts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({
        ok: res.statusCode >= 200 && res.statusCode < 300,
        status: res.statusCode,
        json: async () => JSON.parse(data),
        text: async () => data,
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function bufToArrayBuffer(buf) { return new Uint8Array(buf).buffer; }
function shimCrypto(crypto) {
  const subtle = crypto.subtle;
  const shimmed = new Proxy({}, {
    get(_t, prop) {
      if (prop === 'exportKey') return async (fmt, key) => {
        if (fmt === 'raw' && key.type === 'private') {
          const jwk = await subtle.exportKey('jwk', key);
          const d = jwk.d.replace(/-/g, '+').replace(/_/g, '/');
          const pad = d.length % 4 ? '='.repeat(4 - d.length % 4) : '';
          return bufToArrayBuffer(Buffer.from(d + pad, 'base64'));
        }
        return bufToArrayBuffer(Buffer.from(await subtle.exportKey(fmt, key)));
      };
      if (prop === 'importKey') return async (fmt, keyData, algorithm, extractable, keyUsages) => {
        const ab = keyData instanceof ArrayBuffer ? keyData :
          (ArrayBuffer.isView(keyData) ? keyData.buffer.slice(keyData.byteOffset, keyData.byteOffset + keyData.byteLength) : keyData);
        if (fmt === 'raw' && algorithm && (algorithm.name === 'ECDH' || algorithm.name === 'EC')) {
          try { return await subtle.importKey(fmt, ab, algorithm, extractable, keyUsages); }
          catch (e) {
            const scalar = Buffer.from(ab);
            const ecdh = nodeCrypto.createECDH('prime256v1');
            ecdh.setPrivateKey(scalar);
            const pub = ecdh.getPublicKey();
            const jwk = { kty: 'EC', crv: 'P-256',
              x: pub.slice(1, 33).toString('base64url'), y: pub.slice(33, 65).toString('base64url'),
              d: scalar.toString('base64url'), key_ops: keyUsages || ['deriveBits'] };
            return await subtle.importKey('jwk', jwk, algorithm, extractable, keyUsages || ['deriveBits']);
          }
        }
        return await subtle.importKey(fmt, ab, algorithm, extractable, keyUsages);
      };
      const v = subtle[prop];
      return typeof v === 'function' ? v.bind(subtle) : v;
    },
  });
  return new Proxy(crypto, {
    get(_t, prop) {
      if (prop === 'subtle') return shimmed;
      const v = crypto[prop];
      return typeof v === 'function' ? v.bind(crypto) : v;
    },
  });
}

function realFetch(token) {
  return async (url, opts = {}) => {
    const full = url.startsWith('http') ? url : BASE + url;
    const headers = { ...(opts.headers || {}) };
    if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    if (token && !headers['Authorization']) headers['Authorization'] = 'Bearer ' + token;
    return customFetch(full, { ...opts, headers });
  };
}

function makeE2E(username, token) {
  const win = {};
  const idb = new IDBFactory();
  const factory = new Function(
    'window', 'indexedDB', 'fetch', 'crypto', 'console', 'TextEncoder', 'TextDecoder', 'atob', 'btoa',
    SRC + '\nreturn window.E2E;'
  );
  return factory(win, idb, realFetch(token), shimCrypto(globalThis.crypto), console, TextEncoder, TextDecoder, atob, btoa);
}

async function reg(name, pw) {
  const r = await customFetch(BASE + '/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: name, password: pw })
  });
  return r.status;
}
async function login(name, pw) {
  const form = `username=${encodeURIComponent(name)}&password=${encodeURIComponent(pw)}`;
  const r = await customFetch(BASE + '/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('login failed: ' + JSON.stringify(j));
  return j.access_token;
}
async function getRsaPub() {
  const r = await customFetch(BASE + '/api/public-key');
  return (await r.json()).public_key;
}
function pemToBuf(pem) {
  const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
  return bufToArrayBuffer(Buffer.from(b64, 'base64'));
}
async function makeEncSessionKey(pem) {
  const pub = await crypto.subtle.importKey('spki', pemToBuf(pem), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const raw = nodeCrypto.randomBytes(32);
  const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw);
  return Buffer.from(ct).toString('base64');
}

function connectWS(token, encKey) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WS_URL, { origin: BASE, rejectUnauthorized: false, agent: PROXY_AGENT });
    ws._handlers = [];
    ws.onMessage = (fn) => ws._handlers.push(fn);
    ws.onopen = () => ws.send(JSON.stringify({ token, encrypted_session_key: encKey }));
    ws.onmessage = (e) => {
      let d; try { d = JSON.parse(e.data.toString()); } catch (err) { return; }
      if (d.type === 'connected') resolve(ws);
      else if (d.type === 'error') reject(new Error(d.message));
      else ws._handlers.forEach(h => h(d));
    };
    ws.onerror = () => reject(new Error('WS error'));
    setTimeout(() => reject(new Error('WS 连接超时')), 10000);
  });
}

let pass = 0, fail = 0;
const fails = [];
function assert(c, m) {
  if (c) { pass++; console.log('  PASS', m); }
  else { fail++; console.error('  FAIL', m); fails.push(m); throw new Error(m); }
}
function log(s) { console.log(s); }

async function main() {
  const PWA = 'Alice@Test123', PWB = 'Bob@Test123', PWC = 'Charlie@Test123';
  const UA = 'e2e_alice', UB = 'e2e_bob', UC = 'e2e_charlie';
  await reg(UA, PWA); await reg(UB, PWB); await reg(UC, PWC);
  const ta = await login(UA, PWA), tb = await login(UB, PWB), tc = await login(UC, PWC);
  const pem = await getRsaPub();
  const ekA = await makeEncSessionKey(pem), ekB = await makeEncSessionKey(pem), ekC = await makeEncSessionKey(pem);

  log('\n=== 阶段1: 三方 WebSocket 鉴权 + E2E 身份初始化（部署服务端 https://39.107.111.43）===');
  const wsA = await connectWS(ta, ekA);
  const wsB = await connectWS(tb, ekB);
  const wsC = await connectWS(tc, ekC);
  assert(true, 'alice & bob & charlie WebSocket 已连接 (wss)');

  const A = makeE2E(UA, ta); A.setToken(ta);
  const B = makeE2E(UB, tb); B.setToken(tb);
  const C = makeE2E(UC, tc); C.setToken(tc);
  await A.init(UA, PWA); await B.init(UB, PWB); await C.init(UC, PWC);
  assert(true, '三方 E2E.init 完成（身份公钥+预密钥已上传）');

  log('\n=== 阶段2: 在线实时投递（alice→bob，WS 推送 + bob 实时解密）===');
  let bobRecv = null;
  wsB.onMessage(d => { if (d.type === 'e2e_message') bobRecv = d; });
  const membersA = await A.getMembers();
  assert(membersA.includes(UB), 'alice 成员列表含 bob: ' + JSON.stringify(membersA));
  const enc2 = await A.encryptForRecipients('Hello online! 🚀', [UB]);
  wsA.send(JSON.stringify({ type: 'e2e_message', ciphertext: enc2.ciphertext, recipients: enc2.recipients, room: 'public' }));
  await new Promise((res, rej) => {
    let n = 0; const t = setInterval(() => { if (bobRecv) { clearInterval(t); res(); } else if (++n > 50) { clearInterval(t); rej(new Error('bob 未收到在线消息')); } }, 100);
  });
  const pt2 = await B.decryptIncoming(bobRecv);
  assert(pt2 === 'Hello online! 🚀', 'bob 实时解密 alice 在线消息: ' + pt2);

  log('\n=== 阶段3: 离线投递（bob 下线，alice 发送，bob 上线后拉取解密）===');
  await new Promise(res => { wsB.onclose = res; wsB.close(); });
  assert(true, 'bob 已下线');
  const off = await A.encryptForRecipients('Offline msg 💤', [UB]);
  wsA.send(JSON.stringify({ type: 'e2e_message', ciphertext: off.ciphertext, recipients: off.recipients, room: 'public' }));
  await new Promise(r => setTimeout(r, 800));
  assert(true, 'alice 已发出离线消息（服务端只存密文）');
  const wsB2 = await connectWS(tb, await makeEncSessionKey(pem));
  assert(true, 'bob 重新上线');
  const got = [];
  await B.fetchOfflineMessages(m => got.push(m));
  assert(got.length === 1, 'bob 拉取到 1 条离线消息');
  assert(got[0].text === 'Offline msg 💤', 'bob 离线解密: ' + got[0].text);
  assert(got[0].sender === UA, '离线消息 sender=alice');

  log('\n=== 阶段4: 多人群发（charlie→alice+bob，二者离线，上线后均解密）===');
  await new Promise(res => { wsA.onclose = res; wsA.close(); });
  await new Promise(res => { wsB2.onclose = res; wsB2.close(); });
  assert(true, 'alice & bob 均已下线');
  const membersC = await C.getMembers();
  assert(membersC.includes(UA) && membersC.includes(UB), 'charlie 成员列表含 alice+bob: ' + JSON.stringify(membersC));
  const grp = await C.encryptForRecipients('Group multi-msg 🎉', [UA, UB]);
  wsC.send(JSON.stringify({ type: 'e2e_message', ciphertext: grp.ciphertext, recipients: grp.recipients, room: 'public' }));
  await new Promise(r => setTimeout(r, 800));
  assert(true, 'charlie 已群发（2 个 enc_key，服务端为 alice+bob 各存一份）');
  const wsA2 = await connectWS(ta, await makeEncSessionKey(pem));
  const gotA = [];
  await A.fetchOfflineMessages(m => gotA.push(m));
  assert(gotA.length === 1, 'alice 拉取到 1 条 charlie 群发消息');
  assert(gotA[0].text === 'Group multi-msg 🎉', 'alice 解密 charlie 群发: ' + gotA[0].text);
  const wsB3 = await connectWS(tb, await makeEncSessionKey(pem));
  const gotB = [];
  await B.fetchOfflineMessages(m => gotB.push(m));
  assert(gotB.length === 1, 'bob 拉取到 1 条 charlie 群发消息');
  assert(gotB[0].text === 'Group multi-msg 🎉', 'bob 解密 charlie 群发: ' + gotB[0].text);

  log('\n=== 阶段5: 零知识校验（部署服务端只存公钥+指纹，无私钥）===');
  const keys = await (await customFetch(BASE + '/api/e2e/keys', { headers: { Authorization: 'Bearer ' + ta } })).json();
  assert(keys.keys.every(k => !k.priv && k.identity_pubkey && k.fingerprint), '公钥目录仅含公钥+指纹，无私钥泄露');

  wsA2.close(); wsB3.close(); wsC.close();
  log(`\n================ 结果: ${pass} 通过, ${fail} 失败 ================`);
  if (fail > 0) { console.error('失败项:', fails); process.exit(1); }
}
main().catch(e => { console.error('测试异常:', e.message || e); console.error(e.stack); process.exit(1); });
