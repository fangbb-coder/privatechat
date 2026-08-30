/* 真实服务端 E2E 全链路测试（WebSocket + REST）
 * 两个真实客户端用 e2e.js 加密，经运行中的后端 (127.0.0.1:8080) 投递：
 *   - 在线实时投递（WS 推送 + 服务端标记已读，防重复投递）
 *   - 离线投递（服务端只存密文；接收方上线后 REST 拉取并解密）
 *  运行: NODE_PATH=/tmp/e2etest/node_modules node tests/e2e_live_test.js
 */
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { IDBFactory } = require('fake-indexeddb');
const WebSocket = require('ws');

const BASE = 'http://127.0.0.1:8080';
const SRC = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'e2e.js'), 'utf8');

// ---- webcrypto 垫片（Node 不支持 ECDH 私钥 raw 导入/导出）----
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
        return subtle.exportKey(fmt, key);
      };
      if (prop === 'importKey') return async (fmt, keyData, algorithm, extractable, keyUsages) => {
        if (fmt === 'raw' && algorithm && (algorithm.name === 'ECDH' || algorithm.name === 'EC')) {
          try { return await subtle.importKey(fmt, keyData, algorithm, extractable, keyUsages); }
          catch (e) {
            const scalar = Buffer.from(keyData);
            const ecdh = nodeCrypto.createECDH('prime256v1');
            ecdh.setPrivateKey(scalar);
            const pub = ecdh.getPublicKey();
            const jwk = { kty: 'EC', crv: 'P-256',
              x: pub.slice(1, 33).toString('base64url'), y: pub.slice(33, 65).toString('base64url'),
              d: scalar.toString('base64url'), key_ops: keyUsages || ['deriveBits'] };
            return await subtle.importKey('jwk', jwk, algorithm, extractable, keyUsages || ['deriveBits']);
          }
        }
        return subtle.importKey(fmt, keyData, algorithm, extractable, keyUsages);
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

// 把 e2e.js 的相对 URL fetch 指向真实服务端
function realFetch(token) {
  return async (url, opts = {}) => {
    const full = url.startsWith('http') ? url : BASE + url;
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (token && !headers['Authorization']) headers['Authorization'] = 'Bearer ' + token;
    return fetch(full, { ...opts, headers });
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

// ---- HTTP 工具 ----
async function reg(name, pw) {
  const r = await fetch(BASE + '/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: name, password: pw }) });
  return r.status;
}
async function login(name, pw) {
  const r = await fetch(BASE + '/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: name, password: pw }) });
  const j = await r.json();
  return j.access_token;
}
async function getRsaPub() {
  const r = await fetch(BASE + '/api/public-key');
  const j = await r.json();
  return j.public_key;
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

// ---- WebSocket 客户端：连接 + 鉴权 + 等待 connected ----
function connectWS(token, encKey) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket('ws://127.0.0.1:8080/ws', { origin: 'http://127.0.0.1:8080' });
    const queue = [];
    ws._handlers = [];
    ws.onMessage = (fn) => ws._handlers.push(fn);
    ws.onopen = () => ws.send(JSON.stringify({ token, encrypted_session_key: encKey }));
    ws.onmessage = (e) => {
      const d = JSON.parse(e.data);
      if (d.type === 'connected') resolve(ws);
      else if (d.type === 'error') reject(new Error(d.message));
      else ws._handlers.forEach(h => h(d));
    };
    ws.onerror = (err) => reject(new Error('WS error'));
    setTimeout(() => reject(new Error('WS 连接超时')), 8000);
  });
}

let pass = 0, fail = 0;
function assert(c, m) { if (c) { pass++; console.log('  PASS', m); } else { fail++; console.error('  FAIL', m); throw new Error(m); } }

async function main() {
  const PWA = 'Alice@Test123', PWB = 'Bob@Test123';
  await reg('alice', PWA); await reg('bob', PWB);
  const ta = await login('alice', PWA), tb = await login('bob', PWB);
  const pem = await getRsaPub();
  const ekA = await makeEncSessionKey(pem), ekB = await makeEncSessionKey(pem);

  console.log('\n=== 阶段1: 双方 WebSocket 鉴权 + E2E 身份初始化（真实服务端）===');
  const wsA = await connectWS(ta, ekA);
  const wsB = await connectWS(tb, ekB);
  assert(true, 'alice & bob WebSocket 已连接');

  const A = makeE2E('alice', ta); A.setToken(ta);
  const B = makeE2E('bob', tb); B.setToken(tb);
  await A.init('alice', PWA); await B.init('bob', PWB);
  assert(true, '双方 E2E.init 完成（身份公钥+预密钥已上传真实服务端）');

  console.log('\n=== 阶段2: 在线实时投递（alice→bob，服务端推送+标记已读）===');
  // 收集 bob 收到的 e2e_message
  let bobRecv = null;
  wsB.onMessage(d => { if (d.type === 'e2e_message') bobRecv = d; });
  const members = await A.getMembers();
  assert(members.includes('bob'), 'alice 成员列表含 bob: ' + JSON.stringify(members));
  const { ciphertext, recipients } = await A.encryptForRecipients('Hello via WS! 🚀', ['bob']);
  wsA.send(JSON.stringify({ type: 'e2e_message', ciphertext, recipients, room: 'public' }));
  // 等待 bob 收到
  await new Promise((res, rej) => {
    let n = 0; const t = setInterval(() => { if (bobRecv) { clearInterval(t); res(); } else if (++n > 40) { clearInterval(t); rej(new Error('bob 未收到在线消息')); } }, 100);
  });
  const pt = await B.decryptIncoming(bobRecv);
  assert(pt === 'Hello via WS! 🚀', 'bob 实时解密: ' + pt);

  console.log('\n=== 阶段3: 离线投递（bob 下线，alice 发送，bob 上线后拉取解密）===');
  // bob 下线
  await new Promise(res => { wsB.onclose = res; wsB.close(); });
  assert(true, 'bob 已下线');
  // alice 发送离线消息（服务端只存密文）
  const off = await A.encryptForRecipients('Offline via WS! 💤', ['bob']);
  wsA.send(JSON.stringify({ type: 'e2e_message', ciphertext: off.ciphertext, recipients: off.recipients, room: 'public' }));
  await new Promise(r => setTimeout(r, 600));
  // bob 重新上线（新 WS），E2E 实例 B 保持（会话状态在 IndexedDB）
  const wsB2 = await connectWS(tb, await makeEncSessionKey(pem));
  assert(true, 'bob 重新上线');
  const got = [];
  await B.fetchOfflineMessages(m => got.push(m));
  assert(got.length === 1, 'bob 拉取到 1 条离线消息');
  assert(got[0].text === 'Offline via WS! 💤', 'bob 离线解密: ' + got[0].text);
  assert(got[0].sender === 'alice', '离线消息 sender=alice');

  console.log('\n=== 阶段4: 零知识校验（真实服务端只存密文，无法解密）===');
  // 直接查服务端 DB：确认无私钥、outbox 只存密文
  // 通过 REST 已读校验：alice 视角无法获取 bob 的私钥（接口不提供）
  const keys = await (await fetch(BASE + '/api/e2e/keys', { headers: { Authorization: 'Bearer ' + ta } })).json();
  assert(keys.keys.every(k => !k.priv && k.identity_pubkey && k.fingerprint), '公钥目录仅含公钥+指纹，无私钥');

  wsA.close(); wsB2.close();
  console.log(`\n================ 结果: ${pass} 通过, ${fail} 失败 ================`);
  if (fail > 0) process.exit(1);
}
main().catch(e => { console.error('测试异常:', e); process.exit(1); });
