/* E2E crypto round-trip test — loads the REAL e2e.js with isolated per-user
 * IndexedDB + a mock in-memory "server" (zero-knowledge key directory + offline outbox).
 * Validates: X3DH handshake, Double Ratchet forward secrecy, envelope multi-recipient
 * encryption, offline message delivery, and that the server store (mock) never sees plaintext.
 *
 * 运行: NODE_PATH=/tmp/e2etest/node_modules node tests/e2e_crypto_test.js
 */
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { IDBFactory } = require('fake-indexeddb');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'e2e.js'), 'utf8');

// ---- webcrypto 兼容垫片：Node 不支持 ECDH 私钥的 raw 导入/导出，浏览器支持。
// 用 jwk 的 d 字段（私钥标量）与 Node createECDH 重建公钥点来桥接，保证 e2e.js 原样运行。
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
            const jwk = {
              kty: 'EC', crv: 'P-256',
              x: pub.slice(1, 33).toString('base64url'),
              y: pub.slice(33, 65).toString('base64url'),
              d: scalar.toString('base64url'),
              key_ops: keyUsages || ['deriveBits'],
            };
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

// ---- 共享"服务端"：零知识密钥目录 + 离线密文 outbox（模拟服务端，无法解密）----
const server = {
  keys: {},      // username -> { identity_pubkey, fingerprint }
  prekeys: {},   // username -> [{ id, pubkey }]（未消耗的一次性预密钥）
  outbox: {},   // recipient -> [{ message_id, sender, ciphertext, enc_key, ratchet_header, created_at }]
};

function mkResp(ok, payload, status = 200) {
  const body = JSON.stringify(payload);
  return { ok, status, text: async () => body, json: async () => payload };
}
function makeFetch(myName) {
  return async (url, opts = {}) => {
    const method = (opts.method || 'GET').toUpperCase();
    const headers = opts.headers || {};
    const auth = headers['Authorization'] || headers.authorization || '';
    if (!auth) throw new Error('mock: 缺少 Authorization');
    if (url.endsWith('/api/e2e/keys/upload') && method === 'POST') {
      const body = JSON.parse(opts.body);
      server.keys[myName] = { identity_pubkey: body.identity_pubkey, fingerprint: body.fingerprint };
      if (body.prekeys && body.prekeys.length) {
        server.prekeys[myName] = (server.prekeys[myName] || []).concat(body.prekeys);
      }
      server.prekeys[myName] = server.prekeys[myName] || [];
      return mkResp(true, { message: '公钥已上传', prekey_count: server.prekeys[myName].length });
    }
    if (url.endsWith('/api/e2e/prekeys') && method === 'POST') {
      const body = JSON.parse(opts.body);
      server.prekeys[myName] = (server.prekeys[myName] || []).concat(body.prekeys || []);
      return mkResp(true, { message: '预密钥已补充', prekey_count: server.prekeys[myName].length });
    }
    if (url.endsWith('/api/e2e/keys') && method === 'GET') {
      const keys = Object.entries(server.keys).map(([username, v]) => ({ username, ...v }));
      return mkResp(true, { keys });
    }
    if (url.endsWith('/api/e2e/members') && method === 'GET') {
      const members = Object.keys(server.keys).filter(u => u !== myName);
      return mkResp(true, { members });
    }
    const pm = url.match(/\/api\/e2e\/prekey\/([^/]+)$/);
    if (pm && method === 'GET') {
      const peer = decodeURIComponent(pm[1]);
      const pool = server.prekeys[peer] || [];
      const idx = pool.findIndex(p => !p._used);
      if (idx < 0) return mkResp(false, { detail: '无可用预密钥' }, 404);
      const pk = pool[idx]; pk._used = true;
      return mkResp(true, { prekey_id: pk.id, pubkey: pk.pubkey });
    }
    if (url.endsWith('/api/e2e/prekey-count') && method === 'GET') {
      const cnt = (server.prekeys[myName] || []).filter(p => !p._used).length;
      return mkResp(true, { count: cnt });
    }
    if (url.endsWith('/api/e2e/messages') && method === 'GET') {
      const msgs = server.outbox[myName] || [];
      return mkResp(true, { messages: msgs });
    }
    const rm = url.match(/\/api\/e2e\/messages\/([^/]+)\/read$/);
    if (rm && method === 'POST') {
      server.outbox[myName] = (server.outbox[myName] || []).filter(m => m.message_id !== rm[1]);
      return mkResp(true, { message: '已标记已读' });
    }
    throw new Error('mock: 未知路由 ' + method + ' ' + url);
  };
}

// 每个用户独立 E2E 实例（独立闭包 _db / 私钥状态）
function makeE2E(username) {
  const win = {};
  const idb = new IDBFactory();
  const factory = new Function(
    'window', 'indexedDB', 'fetch', 'crypto', 'console', 'TextEncoder', 'TextDecoder', 'atob', 'btoa',
    SRC + '\nreturn window.E2E;'
  );
  return factory(win, idb, makeFetch(username), shimCrypto(globalThis.crypto), console, TextEncoder, TextDecoder, atob, btoa);
}

let pass = 0, fail = 0;
function assert(cond, msg) { if (cond) { pass++; console.log('  ✅', msg); } else { fail++; console.error('  ❌', msg); throw new Error(msg); } }

async function main() {
  const alice = makeE2E('alice');
  const bob = makeE2E('bob');
  const carol = makeE2E('carol');
  alice.setToken('tok_alice'); bob.setToken('tok_bob'); carol.setToken('tok_carol');

  console.log('\n=== 阶段1: 三方初始化（生成身份密钥 + 上传公钥 + 预密钥池）===');
  await alice.init('alice', 'pw_alice');
  await bob.init('bob', 'pw_bob');
  await carol.init('carol', 'pw_carol');
  assert(server.prekeys.alice.length === 20, 'alice 上传 20 个预密钥');
  assert(server.prekeys.bob.length === 20, 'bob 上传 20 个预密钥');
  assert(!!alice.getFingerprint() && !!bob.getFingerprint(), '身份指纹已生成');
  console.log('  alice 指纹:', alice.getFingerprint().slice(0, 23) + '…');

  console.log('\n=== 阶段2: 在线单聊 + 前向保密（alice 连发 3 条给 bob）===');
  const texts = ['Hello Bob #1', 'Hello Bob #2', 'Hello Bob #3'];
  const encKeys = [];
  for (const t of texts) {
    const { ciphertext, recipients } = await alice.encryptForRecipients(t, ['bob']);
    assert(recipients.length === 1, '接收方=1 (bob)');
    encKeys.push(recipients[0].enc_key);
    const pt = await bob.decryptIncoming({ sender: 'alice', ciphertext, enc_key: recipients[0].enc_key, ratchet_header: recipients[0].ratchet_header });
    assert(pt === t, 'bob 解密成功: ' + t);
  }
  assert(new Set(encKeys).size === 3, '每条消息 enc_key 不同（前向保密：ratchet 步进）');

  console.log('\n=== 阶段3: 多人聊天（alice → [bob, carol] 信封加密）===');
  {
    const { ciphertext, recipients } = await alice.encryptForRecipients('Hi group! 🔒', ['bob', 'carol']);
    assert(recipients.length === 2, '两个接收方各一份 enc_key');
    const rB = recipients.find(r => r.username === 'bob');
    const rC = recipients.find(r => r.username === 'carol');
    assert(rB && rC, 'bob & carol 均在接收列表');
    assert(rB.enc_key !== rC.enc_key, '两接收方 enc_key 不同（各自链派生）');
    const ptB = await bob.decryptIncoming({ sender: 'alice', ciphertext, enc_key: rB.enc_key, ratchet_header: rB.ratchet_header });
    const ptC = await carol.decryptIncoming({ sender: 'alice', ciphertext, enc_key: rC.enc_key, ratchet_header: rC.ratchet_header });
    assert(ptB === 'Hi group! 🔒' && ptC === 'Hi group! 🔒', 'bob & carol 均解出同一明文');
  }

  console.log('\n=== 阶段4: 离线消息（bob 离线时 alice 发送，bob 上线后拉取解密）===');
  {
    const { ciphertext, recipients } = await alice.encryptForRecipients('Offline ping for bob', ['bob']);
    const rB = recipients.find(r => r.username === 'bob');
    const mid = 'msg_offline_' + Date.now();
    server.outbox.bob = (server.outbox.bob || []).concat([{ message_id: mid, sender: 'alice', ciphertext, enc_key: rB.enc_key, ratchet_header: rB.ratchet_header, created_at: new Date().toISOString() }]);
    assert(typeof server.outbox.bob[0].ciphertext === 'string' && !server.outbox.bob[0].ciphertext.includes('ping'), '服务端只存密文，不含明文');
    const got = [];
    const n = await bob.fetchOfflineMessages(m => got.push(m));
    assert(n === 1, 'bob 拉取到 1 条离线消息');
    assert(got.length === 1, '回调收到 1 条');
    assert(got[0].text === 'Offline ping for bob', '离线消息解密成功: ' + got[0].text);
    assert((server.outbox.bob || []).length === 0, '离线消息拉取后已标记已读并移除');
  }

  console.log('\n=== 阶段5: 零知识校验（服务端持有的所有数据均无法解密正文）===');
  assert(Object.keys(server.keys).every(u => !server.keys[u].priv), '服务端公钥目录无私钥');
  assert(Object.values(server.prekeys).flat().every(p => !p.priv), '服务端预密钥池无私钥');
  const allCt = [].concat(...Object.values(server.outbox));
  assert(allCt.every(m => typeof m.ciphertext === 'string' && !m.ciphertext.includes('Hello') && !m.ciphertext.includes('ping')), 'outbox 密文不含任何明文片段');

  console.log(`\n================ 结果: ${pass} 通过, ${fail} 失败 ================`);
  if (fail > 0) process.exit(1);
}
main().catch(e => { console.error('测试异常:', e); process.exit(1); });
