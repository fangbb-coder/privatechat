/* ===================================================================
 * Private Chat — 端到端加密（E2E）客户端协议模块
 *
 * 协议：简化 Signal
 *   - X3DH 握手（身份密钥 IK + 一次性预密钥 OPK + 临时密钥 EK）支持离线首次握手
 *   - 对称 KDF 链 ratchet（每条消息步进 CK，旧密钥丢弃 → 前向保密）
 *   - 信封加密：随机消息密钥 K 加密正文，每个接收方用各自链派生的 mk 加密 K
 *   - 群组前向保密：每个 sender→recipient 一条独立链（多接收方各一份 enc_key）
 *
 * 私钥隔离（v2）：身份私钥、OPK 私钥、ratchet 链密钥在 IndexedDB 中均以
 *   AES-GCM 封装存盘。封装密钥不再来自登录口令，而由平台认证器
 *   （Touch ID / Windows Hello / 生物识别）经 WebAuthn PRF 扩展派生，
 *   解封需用户本地验证（生物识别/PIN），私钥与设备绑定。
 *   无平台认证器或 PRF 不可用时，回退到登录口令 PBKDF2 派生密钥封装。
 *
 * 零知识：私钥永不离开客户端；服务端只存密文 + per-recipient enc_key，无法解密。
 * 客户端不存消息，按需从服务端拉取密文解密渲染（仅持久化私钥与 ratchet 状态）。
 * 离线消息：用户上线后拉取服务端存档的密文，本地解密。
 * =================================================================== */
window.E2E = (function () {
  'use strict';

  const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
  const HKDF_SALT = new Uint8Array([112, 114, 105, 118, 97, 116, 101, 99, 104, 97, 116]); // "privatechat"
  const PBKDF2_ITER = 100000;

  // ---------- base64 工具 ----------
  function b64(buf) {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function unb64(str) {
    const s = atob(str);
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  function b64u(buf) {
    return b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64uDec(str) {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return unb64(s);
  }
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------- IndexedDB（私钥 + ratchet 状态 + 预密钥池） ----------
  const DB_NAME = 'e2e_privatechat';
  let _db = null;
  function db() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
      const r = indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = () => {
        const d = r.result;
        if (!d.objectStoreNames.contains('keys')) d.createObjectStore('keys', { keyPath: 'username' });
        if (!d.objectStoreNames.contains('sessions')) d.createObjectStore('sessions', { keyPath: 'peer' });
        if (!d.objectStoreNames.contains('prekeys')) d.createObjectStore('prekeys', { keyPath: 'id' });
      };
      r.onsuccess = () => { _db = r.result; resolve(_db); };
      r.onerror = () => reject(r.error);
    });
  }
  function idbGet(store, key) {
    return db().then(d => new Promise((res, rej) => {
      const r = d.transaction(store).objectStore(store).get(key);
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    }));
  }
  function idbGetAll(store) {
    return db().then(d => new Promise((res, rej) => {
      const r = d.transaction(store).objectStore(store).getAll();
      r.onsuccess = () => res(r.result || []); r.onerror = () => rej(r.error);
    }));
  }
  function idbPut(store, val) {
    return db().then(d => new Promise((res, rej) => {
      const r = d.transaction(store, 'readwrite').objectStore(store).put(val);
      r.onsuccess = () => res(); r.onerror = () => rej(r.error);
    }));
  }
  function idbDel(store, key) {
    return db().then(d => new Promise((res, rej) => {
      const r = d.transaction(store, 'readwrite').objectStore(store).delete(key);
      r.onsuccess = () => res(); r.onerror = () => rej(r.error);
    }));
  }

  // ---------- 密码学原语 ----------
  function genECDH() { return crypto.subtle.generateKey(CURVE, true, ['deriveKey', 'deriveBits']); }
  async function pubRaw(keyPair) { return new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)); }
  // EC 私钥用 PKCS#8 格式导出/导入（Web Crypto 标准）。
  // 注意：'raw' 格式仅用于公钥；私钥 'raw' 导出非标准，浏览器会抛
  // "The key is not of the expected type"，故私钥统一走 pkcs8。
  async function privRaw(keyPair) { return new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)); }
  function importPub(rawBytes) { return crypto.subtle.importKey('raw', rawBytes, CURVE, false, []); }
  function importPriv(privBytes) { return crypto.subtle.importKey('pkcs8', privBytes, CURVE, false, ['deriveBits']); }
  function dh(privKey, pubKey) { return crypto.subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256); }
  async function hkdf(ikmBytes, infoStr, len = 32) {
    const base = await crypto.subtle.importKey('raw', ikmBytes, 'HKDF', false, ['deriveBits']);
    const out = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: enc.encode(infoStr) }, base, len * 8);
    return new Uint8Array(out);
  }
  async function sha256Hex(rawBytes) {
    const h = await crypto.subtle.digest('SHA-256', rawBytes);
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join(':');
  }
  function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  async function aesGcmEncrypt(keyBytes, data) {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = rand(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, data));
    const out = new Uint8Array(iv.length + ct.length); out.set(iv, 0); out.set(ct, iv.length);
    return out; // iv‖ciphertext+tag
  }
  async function aesGcmDecrypt(keyBytes, packed) {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const iv = packed.slice(0, 12);
    const ct = packed.slice(12);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, ct));
  }

  // ---------- 私钥封装（at-rest protection） ----------
  // myWrapKey：内存中的封装密钥（32 字节）。
  //   - 平台模式：由 WebAuthn PRF 派生（解封需生物识别/PIN，绑定设备）
  //   - 口令模式：由登录口令 PBKDF2 派生（无平台认证器时回退）
  // 用它封装：身份私钥、OPK 私钥、ratchet 链密钥。
  let myWrapKey = null;        // Uint8Array(32) 或 null
  let protectionMode = 'password'; // 'password' | 'webauthn'

  async function aesKey(rawBytes) {
    return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }
  // 登录口令派生封装密钥（回退路径）
  async function deriveWrapKeyRaw(password, salt) {
    const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, km, 256);
    return new Uint8Array(bits);
  }
  // 用指定 raw 封装密钥加解密
  async function wrapWith(rawKey, data) {
    const iv = rand(12);
    const k = await aesKey(rawKey);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, data));
    return { wrapped: b64(ct), iv: b64(iv) };
  }
  async function unwrapWith(rawKey, wrappedB64, ivB64) {
    const k = await aesKey(rawKey);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, k, unb64(wrappedB64)));
  }
  // 用当前 myWrapKey 封装/解封
  function wrapPriv(rawPriv) {
    if (!myWrapKey) return Promise.reject(new Error('封装密钥未就绪'));
    return wrapWith(myWrapKey, rawPriv);
  }
  function unwrapPriv(wrappedB64, ivB64) {
    if (!myWrapKey) return Promise.reject(new Error('封装密钥未就绪'));
    return unwrapWith(myWrapKey, wrappedB64, ivB64);
  }

  // ---------- WebAuthn PRF 平台密钥 ----------
  async function platformAuthAvailable() {
    try {
      if (typeof PublicKeyCredential === 'undefined' ||
        typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') return false;
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) { return false; }
  }
  function supportsPrf(assertion) {
    const ext = assertion && assertion.getClientExtensionResults && assertion.getClientExtensionResults();
    return !!(ext && ext.prf && ext.prf.enabled);
  }
  function prfResult(assertion) {
    const ext = assertion && assertion.getClientExtensionResults && assertion.getClientExtensionResults();
    const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    return first ? new Uint8Array(first) : null;
  }
  // 评估 PRF → 封装密钥（需用户本地验证）
  async function prfDerive(credIdB64u, salt) {
    const challenge = rand(32);
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ type: 'public-key', id: b64uDec(credIdB64u) }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: salt } } },
        timeout: 60000,
      }
    });
    let first = prfResult(assertion);
    if (!first) throw new Error('WebAuthn PRF 不可用：当前浏览器/认证器不支持 PRF 扩展');
    return hkdf(first, 'e2e_wrap_key_v1', 32);
  }
  // 注册平台驻留凭据并评估 PRF → {credId, wrapKey}
  async function createPlatformCred(username, salt) {
    const challenge = rand(32);
    const userId = await crypto.subtle.digest('SHA-256', enc.encode(username));
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: 'Private Chat E2E' },
        user: { id: new Uint8Array(userId), name: username, displayName: username },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { userVerification: 'required', residentKey: 'preferred', authenticatorAttachment: 'platform' },
        extensions: { prf: { eval: { first: salt } } },
        timeout: 60000,
      }
    });
    const credId = b64u(cred.rawId);
    let first = prfResult(cred);
    if (!first) {
      // create 未返回 PRF（部分实现需 get() 评估）
      first = await prfDerive(credId, salt);
    }
    return { credId, wrapKey: await hkdf(first, 'e2e_wrap_key_v1', 32) };
  }

  // ---------- 会话状态（ratchet 链密钥封装存盘） ----------
  // sessions[peer] 在内存中为 { peer, rk, send_ck, send_seq, recv_ck, recv_seq, peer_ik, initiated }
  // 存盘时整体封装为 blob（链密钥不落明文）
  async function getSession(peer) {
    const rec = await idbGet('sessions', peer);
    if (!rec) return null;
    if (rec.blob && myWrapKey) {
      const payload = await unwrapWith(myWrapKey, rec.blob, rec.iv);
      const obj = JSON.parse(dec.decode(payload));
      return { peer, ...obj };
    }
    // 旧版明文记录兼容
    return {
      peer, rk: rec.rk, send_ck: rec.send_ck, send_seq: rec.send_seq,
      recv_ck: rec.recv_ck, recv_seq: rec.recv_seq, peer_ik: rec.peer_ik, initiated: rec.initiated,
    };
  }
  async function putSession(s) {
    const payload = enc.encode(JSON.stringify({
      rk: s.rk, send_ck: s.send_ck, send_seq: s.send_seq,
      recv_ck: s.recv_ck, recv_seq: s.recv_seq, peer_ik: s.peer_ik, initiated: s.initiated,
    }));
    if (myWrapKey) {
      const w = await wrapWith(myWrapKey, payload);
      await idbPut('sessions', { peer: s.peer, iv: w.iv, blob: w.wrapped });
    } else {
      const obj = JSON.parse(dec.decode(payload));
      await idbPut('sessions', { peer: s.peer, ...obj });
    }
  }
  async function ratchetStep(ckBytes) {
    const mk = await hkdf(ckBytes, 'message_key', 32);
    const next = await hkdf(ckBytes, 'chain_advance', 32);
    return { mk, next };
  }

  // ---------- 公共状态 ----------
  let myUsername = null;
  let myIdentityPriv = null;      // CryptoKey（非导出，用于 DH）
  let myIdentityPrivRaw = null;   // Uint8Array（内存缓存，用于平台密钥迁移重封装；不落盘）
  let myIdentityPubRaw = null;    // Uint8Array(65)
  let myFingerprint = null;
  let token = null; // JWT，用于 REST 调用

  async function fetchJSON(url, opts = {}) {
    const r = await fetch(url, { ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } });
    const t = await r.text();
    let j = null; try { j = t ? JSON.parse(t) : null; } catch (e) { j = null; }
    if (!r.ok) throw new Error((j && j.detail) || ('HTTP ' + r.status));
    return j;
  }

  // ---------- 初始化：生成/加载身份密钥，上传公钥+预密钥 ----------
  async function ensureIdentity(username, password) {
    myUsername = username;
    const rec = await idbGet('keys', username);
    const usePlatform = await platformAuthAvailable();
    if (rec) {
      // 已有身份密钥：按存盘的 protectionMode 解封
      if (rec.mode === 'webauthn' && rec.credId) {
        // 平台密钥解封：PRF 派生封装密钥（需生物识别/PIN）
        myWrapKey = await prfDerive(rec.credId, unb64(rec.salt));
        protectionMode = 'webauthn';
      } else {
        // 口令解封（兼容旧记录无 mode 字段）
        myWrapKey = await deriveWrapKeyRaw(password, unb64(rec.salt));
        protectionMode = 'password';
      }
      let privRawBytes;
      try {
        privRawBytes = await unwrapPriv(rec.priv, rec.iv);
      } catch (e) {
        throw new Error('解锁私钥失败：' + (protectionMode === 'webauthn' ? '平台验证失败或数据损坏' : '口令错误或数据损坏'));
      }
      myIdentityPrivRaw = privRawBytes;
      myIdentityPriv = await importPriv(privRawBytes);
      myIdentityPubRaw = unb64(rec.pub);
    } else {
      // 首次：生成身份密钥对
      const ik = await genECDH();
      const pr = await privRaw(ik);
      const pu = await pubRaw(ik);
      const salt = rand(16);
      let credId = null;
      if (usePlatform) {
        // 平台认证器可用 → 用 PRF 封装（注册凭据，需生物识别）
        try {
          const pc = await createPlatformCred(username, salt);
          myWrapKey = pc.wrapKey; credId = pc.credId; protectionMode = 'webauthn';
        } catch (e) {
          // 用户取消或 PRF 不可用 → 回退口令封装
          myWrapKey = await deriveWrapKeyRaw(password, salt); protectionMode = 'password';
        }
      } else {
        myWrapKey = await deriveWrapKeyRaw(password, salt); protectionMode = 'password';
      }
      const w = await wrapPriv(pr);
      await idbPut('keys', { username, priv: w.wrapped, iv: w.iv, salt: b64(salt), pub: b64(pu), mode: protectionMode, credId });
      myIdentityPrivRaw = pr;
      myIdentityPriv = ik.privateKey;
      myIdentityPubRaw = pu;
    }
    // 指纹必须先于上传计算（generateAndUploadPrekeys 会把指纹一并上传）
    myFingerprint = await sha256Hex(myIdentityPubRaw);
    if (!rec) {
      // 首次：预生成一批一次性预密钥并上传
      await generateAndUploadPrekeys(20);
    }
  }

  async function generateAndUploadPrekeys(count) {
    const batch = [];
    for (let i = 0; i < count; i++) {
      const pk = await genECDH();
      const pubRawB = await pubRaw(pk);
      const privRawB = await privRaw(pk);
      const id = 'opk_' + Date.now() + '_' + i + '_' + [...rand(4)].map(x => x.toString(16).padStart(2, '0')).join('');
      // OPK 私钥用 myWrapKey 封装存盘（不落明文）
      const w = await wrapPriv(privRawB);
      await idbPut('prekeys', { id, priv: w.wrapped, iv: w.iv, pub: b64(pubRawB) });
      batch.push({ id, pubkey: b64(pubRawB) });
    }
    await fetchJSON('/api/e2e/keys/upload', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token },
      body: JSON.stringify({
        identity_pubkey: b64(myIdentityPubRaw),
        fingerprint: myFingerprint,
        prekeys: batch,
      }),
    });
  }

  // ---------- X3DH 握手（发起方 A → B，B 可离线） ----------
  async function initiateSession(peerUsername) {
    // 取对方身份公钥
    const keys = await fetchJSON('/api/e2e/keys', { headers: { Authorization: 'Bearer ' + token } });
    const peer = keys.keys.find(k => k.username === peerUsername);
    if (!peer) throw new Error('对方尚未上传 E2E 公钥');
    const peerIK = await importPub(unb64(peer.identity_pubkey));
    // 消耗对方一个预密钥（离线首次握手）
    let opk = null;
    try {
      opk = await fetchJSON('/api/e2e/prekey/' + encodeURIComponent(peerUsername),
        { headers: { Authorization: 'Bearer ' + token } });
    } catch (e) { throw new Error('对方暂无可用预密钥（请对方上线补充）: ' + e.message); }
    const peerOPK = await importPub(unb64(opk.pubkey));
    // 临时密钥 EK
    const ek = await genECDH();
    const ekPrivRaw = await privRaw(ek);
    const ekPubRaw = await pubRaw(ek);
    const ekPriv = await importPriv(ekPrivRaw);
    // 三次 DH
    const DH1 = new Uint8Array(await dh(myIdentityPriv, peerIK));
    const DH2 = new Uint8Array(await dh(ekPriv, peerIK));
    const DH3 = new Uint8Array(await dh(ekPriv, peerOPK));
    const ikm = new Uint8Array(DH1.length + DH2.length + DH3.length);
    ikm.set(DH1, 0); ikm.set(DH2, DH1.length); ikm.set(DH3, DH1.length + DH2.length);
    const RK = await hkdf(ikm, 'root_key_v1', 32);
    const chainAB = await hkdf(RK, 'chain_A_to_B', 32); // A 发 / B 收
    const chainBA = await hkdf(RK, 'chain_B_to_A', 32); // B 发 / A 收
    const sess = {
      peer: peerUsername,
      rk: b64(RK),
      send_ck: b64(chainAB), send_seq: 0,
      recv_ck: b64(chainBA), recv_seq: 0,
      peer_ik: peer.identity_pubkey,
      initiated: true,
    };
    await putSession(sess);
    // 首条消息的 ratchet_header：含 X3DH 材料，供 B 初始化
    return {
      sess,
      header: { new: true, ik_pub: b64(myIdentityPubRaw), ek_pub: b64(ekPubRaw), opk_id: opk.prekey_id, seq: 0 }
    };
  }

  // ---------- X3DH 响应方 B 首次收到 ----------
  async function deriveReceiveSession(senderUsername, header) {
    if (!header.new) return null; // 既有会话由调用方从库取
    // 取对方身份公钥（header.ik_pub 即可）
    const theirIK = await importPub(unb64(header.ik_pub));
    const theirEK = await importPub(unb64(header.ek_pub));
    // 取自己对应 opk_id 的私钥（一次性预密钥，封装存盘 → 解封）
    const opkRec = await idbGet('prekeys', header.opk_id);
    if (!opkRec) throw new Error('本地无此预密钥（可能已在其他设备消耗）');
    let opkPrivRaw;
    if (opkRec.iv) {
      opkPrivRaw = await unwrapPriv(opkRec.priv, opkRec.iv);
    } else {
      opkPrivRaw = unb64(opkRec.priv); // 旧版明文兼容
    }
    const myOPKpriv = await importPriv(opkPrivRaw);
    // 严格对齐发起方推导：
    //   发起方: DH1=IK_my·IK_them, DH2=EK_my·IK_them, DH3=EK_my·OPK_them
    //   响应方: DH1=IK_my·IK_them, DH2=IK_my·EK_them, DH3=OPK_my·EK_them  (对称等价)
    const DH1b = new Uint8Array(await dh(myIdentityPriv, theirIK));
    const DH2b = new Uint8Array(await dh(myIdentityPriv, theirEK));
    const DH3b = new Uint8Array(await dh(myOPKpriv, theirEK));
    const ikm = new Uint8Array(DH1b.length + DH2b.length + DH3b.length);
    ikm.set(DH1b, 0); ikm.set(DH2b, DH1b.length); ikm.set(DH3b, DH1b.length + DH2b.length);
    const RK = await hkdf(ikm, 'root_key_v1', 32);
    const chainAB = await hkdf(RK, 'chain_A_to_B', 32);
    const chainBA = await hkdf(RK, 'chain_B_to_A', 32);
    // B 是响应方：B 发用 chainBA, B 收用 chainAB（与 A 对齐）
    const sess = {
      peer: senderUsername,
      rk: b64(RK),
      send_ck: b64(chainBA), send_seq: 0,
      recv_ck: b64(chainAB), recv_seq: 0,
      peer_ik: header.ik_pub,
      initiated: false,
    };
    await putSession(sess);
    await idbDel('prekeys', header.opk_id); // 一次性预密钥用后即删
    return sess;
  }

  // ---------- 发送：信封加密给多接收方 ----------
  async function encryptForRecipients(plaintext, memberList) {
    if (!memberList || !memberList.length) throw new Error('暂无可用的 E2E 成员');
    // 1. 随机消息密钥 K 加密正文
    const kMsg = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const kMsgRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kMsg));
    const ciphertext = b64(await aesGcmEncrypt(kMsgRaw, enc.encode(plaintext)));
    // 2. 每个接收方用各自链派生的 mk 加密 K
    const recipients = [];
    for (const peer of memberList) {
      let sess = await getSession(peer);
      let header;
      if (!sess) {
        // 首次：X3DH 握手
        const init = await initiateSession(peer);
        sess = init.sess;
        header = init.header;
      }
      // ratchet 步进派生 mk
      const { mk, next } = await ratchetStep(unb64(sess.send_ck));
      sess.send_ck = b64(next);
      sess.send_seq = sess.send_seq + 1;
      await putSession(sess);
      // 用 mk 加密 K
      const encKey = b64(await aesGcmEncrypt(mk, kMsgRaw));
      recipients.push({ username: peer, enc_key: encKey, ratchet_header: JSON.stringify(header || { new: false, seq: sess.send_seq - 1 }) });
    }
    return { ciphertext, recipients };
  }

  // ---------- 接收：解密 ----------
  async function decryptIncoming(msg) {
    const { sender, ciphertext, enc_key, ratchet_header } = msg;
    let header;
    try { header = JSON.parse(ratchet_header); } catch (e) { header = { new: false, seq: 0 }; }
    let sess = await getSession(sender);
    if (header.new || !sess) {
      sess = await deriveReceiveSession(sender, header);
    }
    // 按 seq 步进 recv_ck（支持离线批量按顺序处理）
    const { mk, next } = await ratchetStep(unb64(sess.recv_ck));
    sess.recv_ck = b64(next);
    sess.recv_seq = sess.recv_seq + 1;
    await putSession(sess);
    // 用 mk 解 enc_key 得 K
    const kMsgRaw = await aesGcmDecrypt(mk, unb64(enc_key));
    // 用 K 解正文
    const pt = await aesGcmDecrypt(kMsgRaw, unb64(ciphertext));
    return dec.decode(pt);
  }

  // ---------- 离线消息拉取 ----------
  async function fetchOfflineMessages(onDecrypted) {
    const data = await fetchJSON('/api/e2e/messages', { headers: { Authorization: 'Bearer ' + token } });
    const msgs = data.messages || [];
    for (const m of msgs) {
      try {
        const text = await decryptIncoming(m);
        if (onDecrypted) onDecrypted({ message_id: m.message_id, sender: m.sender, text, time: m.created_at });
        // 标记已读
        fetch('/api/e2e/messages/' + encodeURIComponent(m.message_id) + '/read', {
          method: 'POST', headers: { Authorization: 'Bearer ' + token }
        }).catch(() => {});
      } catch (e) {
        console.error('离线消息解密失败', m.message_id, e);
      }
    }
    // 预密钥不足时补充（保证后续他人可与离线的我握手）
    try { await E2E.replenishPrekeys(); } catch (e) { /* 补充失败不阻塞 */ }
    return msgs.length;
  }

  // ---------- 平台密钥迁移：把口令封装升级为 PRF 封装 ----------
  async function enablePlatformKey() {
    if (!(await platformAuthAvailable())) throw new Error('当前环境无平台认证器（需 Touch ID / Windows Hello / 生物识别）');
    if (!myUsername) throw new Error('请先登录并初始化 E2E');
    if (!myIdentityPrivRaw) throw new Error('身份私钥未在内存（请重新登录后再迁移）');
    const oldWrap = myWrapKey; // 旧封装密钥（口令派生）
    // 注册平台凭据 + 评估 PRF 得新封装密钥（需生物识别）
    const newSalt = rand(16);
    const pc = await createPlatformCred(myUsername, newSalt);
    const newWrap = pc.wrapKey;
    // 1) 重封装身份私钥
    const w = await wrapWith(newWrap, myIdentityPrivRaw);
    await idbPut('keys', {
      username: myUsername, priv: w.wrapped, iv: w.iv, salt: b64(newSalt),
      pub: b64(myIdentityPubRaw), mode: 'webauthn', credId: pc.credId,
    });
    // 2) 重封装所有未消耗的预密钥
    const prekeys = await idbGetAll('prekeys');
    for (const p of prekeys) {
      let raw;
      if (p.iv && oldWrap) raw = await unwrapWith(oldWrap, p.priv, p.iv);
      else raw = unb64(p.priv); // 旧版明文
      const nw = await wrapWith(newWrap, raw);
      await idbPut('prekeys', { id: p.id, priv: nw.wrapped, iv: nw.iv, pub: p.pub });
    }
    // 3) 重封装所有 ratchet 会话
    const sessions = await idbGetAll('sessions');
    for (const s of sessions) {
      let payload;
      if (s.blob && oldWrap) payload = await unwrapWith(oldWrap, s.blob, s.iv);
      else payload = enc.encode(JSON.stringify({
        rk: s.rk, send_ck: s.send_ck, send_seq: s.send_seq,
        recv_ck: s.recv_ck, recv_seq: s.recv_seq, peer_ik: s.peer_ik, initiated: s.initiated,
      })); // 旧版明文
      const nw = await wrapWith(newWrap, payload);
      await idbPut('sessions', { peer: s.peer, iv: nw.iv, blob: nw.wrapped });
    }
    myWrapKey = newWrap;
    protectionMode = 'webauthn';
    return { enabled: true, credId: pc.credId };
  }

  // ---------- 暴露 API ----------
  return {
    setToken(t) { token = t; },
    getUsername() { return myUsername; },
    getFingerprint() { return myFingerprint; },
    getProtectionMode() { return protectionMode; },
    isPlatformAvailable: platformAuthAvailable,
    /** 登录/注册成功后调用：解锁/生成身份密钥并上传公钥+预密钥 */
    async init(username, password) {
      await ensureIdentity(username, password);
      // 上传身份公钥（即使已有也刷新指纹；预密钥仅在首次生成时上传）
      await fetchJSON('/api/e2e/keys/upload', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token },
        body: JSON.stringify({
          identity_pubkey: b64(myIdentityPubRaw),
          fingerprint: myFingerprint,
          prekeys: [], // 已在 ensureIdentity 首次上传
        }),
      });
      return { fingerprint: myFingerprint, mode: protectionMode };
    },
    /** 升级到平台密钥封装（一键迁移，无需重输口令；私钥已在内存） */
    enablePlatformKey,
    /** 拉取已支持 E2E 的成员（发送时作为接收方） */
    async getMembers() {
      const d = await fetchJSON('/api/e2e/members', { headers: { Authorization: 'Bearer ' + token } });
      return d.members || [];
    },
    encryptForRecipients,
    decryptIncoming,
    fetchOfflineMessages,
    async prekeyCount() {
      try {
        const d = await fetchJSON('/api/e2e/prekey-count', { headers: { Authorization: 'Bearer ' + token } });
        return d.count;
      } catch (e) { return -1; }
    },
    /** 预密钥不足时自动补充（保证离线首次握手可用） */
    async replenishPrekeys(threshold = 5, batch = 20) {
      let cnt = await E2E.prekeyCount();
      if (cnt < 0) return -1; // 接口不可用
      if (cnt >= threshold) return cnt;
      await generateAndUploadPrekeys(batch);
      return await E2E.prekeyCount();
    },
  };
})();
