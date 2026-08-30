"""E2E REST 接口集成测试 —— 针对运行中的后端 (127.0.0.1:8080)
验证零知识服务端的 E2E 接口：密钥上传/目录/成员/预密钥消耗/计数/离线消息拉取。
"""
import json
import urllib.request

BASE = "http://127.0.0.1:8080"
UA = "e2e-integration-test"


def call(method, path, token=None, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", UA)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def register(name, pw):
    s, j = call("POST", "/register", body={"username": name, "password": pw})
    return s, j


def login(name, pw):
    s, j = call("POST", "/token", body={"username": name, "password": pw})
    return s, j


def gen_fake_pubkey(name, i):
    # 真实公钥由浏览器生成；此处仅验证接口接受/存储/检索，用占位字符串
    return "PUBKEY_" + name + "_" + str(i)


def main():
    p = f = 0

    def ck(cond, msg):
        nonlocal p, f
        if cond:
            p += 1
            print("  PASS", msg)
        else:
            f += 1
            print("  FAIL", msg)

    PWA, PWB = "Alice@Test123", "Bob@Test123"
    # 注册（若已存在则忽略）
    register("alice", PWA)
    register("bob", PWB)
    print("注册 alice/bob 完成")

    # 登录拿 JWT
    sa, ja = login("alice", PWA)
    sb, jb = login("bob", PWB)
    ck(sa == 200 and "access_token" in ja, "alice 登录拿 token")
    ck(sb == 200 and "access_token" in jb, "bob 登录拿 token")
    ta, tb = ja["access_token"], jb["access_token"]

    # alice 上传身份公钥 + 5 个预密钥
    prekeysA = [{"id": "opkA_" + str(i), "pubkey": gen_fake_pubkey("alice", i)} for i in range(5)]
    s, j = call("POST", "/api/e2e/keys/upload", ta, {
        "identity_pubkey": "IK_ALICE", "fingerprint": "fp:alice", "prekeys": prekeysA})
    ck(s == 200 and j.get("prekey_count") == 5, "alice 上传公钥+5预密钥, count=5")

    # bob 上传身份公钥 + 5 个预密钥
    prekeysB = [{"id": "opkB_" + str(i), "pubkey": gen_fake_pubkey("bob", i)} for i in range(5)]
    s, j = call("POST", "/api/e2e/keys/upload", tb, {
        "identity_pubkey": "IK_BOB", "fingerprint": "fp:bob", "prekeys": prekeysB})
    ck(s == 200 and j.get("prekey_count") == 5, "bob 上传公钥+5预密钥, count=5")

    # 成员目录（alice 视角应包含 bob，不含自己）
    s, j = call("GET", "/api/e2e/members", ta)
    ck(s == 200 and "bob" in j.get("members", []) and "alice" not in j.get("members", []), "成员列表含 bob 不含自己")

    # 公钥目录
    s, j = call("GET", "/api/e2e/keys", ta)
    users = [k["username"] for k in j.get("keys", [])]
    ck(s == 200 and "alice" in users and "bob" in users, "公钥目录含 alice+bob")

    # alice 消耗 bob 一个预密钥
    s, j = call("GET", "/api/e2e/prekey/bob", ta)
    ck(s == 200 and j.get("prekey_id", "").startswith("opkB_"), "alice 消耗 bob 一个预密钥: " + str(j.get("prekey_id")))

    # bob 剩余预密钥数应为 4
    s, j = call("GET", "/api/e2e/prekey-count", tb)
    ck(s == 200 and j.get("count") == 4, "bob 剩余预密钥=4（一次性消耗）")

    # 再次消耗 bob 预密钥
    s, j = call("GET", "/api/e2e/prekey/bob", ta)
    ck(s == 200, "再次消耗 bob 预密钥成功")

    s, j = call("GET", "/api/e2e/prekey-count", tb)
    ck(s == 200 and j.get("count") == 3, "bob 剩余预密钥=3")

    # 补充预密钥
    s, j = call("POST", "/api/e2e/prekeys", tb, {"prekeys": [{"id": "opkB_new_1", "pubkey": "PK_NEW"}]})
    ck(s == 200 and j.get("prekey_count") == 4, "bob 补充预密钥后 count=4")

    # 拉取离线消息（此时应无）
    s, j = call("GET", "/api/e2e/messages", tb)
    ck(s == 200 and j.get("messages") == [], "bob 无离线消息")

    print(f"\n==== 结果: {p} 通过, {f} 失败 ====")
    return 0 if f == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
