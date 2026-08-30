"""删除测试用户 e2e_tester 与 testu1（通过应用自身 API，确保缓存与 WS 连接同步更新）"""
import json
import urllib.request
import urllib.error
import sys

BASE = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "mkhgK-G-XMlBs0ucmXzzjg"
TARGETS = ["e2e_tester", "testu1"]


def _req(method, path, payload=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# 1. 登录获取 access_token
status, body = _req("POST", "/token",
                    {"username": ADMIN_USER, "password": ADMIN_PASS})
if status != 200:
    print("LOGIN FAIL", status, body)
    sys.exit(1)
token = json.loads(body)["access_token"]
print("LOGIN OK -> token acquired")

# 2. 逐个删除目标用户
for u in TARGETS:
    status, body = _req("DELETE", "/api/admin/user/" + u,
                        {"admin_password": ADMIN_PASS}, token=token)
    print(f"DELETE {u} -> {status} {body}")

print("DONE")
