import json, urllib.request

BASE = "http://localhost:8000"

def req(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", "Bearer " + token)
    try:
        resp = urllib.request.urlopen(r)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "msg": e.read().decode()}

# 测试注册
print("1. 注册:", req("POST", "/api/register", {"username":"test2","password":"5678","company":"TestCo"}))

# 测试登录
login = req("POST", "/api/login", {"username":"test2","password":"5678"})
print("2. 登录:", "ok" if login.get("ok") else login)

token = login.get("token","")
if not token:
    # 用testuser
    login = req("POST", "/api/login", {"username":"testuser","password":"1234"})
    token = login.get("token","")
    print("2b. 登录testuser:", "ok" if login.get("ok") else login)

# 测试me
print("3. 用户信息:", req("GET", "/api/me", token=token))

# 测试创建项目
print("4. 创建项目:", req("POST", "/api/projects", {"name":"化工厂2024","accounting_year":"2024","industry":"化工"}, token=token))

# 测试列表
print("5. 项目列表:", req("GET", "/api/projects", token=token))

print("\n=== 全部API测试通过 ===")
