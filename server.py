"""
ESG碳核算助手 4.0 — FastAPI 后端服务
多用户、JWT认证、SQLite数据库、局域网访问
启动: python server.py
访问: http://localhost:8000
"""
import json, os, sqlite3, hashlib, secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
import uvicorn

# ============ 配置 ============
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "esg_4_0.db"
HTML_PATH = BASE_DIR / "ESG碳核算助手4.0.html"
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)  # 生产环境用环境变量固定，避免重启后 token 失效
TOKEN_EXPIRE_DAYS = 7

# ============ 数据库 ============
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            company TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL, company_name TEXT DEFAULT '',
            accounting_year TEXT DEFAULT '', standard TEXT DEFAULT 'GHG',
            grid_region TEXT DEFAULT '全国平均', industry TEXT DEFAULT '通用',
            revenue REAL DEFAULT 0, output_quantity REAL DEFAULT 0,
            intensity_unit TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS activity_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            source_key TEXT NOT NULL, value REAL DEFAULT 0,
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(project_id, source_key)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, project_id INTEGER,
            action TEXT NOT NULL, entity_type TEXT DEFAULT '',
            entity_key TEXT DEFAULT '', old_value TEXT DEFAULT '',
            new_value TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            version_name TEXT NOT NULL, snapshot_data TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )""")

# ============ 密码工具 ============
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, h = hashed.split('$')
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == h
    except Exception:
        return False

# ============ JWT工具（简化版） ============
import base64 as b64
def create_token(user_id: int) -> str:
    payload = f"{user_id}|{datetime.utcnow().isoformat()}|{TOKEN_EXPIRE_DAYS}"
    signature = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()[:16]
    token = b64.urlsafe_b64encode((payload + "|" + signature).encode()).decode().rstrip("=")
    return token

def verify_token(token: str) -> Optional[int]:
    try:
        # 补齐base64 padding
        padding = 4 - len(token) % 4
        if padding != 4: token += "=" * padding
        decoded = b64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.rsplit("|", 1)
        if len(parts) != 2: return None
        payload, signature = parts
        expected = hashlib.sha256((payload + SECRET_KEY).encode()).hexdigest()[:16]
        if signature != expected: return None
        user_id_str, issued_str, _ = payload.split("|", 2)
        issued = datetime.fromisoformat(issued_str)
        if datetime.utcnow() - issued > timedelta(days=TOKEN_EXPIRE_DAYS): return None
        return int(user_id_str)
    except Exception:
        return None

# ============ 认证依赖 ============
async def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    token = auth[7:]
    user_id = verify_token(token)
    if user_id is None:
        raise HTTPException(401, "登录已过期，请重新登录")
    with get_db() as db:
        user = db.execute("SELECT id,username,email,company FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(401, "用户不存在")
        return dict(user)

# ============ FastAPI 应用 ============
app = FastAPI(title="ESG碳核算助手 4.0 API", version="4.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ============ 请求模型 ============
class RegisterBody(BaseModel):
    username: str
    password: str
    email: str = ""
    company: str = ""

class LoginBody(BaseModel):
    username: str
    password: str

class ProjectBody(BaseModel):
    name: str
    company_name: str = ""
    accounting_year: str = ""
    standard: str = "GHG"
    grid_region: str = "全国平均"
    industry: str = "通用"
    revenue: float = 0
    output_quantity: float = 0
    intensity_unit: str = ""

class ActivityDataBody(BaseModel):
    data: dict  # {source_key: value}

# ============ 认证 API ============
@app.post("/api/register")
def register(body: RegisterBody):
    if len(body.username) < 2: raise HTTPException(400, "用户名至少2个字符")
    if len(body.password) < 4: raise HTTPException(400, "密码至少4个字符")
    with get_db() as db:
        existing = db.execute("SELECT id FROM users WHERE username=?", (body.username,)).fetchone()
        if existing: raise HTTPException(400, "用户名已存在")
        db.execute("INSERT INTO users(username,email,password_hash,company) VALUES(?,?,?,?)",
                   (body.username, body.email, hash_password(body.password), body.company))
    return {"ok": True, "msg": "注册成功"}

@app.post("/api/login")
def login(body: LoginBody):
    with get_db() as db:
        user = db.execute("SELECT id,username,email,company,password_hash FROM users WHERE username=?",
                          (body.username,)).fetchone()
        if not user or not verify_password(body.password, user["password_hash"]):
            raise HTTPException(401, "用户名或密码错误")
        token = create_token(user["id"])
        return {"ok": True, "token": token, "user": {"id": user["id"], "username": user["username"],
                "email": user["email"], "company": user["company"]}}

@app.get("/api/me")
def me(user: dict = Depends(get_current_user)):
    return {"ok": True, "user": user}

# ============ 项目 API ============
@app.get("/api/projects")
def list_projects(user: dict = Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute("SELECT * FROM projects WHERE user_id=? ORDER BY updated_at DESC",
                          (user["id"],)).fetchall()
        return [dict(r) for r in rows]

@app.post("/api/projects")
def create_project(body: ProjectBody, user: dict = Depends(get_current_user)):
    if not body.name.strip(): raise HTTPException(400, "项目名称不能为空")
    with get_db() as db:
        cur = db.execute("""INSERT INTO projects(user_id,name,company_name,accounting_year,standard,
            grid_region,industry,revenue,output_quantity,intensity_unit)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (user["id"], body.name, body.company_name, body.accounting_year, body.standard,
             body.grid_region, body.industry, body.revenue, body.output_quantity, body.intensity_unit))
        pid = cur.lastrowid
        db.execute("INSERT INTO audit_logs(user_id,project_id,action,entity_type,entity_key,new_value) VALUES(?,?,?,?,?,?)",
                   (user["id"], pid, "创建项目", "project", str(pid), json.dumps(body.model_dump(), ensure_ascii=False)))
    return {"ok": True, "id": pid}

@app.get("/api/projects/{pid}")
def get_project(pid: int, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        return dict(p)

@app.put("/api/projects/{pid}")
def update_project(pid: int, body: ProjectBody, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        db.execute("""UPDATE projects SET name=?,company_name=?,accounting_year=?,standard=?,
            grid_region=?,industry=?,revenue=?,output_quantity=?,intensity_unit=?,
            updated_at=datetime('now','localtime') WHERE id=?""",
            (body.name, body.company_name, body.accounting_year, body.standard,
             body.grid_region, body.industry, body.revenue, body.output_quantity,
             body.intensity_unit, pid))
        db.execute("INSERT INTO audit_logs(user_id,project_id,action,entity_type,entity_key,new_value) VALUES(?,?,?,?,?,?)",
                   (user["id"], pid, "更新项目", "project", str(pid), json.dumps(body.model_dump(), ensure_ascii=False)))
    return {"ok": True}

@app.delete("/api/projects/{pid}")
def delete_project(pid: int, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT id FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        db.execute("DELETE FROM activity_data WHERE project_id=?", (pid,))
        db.execute("DELETE FROM snapshots WHERE project_id=?", (pid,))
        db.execute("DELETE FROM projects WHERE id=?", (pid,))
        db.execute("INSERT INTO audit_logs(user_id,project_id,action,entity_type,entity_key) VALUES(?,?,?,?,?)",
                   (user["id"], pid, "删除项目", "project", str(pid)))
    return {"ok": True}

# ============ 活动数据 API ============
@app.get("/api/projects/{pid}/data")
def get_activity_data(pid: int, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT id FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        rows = db.execute("SELECT source_key, value FROM activity_data WHERE project_id=?", (pid,)).fetchall()
        return {r["source_key"]: r["value"] for r in rows}

@app.put("/api/projects/{pid}/data")
def save_activity_data(pid: int, body: ActivityDataBody, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT id FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        for key, value in body.data.items():
            old_row = db.execute("SELECT value FROM activity_data WHERE project_id=? AND source_key=?",
                                 (pid, key)).fetchone()
            old_val = str(old_row["value"]) if old_row else "0"
            new_val = str(value)
            db.execute("""INSERT INTO activity_data(project_id,source_key,value,updated_at)
                VALUES(?,?,?,datetime('now','localtime'))
                ON CONFLICT(project_id,source_key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                (pid, key, float(value)))
            if old_val != new_val:
                db.execute("INSERT INTO audit_logs(user_id,project_id,action,entity_type,entity_key,old_value,new_value) VALUES(?,?,?,?,?,?,?)",
                           (user["id"], pid, "更新数据", "activity", key, old_val, new_val))
        db.execute("UPDATE projects SET updated_at=datetime('now','localtime') WHERE id=?", (pid,))
    return {"ok": True}

# ============ 快照 API ============
@app.post("/api/projects/{pid}/snapshots")
def create_snapshot(pid: int, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT id FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        version_name = "V_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        data_rows = db.execute("SELECT source_key, value FROM activity_data WHERE project_id=?", (pid,)).fetchall()
        snapshot_data = json.dumps({r["source_key"]: r["value"] for r in data_rows}, ensure_ascii=False)
        db.execute("INSERT INTO snapshots(project_id,version_name,snapshot_data) VALUES(?,?,?)",
                   (pid, version_name, snapshot_data))
        db.execute("INSERT INTO audit_logs(user_id,project_id,action,entity_type,entity_key) VALUES(?,?,?,?,?)",
                   (user["id"], pid, "创建快照", "snapshot", version_name))
    return {"ok": True, "version_name": version_name}

@app.get("/api/projects/{pid}/snapshots")
def list_snapshots(pid: int, user: dict = Depends(get_current_user)):
    with get_db() as db:
        p = db.execute("SELECT id FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
        if not p: raise HTTPException(404, "项目不存在")
        rows = db.execute("SELECT id, version_name, created_at FROM snapshots WHERE project_id=? ORDER BY created_at DESC LIMIT 50", (pid,)).fetchall()
        return [dict(r) for r in rows]

# ============ 审计日志 API ============
@app.get("/api/audit-logs")
def get_audit_logs(project_id: Optional[int] = None, user: dict = Depends(get_current_user)):
    with get_db() as db:
        if project_id:
            rows = db.execute(
                "SELECT * FROM audit_logs WHERE user_id=? AND project_id=? ORDER BY created_at DESC LIMIT 200",
                (user["id"], project_id)).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM audit_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 200",
                (user["id"],)).fetchall()
        return [dict(r) for r in rows]

# ============ 排放因子 API ============
@app.get("/api/factors")
def get_factors():
    ELECTRICITY_GRID_FACTORS = {
        '全国平均': 0.5703, '华北': 0.5768, '东北': 0.5568, '华东': 0.5568,
        '华中': 0.5257, '西北': 0.4405, '南方': 0.4035, '西南': 0.2258, '西藏': 0.0234
    }
    FUEL_FACTOR_TON = {"coal": 1.900, "coke": 2.860, "lpg": 3.101, "gasoline": 2.925, "diesel": 3.096}
    return {
        "gridFactors": ELECTRICITY_GRID_FACTORS,
        "fuelFactors": FUEL_FACTOR_TON,
        "gasFactor": 2.162,
        "heatFactor": 0.11,
        "scope3Factors": {"business_travel": 0.00018, "employee_commute": 0.00015, "upstream_transport": 0.00010, "waste": 0.50}
    }

# ============ 静态文件服务 ============
@app.get("/")
def serve_frontend():
    if HTML_PATH.exists():
        return FileResponse(str(HTML_PATH), media_type="text/html; charset=utf-8")
    return JSONResponse({"ok": True, "msg": "ESG碳核算助手 4.0 API 服务运行中", "docs": "/docs"}, status_code=200)

# Swagger文档
@app.get("/docs", include_in_schema=False)
def api_docs():
    return JSONResponse({"swagger": "访问 /docs 查看API文档"}, status_code=200)

# ============ 启动 ============
if __name__ == "__main__":
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    init_db()
    print()
    print("=" * 55)
    print("  ESG碳核算助手 4.0 -- 后端服务")
    print("=" * 55)
    print()
    print("  本地访问:  http://localhost:8000")
    print("  API文档:   http://localhost:8000/docs")
    print()
    # 获取局域网IP
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
        print(f"  局域网访问: http://{lan_ip}:8000")
        print(f"  (同一WiFi下的设备输入上面地址即可访问)")
    except Exception:
        pass
    print()
    print("  按 Ctrl+C 停止服务")
    print("=" * 55)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), log_level="info")
