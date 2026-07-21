from __future__ import annotations

import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import socket
import ipaddress
import uuid as uuid_lib
import logging
import base64
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, APIRouter
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import uvicorn
import httpx
import psutil
from pydantic_settings import BaseSettings, SettingsConfigDict

# ==========================================
# Settings Management (pydantic-settings)
# ==========================================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    port: int = 8000
    secret_key: str = "ren-default-secret-key"
    admin_password: str = "admin"
    # Persistence: relative paths are resolved next to this file.
    data_file: str = "data/ren_data.json"
    # Security hardening toggles
    allow_private_ranges: bool = False   # if True, the tunnel may reach private/loopback ranges
    login_max_attempts: int = 5
    login_window_seconds: int = 900

CONFIG = Settings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

# ==========================================
# Static UI assets (extracted from the monolith)
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

def _load_html(name: str) -> str:
    try:
        with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as f:
            return f.read()
    except Exception as exc:
        logger.error(f"Failed to load UI asset '{name}': {exc}")
        return f"<!DOCTYPE html><html><body><h1>REN</h1><p>UI asset '{name}' is missing.</p></body></html>"

LOGIN_HTML = _load_html("login.html")
DASHBOARD_HTML = _load_html("dashboard.html")

# ==========================================
# Global State
# ==========================================
connections: dict = {}
connection_sockets: dict = {}
ip_ref_count: dict = defaultdict(lambda: defaultdict(int))

stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_DOMAIN: str = ""

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7
IDLE_TIMEOUT = 300

# Auth state: {"salt": hex, "hash": hex, "must_change": bool}
AUTH: dict = {}
SESSIONS: dict = {}

# Login brute-force protection: ip -> [failure timestamps]
login_attempts: dict = defaultdict(list)

PBKDF2_ITERATIONS = 200_000

# ==========================================
# Password Hashing & Authentication
# ==========================================
def hash_password(pw: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()

def make_auth(pw: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), "hash": hash_password(pw, salt), "must_change": False}

def verify_password(pw: str, auth: dict) -> bool:
    try:
        salt = bytes.fromhex(auth["salt"])
    except Exception:
        return False
    candidate = hash_password(pw, salt)
    return secrets.compare_digest(candidate, auth.get("hash", ""))

def init_auth():
    global AUTH
    env_pw = CONFIG.admin_password or "admin"
    AUTH = make_auth(env_pw)
    # Force a change while the operator is still on the well-known default.
    AUTH["must_change"] = (env_pw == "admin")

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    exp = SESSIONS.get(token)
    if exp is None or exp < time.time():
        SESSIONS.pop(token, None)
        return False
    return True

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def request_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window = CONFIG.login_window_seconds
    recent = [t for t in login_attempts.get(ip, []) if now - t < window]
    login_attempts[ip] = recent
    return len(recent) >= CONFIG.login_max_attempts

def record_failed_login(ip: str):
    login_attempts[ip].append(time.time())

def reset_login_attempts(ip: str):
    login_attempts.pop(ip, None)

# ==========================================
# Persistence (JSON file, stdlib only)
# ==========================================
_persist_lock = asyncio.Lock()

def _data_path() -> str:
    p = CONFIG.data_file
    return p if os.path.isabs(p) else os.path.join(BASE_DIR, p)

def save_state_sync():
    path = _data_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    export_links = {}
    for k, v in LINKS.items():
        export_links[k] = {kk: vv for kk, vv in v.items() if kk != "uuid_bytes"}
    data = {
        "links": export_links,
        "addresses": CUSTOM_ADDRESSES,
        "domain": CUSTOM_DOMAIN,
        "auth": AUTH,
        "saved_at": datetime.now().isoformat(),
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)

async def save_state():
    async with _persist_lock:
        try:
            await asyncio.to_thread(save_state_sync)
        except Exception as exc:
            logger.error(f"Failed to persist state: {exc}")

def load_state() -> bool:
    global CUSTOM_ADDRESSES, CUSTOM_DOMAIN, AUTH
    path = _data_path()
    if not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        logger.error(f"Failed to load state from {path}: {exc}")
        return False

    for k, v in (data.get("links") or {}).items():
        try:
            v["uuid_bytes"] = uuid_lib.UUID(k).bytes
            LINKS[k] = v
        except Exception:
            logger.warning(f"Skipping invalid link during load: {k}")
    addresses = data.get("addresses")
    if isinstance(addresses, list):
        CUSTOM_ADDRESSES = addresses
    if isinstance(data.get("domain"), str):
        CUSTOM_DOMAIN = data["domain"]
    if isinstance(data.get("auth"), dict) and data["auth"].get("hash"):
        AUTH = data["auth"]
        AUTH.setdefault("must_change", False)
    logger.info(f"State restored from {path}")
    return True

# ==========================================
# Background Tasks
# ==========================================
async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
        except Exception:
            pass

async def cleanup_traffic_task():
    while True:
        await asyncio.sleep(3600)
        now = datetime.now()
        keys_to_delete = []
        for k in list(hourly_traffic.keys()):
            try:
                dt = datetime.strptime(k, "%Y-%m-%d %H:00")
                if (now - dt).total_seconds() > 86400:
                    keys_to_delete.append(k)
            except Exception:
                pass
        for k in keys_to_delete:
            hourly_traffic.pop(k, None)

async def periodic_save_task():
    # Traffic/usage counters change in the hot path; flush them periodically
    # instead of on every packet to avoid I/O storms.
    while True:
        await asyncio.sleep(60)
        await save_state()

def ensure_default_link():
    if not LINKS:
        uid = str(uuid_lib.uuid4())
        LINKS[uid] = {
            "label": "Default", "limit_bytes": 0, "used_bytes": 0,
            "max_connections": 0, "created_at": datetime.now().isoformat(),
            "active": True, "expiry": "",
            "uuid_bytes": uuid_lib.UUID(uid).bytes
        }

# ==========================================
# Helpers
# ==========================================
def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return sum(ip_ref_count[uid].values())

def remove_ip_from_link(uid: str, ip: str):
    if uid in ip_ref_count and ip in ip_ref_count[uid]:
        ip_ref_count[uid][ip] -= 1
        if ip_ref_count[uid][ip] <= 0:
            ip_ref_count[uid].pop(ip, None)
            if not ip_ref_count[uid]:
                ip_ref_count.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    ip_ref_count.pop(uid, None)

# ==========================================
# SSRF hardening: block internal / metadata destinations
# ==========================================
def _ip_is_blocked(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_link_local or ip.is_private
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

async def destination_allowed(address: str, port: int) -> bool:
    if CONFIG.allow_private_ranges:
        return True
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(address, port, type=socket.SOCK_STREAM)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        if _ip_is_blocked(info[4][0]):
            return False
    return True

# ==========================================
# App + Lifespan
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)

    load_state()
    if "hash" not in AUTH:
        init_auth()
    if AUTH.get("must_change"):
        logger.warning("SECURITY: admin password is the default 'admin'. "
                       "Set a strong ADMIN_PASSWORD or change it in the panel immediately.")

    ensure_default_link()
    tasks = [
        asyncio.create_task(keep_alive()),
        asyncio.create_task(cleanup_traffic_task()),
        asyncio.create_task(periodic_save_task()),
    ]
    logger.info(f"REN started on port {CONFIG.port}")
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await save_state()
        if http_client:
            await http_client.aclose()

app = FastAPI(title="REN", docs_url=None, redoc_url=None, lifespan=lifespan)

def _allowed_origins() -> list:
    origins = set()
    dom = get_domain()
    if dom and dom != "localhost":
        origins.add(f"https://{dom}")
    railway = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
    if railway:
        origins.add(f"https://{railway.replace('https://', '').replace('http://', '')}")
    origins.add(f"http://localhost:{CONFIG.port}")
    origins.add(f"http://127.0.0.1:{CONFIG.port}")
    return list(origins)

# Same-origin dashboard only needs its own origin(s); the previous
# wildcard + credentials combination is rejected by browsers and unsafe.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

api_router = APIRouter(prefix="/api")

def _cookie_is_secure() -> bool:
    return get_domain() != "localhost"

# ==========================================
# Camouflage Routes
# ==========================================
FAKE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title><style>body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }</style></head>
<body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p></body>
</html>
"""

@app.get("/")
async def root():
    return HTMLResponse(content=FAKE_HTML, status_code=200)

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    return HTMLResponse(content=FAKE_HTML, status_code=404)

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ==========================================
# API Routes
# ==========================================
@api_router.post("/login")
async def api_login(request: Request):
    ip = request_ip(request)
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    body = await request.json()
    password = str(body.get("password") or "")
    if not verify_password(password, AUTH):
        record_failed_login(ip)
        raise HTTPException(status_code=401, detail="Invalid password")
    reset_login_attempts(ip)
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL,
                    httponly=True, samesite="lax", secure=_cookie_is_secure(), path="/")
    return resp

@api_router.post("/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    SESSIONS.pop(token, None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@api_router.get("/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    authed = await is_valid_session(token)
    return {
        "authenticated": authed,
        "must_change_password": bool(AUTH.get("must_change")) if authed else False,
    }

@api_router.post("/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global AUTH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, AUTH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    AUTH = make_auth(new)
    AUTH["must_change"] = False
    current_token = request.cookies.get(SESSION_COOKIE)
    SESSIONS.clear()
    if current_token:
        SESSIONS[current_token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@api_router.post("/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label) or not label:
        raise HTTPException(status_code=400, detail="Invalid inbound name")

    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = max(0, int(body.get("max_connections") or 0))
    expiry = compute_expiry(body.get("expiry_days"))
    uid = str(uuid_lib.uuid4())

    uid_bytes = uuid_lib.UUID(uid).bytes
    LINKS[uid] = {
        "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "created_at": datetime.now().isoformat(),
        "active": True, "expiry": expiry, "uuid_bytes": uid_bytes
    }
    await save_state()
    return {"uuid": uid, "label": label, "vless_link": generate_vless_link(uid, remark=f"REN-{label}")}

@api_router.get("/links")
async def list_links(_=Depends(require_auth)):
    result = []
    for uid, data in LINKS.items():
        active_ips = list(ip_ref_count.get(uid, {}).keys())
        result.append({
            "uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"],
            "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0),
            "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data),
            "created_at": data["created_at"], "current_connections": count_connections_for_link(uid),
            "connected_ips": active_ips,
            "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}")
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@api_router.patch("/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    if uid not in LINKS:
        raise HTTPException(status_code=404, detail="link not found")
    if "active" in body:
        LINKS[uid]["active"] = bool(body["active"])
    if "limit_value" in body:
        limit_value = float(body.get("limit_value") or 0)
        limit_unit = body.get("limit_unit") or "GB"
        LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    if "reset_usage" in body and body["reset_usage"]:
        LINKS[uid]["used_bytes"] = 0
    if "expiry_days" in body:
        LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
    if "label" in body:
        LINKS[uid]["label"] = str(body["label"])[:60]
    if "max_connections" in body:
        LINKS[uid]["max_connections"] = max(0, int(body["max_connections"] or 0))
    await save_state()
    return {"ok": True}

@api_router.delete("/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    await save_state()
    return {"ok": True}

@api_router.get("/domain")
async def get_custom_domain(_=Depends(require_auth)):
    return {"domain": CUSTOM_DOMAIN}

@api_router.post("/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    global CUSTOM_DOMAIN
    CUSTOM_DOMAIN = domain
    await save_state()
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@api_router.get("/addresses")
async def list_addresses(_=Depends(require_auth)):
    return {"addresses": list(CUSTOM_ADDRESSES)}

@api_router.post("/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address or not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Invalid address")
    if address not in CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append(address)
    await save_state()
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@api_router.delete("/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    if 0 <= index < len(CUSTOM_ADDRESSES):
        CUSTOM_ADDRESSES.pop(index)
    else:
        raise HTTPException(status_code=404, detail="Address not found")
    await save_state()
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@api_router.get("/backup")
async def export_data(_=Depends(require_auth)):
    export_links = {}
    for k, v in LINKS.items():
        clean_v = v.copy()
        clean_v.pop("uuid_bytes", None)  # Exclude pre-compiled bytes
        export_links[k] = clean_v
    return {
        "links": export_links,
        "addresses": CUSTOM_ADDRESSES,
        "domain": CUSTOM_DOMAIN,
    }

@api_router.post("/backup")
async def import_data(request: Request, _=Depends(require_auth)):
    data = await request.json()
    global LINKS, CUSTOM_ADDRESSES, CUSTOM_DOMAIN
    if "links" in data and isinstance(data["links"], dict):
        for k, v in data["links"].items():
            try:
                v["uuid_bytes"] = uuid_lib.UUID(k).bytes
                LINKS[k] = v
            except Exception:
                logger.warning(f"Skipping invalid link during import: {k}")
    if "addresses" in data and isinstance(data["addresses"], list):
        CUSTOM_ADDRESSES = data["addresses"]
    if "domain" in data and isinstance(data["domain"], str):
        CUSTOM_DOMAIN = data["domain"]
    await save_state()
    return {"ok": True}

app.include_router(api_router)

# ==========================================
# Subscription Route
# ==========================================
@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    link = LINKS.get(uid)
    if link is None:
        raise HTTPException(status_code=404, detail="link not found")
    if not link["active"] or is_expired(link):
        raise HTTPException(status_code=403, detail="link inactive or expired")

    sub_links = [generate_vless_link(uid, remark=f"REN-{link['label']}-Server")]
    for i, addr in enumerate(CUSTOM_ADDRESSES):
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}", address=addr))

    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

# ==========================================
# Core Proxy Protocol Engine (VLESS)
# ==========================================
async def parse_vless_header(buffer: bytes, expected_uuid_bytes: bytes):
    if len(buffer) < 24:
        return None

    version = buffer[0]
    if version != 0:
        raise ValueError(f"Unsupported VLESS version: {version}")

    received_uuid_bytes = buffer[1:17]
    if expected_uuid_bytes != received_uuid_bytes:
        raise ValueError("UUID mismatch")

    addon_len = buffer[17]
    pos = 18 + addon_len
    if len(buffer) < pos + 3:
        return None

    command = buffer[pos]
    pos += 1
    port = int.from_bytes(buffer[pos:pos + 2], "big")
    pos += 2
    addr_type = buffer[pos]
    pos += 1

    if addr_type == 1:
        if len(buffer) < pos + 4:
            return None
        address = ".".join(str(b) for b in buffer[pos:pos + 4])
        pos += 4
    elif addr_type == 2:
        if len(buffer) < pos + 1:
            return None
        domain_len = buffer[pos]
        pos += 1
        if len(buffer) < pos + domain_len:
            return None
        address = buffer[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(buffer) < pos + 16:
            return None
        address = ":".join(f"{buffer[i]:02x}{buffer[i+1]:02x}" for i in range(pos, pos + 16, 2))
        pos += 16
    else:
        raise ValueError(f"Unknown address type: {addr_type}")

    return command, address, port, buffer[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    link = LINKS.get(uid)
    if not link or not link["active"] or is_expired(link):
        return False
    if link["limit_bytes"] == 0:
        return True
    return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    if uid in LINKS:
        LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await asyncio.wait_for(websocket.receive(), IDLE_TIMEOUT)
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            stats["total_bytes"] += size
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += size
            await add_usage(link_uid, size)

            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, WebSocketDisconnect):
        pass
    except Exception:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    buf_size = 16384
    try:
        while True:
            data = await asyncio.wait_for(reader.read(buf_size), IDLE_TIMEOUT)
            if not data:
                break
            size = len(data)

            # Dynamically adjust buffer based on throughput saturation
            if size == buf_size and buf_size < 262144:
                buf_size *= 2
            elif size < buf_size / 2 and buf_size > 16384:
                buf_size = max(16384, int(buf_size / 2))

            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += size
            await add_usage(link_uid, size)

            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except (asyncio.TimeoutError, WebSocketDisconnect):
        pass
    except Exception:
        pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        link_data = LINKS.get(uuid)
        if not link_data or not link_data["active"] or is_expired(link_data):
            await websocket.close(code=1008, reason="forbidden")
            return

        max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = ip_ref_count.get(uuid, {}).get(client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="limit reached")
                return

        expected_bytes = link_data.get("uuid_bytes")
        if not expected_bytes:
            expected_bytes = uuid_lib.UUID(uuid).bytes
            link_data["uuid_bytes"] = expected_bytes

        buffer = b""
        command = port = address = initial_payload = None
        while True:
            try:
                first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
            except asyncio.TimeoutError:
                await websocket.close(code=1008, reason="timeout")
                return
            if first_msg["type"] == "websocket.disconnect":
                return
            chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
            if not chunk:
                continue

            buffer += chunk
            parsed = await parse_vless_header(buffer, expected_bytes)
            if parsed is not None:
                command, address, port, initial_payload = parsed
                break
            if len(buffer) > 2048:
                raise ValueError("Header overflow")

        # SSRF hardening: refuse internal / metadata destinations.
        if not await destination_allowed(address, port):
            await websocket.close(code=1008, reason="destination not allowed")
            return

        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        ip_ref_count[uuid][client_ip] += 1

        size = len(buffer)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += size
        await add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)

        try:
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                remove_ip_from_link(info.get("uuid"), info.get("ip"))

# ==========================================
# Dashboard & Login UI
# ==========================================
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG.port)
