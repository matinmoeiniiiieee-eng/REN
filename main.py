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
    # Persistent-volume directory. On Render/Railway the default filesystem is
    # ephemeral, so redeploys/cold-starts wipe ren_data.json. Point DATA_DIR at
    # a mounted disk/volume (e.g. /var/data on Render, /data on Railway) and the
    # state file is stored there instead, surviving restarts. Empty = legacy
    # behaviour (data_file resolved next to main.py).
    data_dir: str = ""
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
# Network / Proxy tuning
# ==========================================
# uTLS fingerprint advertised in share links (chrome blends best with CDN traffic).
DEFAULT_FINGERPRINT = os.environ.get("REN_FINGERPRINT", "chrome").strip() or "chrome"
# WebSocket early-data budget (bytes) advertised via the `ed` path param.
EARLY_DATA_MAX = 2048
# Upstream TCP socket buffer size; modest so we stay inside PaaS memory limits.
SOCKET_BUFFER_BYTES = 262144
# Downstream read buffer bounds (adaptive between these two).
DOWNSTREAM_MIN_BUF = 16384
DOWNSTREAM_MAX_BUF = 262144

# ---- gRPC ("gun") transport tuning ------------------------------------------
# serviceName advertised in gRPC share links is "<prefix>/<uuid>", which maps to
# the request path "/<prefix>/<uuid>/Tun". Keeping the uuid in the path lets us
# route per-link (like the WS path) while the VLESS header remains the source of
# truth for authentication.
GRPC_SERVICE_PREFIX = (os.environ.get("REN_GRPC_PREFIX", "grpc").strip("/") or "grpc")
# Cap a single decoded VLESS-header buffer so a malformed stream can't grow it
# without bound before the header is recognised.
GRPC_HEADER_MAX = 2048

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
    # A persistent volume (DATA_DIR) always wins: the state file lives inside it
    # under its basename, so operators only have to mount a disk and set one env
    # var to get durable storage across Render/Railway restarts.
    filename = os.path.basename(CONFIG.data_file) or "ren_data.json"
    data_dir = (CONFIG.data_dir or "").strip()
    if data_dir:
        return os.path.join(data_dir, filename)
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

async def prune_state_task():
    # Sessions and login-attempt buckets are only cleaned lazily on access, so
    # abandoned tokens / one-off attacker IPs would accumulate forever. Sweep them
    # hourly to keep memory flat on long-lived free-tier instances.
    while True:
        await asyncio.sleep(3600)
        now = time.time()
        for tok in [t for t, exp in list(SESSIONS.items()) if exp < now]:
            SESSIONS.pop(tok, None)
        window = CONFIG.login_window_seconds
        for ip in list(login_attempts.keys()):
            recent = [t for t in login_attempts.get(ip, []) if now - t < window]
            if recent:
                login_attempts[ip] = recent
            else:
                login_attempts.pop(ip, None)

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

def grpc_service_name(uuid: str) -> str:
    """serviceName carried in gRPC share links (maps to path /<prefix>/<uuid>)."""
    return f"{GRPC_SERVICE_PREFIX}/{uuid}"

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None,
                        transport: str = "ws") -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain

    if transport == "grpc":
        # gRPC ("gun") transport rides HTTP/2. The client opens a bidirectional
        # gRPC stream at /<serviceName>/Tun; the VLESS request header travels in
        # the first Hunk message, exactly like the WS first frame. `alpn=h2` is
        # required so the TLS/ALPN negotiation selects HTTP/2. Fully compatible
        # with v2rayNG / sing-box gRPC (gun mode) configs.
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "grpc",
            "serviceName": grpc_service_name(uuid),
            "mode": "gun",
            "authority": domain,
            "sni": domain,
            "fp": DEFAULT_FINGERPRINT,
            "alpn": "h2",
            "allowInsecure": "0",
        }
    else:
        # WebSocket early-data (0-RTT): the client carries the first chunk (which
        # holds the VLESS request header) inside the `Sec-WebSocket-Protocol`
        # upgrade header. This shaves a round-trip AND blends the handshake into
        # ordinary CDN traffic, which helps under DPI. Clients that don't
        # understand `ed` simply ignore it and send data as normal frames -> the
        # server handles both paths, so it stays fully compatible with standard
        # v2rayNG / Nekobox / sing-box configs.
        path = f"/ws/{uuid}?ed={EARLY_DATA_MAX}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "headerType": "none",
            "host": domain,
            "path": path,
            "sni": domain,
            "fp": DEFAULT_FINGERPRINT,
            "alpn": "http/1.1",
            "allowInsecure": "0",
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
        asyncio.create_task(prune_state_task()),
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
    return {
        "uuid": uid,
        "label": label,
        "vless_link": generate_vless_link(uid, remark=f"REN-{label}"),
        "vless_link_grpc": generate_vless_link(uid, remark=f"REN-{label}-gRPC", transport="grpc"),
    }

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
            "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}"),
            "vless_link_grpc": generate_vless_link(uid, remark=f"REN-{data['label']}-gRPC", transport="grpc"),
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

    # Offer both transports for the main server and every custom address so
    # clients can pick whichever survives their network (WS or gRPC/gun).
    sub_links = [
        generate_vless_link(uid, remark=f"REN-{link['label']}-WS"),
        generate_vless_link(uid, remark=f"REN-{link['label']}-gRPC", transport="grpc"),
    ]
    for i, addr in enumerate(CUSTOM_ADDRESSES):
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}-WS", address=addr))
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}-gRPC", address=addr, transport="grpc"))

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
def decode_early_data(subprotocol_header: str | None) -> bytes:
    """Decode WebSocket 0-RTT early data from the Sec-WebSocket-Protocol header.

    Xray/sing-box carry the first stream chunk as URL-safe base64 (no padding) in
    that header when `ed=` is set. If the value isn't valid base64 (i.e. it is a
    genuine subprotocol name), we return b"" and let the normal frame path run,
    so non-early-data clients are unaffected.
    """
    if not subprotocol_header:
        return b""
    token = subprotocol_header.split(",")[0].strip()
    if not token:
        return b""
    try:
        padded = token + "=" * (-len(token) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return b""


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

# --- Shared transport helpers (reused by both the WS and gRPC tunnels) -------
def _apply_socket_opts(writer: asyncio.StreamWriter):
    """Tune an upstream TCP socket: keepalive, no-Nagle, modest buffers."""
    try:
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Disable Nagle: tunnelled traffic is already framed, so coalescing
            # adds latency (esp. for interactive TLS records) with no benefit.
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Modest, PaaS-friendly socket buffers for smoother bulk throughput.
            for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, opt, SOCKET_BUFFER_BYTES)
                except OSError:
                    pass
    except Exception:
        pass

async def open_upstream(address: str, port: int):
    """Open the destination TCP connection and apply socket tuning.

    Shared by the WebSocket and gRPC engines so both transports get identical
    connect behaviour, timeouts and socket options.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port), timeout=10.0
    )
    _apply_socket_opts(writer)
    return reader, writer

def account_traffic(conn_id: str | None, uid: str, size: int, is_request: bool = False):
    """Record byte accounting for a transferred chunk (transport-agnostic).

    Consolidates the global stats counters, per-connection byte tally, hourly
    traffic histogram and per-link usage that the WS and gRPC pumps both need.
    """
    stats["total_bytes"] += size
    if is_request:
        stats["total_requests"] += 1
    if conn_id and conn_id in connections:
        connections[conn_id]["bytes"] += size
    hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += size
    if uid in LINKS:
        LINKS[uid]["used_bytes"] += size

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

            account_traffic(conn_id, link_uid, size, is_request=True)

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
    buf_size = DOWNSTREAM_MIN_BUF
    try:
        while True:
            data = await asyncio.wait_for(reader.read(buf_size), IDLE_TIMEOUT)
            if not data:
                break
            size = len(data)

            # Dynamically adjust buffer based on throughput saturation: grow when we
            # keep filling the buffer (bulk transfer), shrink when reads run small
            # (interactive/idle) so we don't pin large buffers per idle connection.
            if size == buf_size and buf_size < DOWNSTREAM_MAX_BUF:
                buf_size = min(DOWNSTREAM_MAX_BUF, buf_size * 2)
            elif size < buf_size / 2 and buf_size > DOWNSTREAM_MIN_BUF:
                buf_size = max(DOWNSTREAM_MIN_BUF, buf_size // 2)

            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            account_traffic(conn_id, link_uid, size)

            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except (asyncio.TimeoutError, WebSocketDisconnect):
        pass
    except Exception:
        pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    # WebSocket 0-RTT: pull any early data out of the subprotocol header and echo
    # the token back on accept so strict clients/CDNs finish the handshake.
    subproto = websocket.headers.get("sec-websocket-protocol")
    early_data = decode_early_data(subproto)
    if subproto:
        await websocket.accept(subprotocol=subproto.split(",")[0].strip())
    else:
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

        # Seed with 0-RTT early data (may already hold the full VLESS header).
        buffer = early_data
        command = port = address = initial_payload = None
        while True:
            if buffer:
                parsed = await parse_vless_header(buffer, expected_bytes)
                if parsed is not None:
                    command, address, port, initial_payload = parsed
                    break
                if len(buffer) > 2048:
                    raise ValueError("Header overflow")
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

        # SSRF hardening: refuse internal / metadata destinations.
        if not await destination_allowed(address, port):
            await websocket.close(code=1008, reason="destination not allowed")
            return

        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        ip_ref_count[uuid][client_ip] += 1

        account_traffic(conn_id, uuid, len(buffer), is_request=True)

        # Reuse the shared upstream-connect helper (open_connection + socket
        # tuning) so WS and gRPC behave identically toward the destination.
        reader, writer = await open_upstream(address, port)

        if initial_payload:
            account_traffic(conn_id, uuid, len(initial_payload))
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        # Await the cancelled halves so their teardown (write_eof, etc.) completes
        # and no orphaned tasks linger between connections.
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

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
# gRPC ("gun") Transport Engine
# ==========================================
# VLESS-over-gRPC rides HTTP/2. The client opens a bidirectional gRPC stream at
# /<serviceName>/Tun and sends the VLESS stream wrapped in protobuf `Hunk`
# messages, each prefixed by the 5-byte gRPC length-prefix framing:
#
#   [ 1 byte compression flag ][ 4 byte big-endian length ][ Hunk protobuf ]
#
# `Hunk` / `MultiHunk` (Xray "gun" proto) is simply:  bytes data = 1;  so a Hunk
# is  0x0a <varint len> <payload>. We decode payloads back into the raw VLESS
# byte stream (reusing parse_vless_header + open_upstream + account_traffic) and
# re-frame the upstream response the same way on the way out.
#
# Implemented as a raw-ASGI app (mounted at /grpc) so we control the HTTP/2
# response directly. NOTE: hypercorn does not implement the ASGI response
# trailers extension, so we cannot emit a `grpc-status` trailer; the gun tunnel
# does not require it (data flows over DATA frames) and the stream is closed
# with a normal final body event.

def _read_varint(buf, pos: int):
    result = 0
    shift = 0
    n = len(buf)
    while pos < n:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("truncated varint")

def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def _decode_hunk(msg: bytes) -> bytes:
    """Extract the concatenated `data` (field 1) bytes from a Hunk/MultiHunk."""
    pos = 0
    n = len(msg)
    parts = []
    while pos < n:
        tag = msg[pos]
        pos += 1
        field = tag >> 3
        wire = tag & 0x07
        if wire == 2:  # length-delimited
            length, pos = _read_varint(msg, pos)
            val = msg[pos:pos + length]
            pos += length
            if field == 1:
                parts.append(val)
        elif wire == 0:  # varint
            _, pos = _read_varint(msg, pos)
        elif wire == 5:  # 32-bit
            pos += 4
        elif wire == 1:  # 64-bit
            pos += 8
        else:
            break
    return b"".join(parts)

def grpc_encode_frame(data: bytes) -> bytes:
    """Wrap raw stream bytes into a single length-prefixed gRPC Hunk frame."""
    hunk = b"\x0a" + _encode_varint(len(data)) + data
    return b"\x00" + len(hunk).to_bytes(4, "big") + hunk

class GrpcFrameDecoder:
    """Incremental decoder: feed HTTP/2 body chunks, get raw VLESS payloads.

    Handles gRPC length-prefixed messages that span multiple chunks and yields
    the inner `data` bytes of each Hunk once a full message is buffered.
    """
    def __init__(self):
        self._buf = bytearray()

    def feed(self, chunk: bytes):
        out = []
        if chunk:
            self._buf.extend(chunk)
        while len(self._buf) >= 5:
            length = int.from_bytes(self._buf[1:5], "big")
            if len(self._buf) < 5 + length:
                break
            msg = bytes(self._buf[5:5 + length])
            del self._buf[:5 + length]
            # Compression flag (self._buf[0] before delete) is ignored: we
            # advertise identity encoding, so no decompression is required.
            out.append(_decode_hunk(msg))
        return out


class _GrpcConn:
    """Handle stored in connection_sockets so close_connections_for_link() can
    tear a gRPC tunnel down (link deletion) the same way it closes a WebSocket.
    """
    def __init__(self):
        self.closed = asyncio.Event()

    async def close(self, code: int = 1000, reason: str = ""):
        self.closed.set()


def _grpc_client_ip(scope) -> str:
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            return value.decode("latin1").split(",")[0].strip()
    client = scope.get("client")
    if client:
        return client[0]
    return "unknown"

async def _grpc_recv_iter(receive):
    """Yield request DATA bytes until the client half-closes or disconnects."""
    while True:
        event = await receive()
        et = event["type"]
        if et == "http.request":
            body = event.get("body") or b""
            if body:
                yield body
            if not event.get("more_body", False):
                return
        elif et == "http.disconnect":
            return

async def _grpc_send_status(send, status: int):
    """Send a bodyless HTTP response (used to reject before tunnelling starts)."""
    try:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/grpc")],
        })
        await send({"type": "http.response.body", "body": b"", "more_body": False})
    except Exception:
        pass

async def grpc_tunnel_asgi(scope, receive, send):
    """Raw-ASGI VLESS-over-gRPC tunnel. Mounted at /grpc (path: /<uuid>/Tun)."""
    if scope["type"] != "http":
        return
    if scope.get("method") != "POST":
        await _grpc_send_status(send, 405)
        return

    # Mounted under /grpc, so scope["path"] is "/<uuid>/<method>" (method is
    # typically "Tun"; "TunMulti" is also accepted since our framing is a
    # superset). The uuid identifies the link, mirroring the WS path.
    parts = [p for p in scope.get("path", "").split("/") if p]
    if not parts:
        await _grpc_send_status(send, 404)
        return
    uuid = parts[0]

    writer = None
    conn_id = None
    conn_handle = _GrpcConn()
    client_ip = _grpc_client_ip(scope)
    started = False
    try:
        link_data = LINKS.get(uuid)
        if not link_data or not link_data["active"] or is_expired(link_data):
            await _grpc_send_status(send, 404)
            return

        max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = ip_ref_count.get(uuid, {}).get(client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uuid) >= max_conn:
                await _grpc_send_status(send, 429)
                return

        expected_bytes = link_data.get("uuid_bytes")
        if not expected_bytes:
            expected_bytes = uuid_lib.UUID(uuid).bytes
            link_data["uuid_bytes"] = expected_bytes

        decoder = GrpcFrameDecoder()
        recv_iter = _grpc_recv_iter(receive)

        # Phase 1: pull Hunk payloads until the VLESS header is complete. The
        # header is extracted from the first packet exactly like the WS path.
        buffer = b""
        command = address = port = initial_payload = None
        header_ready = False
        async for chunk in recv_iter:
            for data in decoder.feed(chunk):
                buffer += data
            if buffer:
                parsed = await parse_vless_header(buffer, expected_bytes)
                if parsed is not None:
                    command, address, port, initial_payload = parsed
                    header_ready = True
                    break
                if len(buffer) > GRPC_HEADER_MAX:
                    raise ValueError("Header overflow")
        if not header_ready:
            await _grpc_send_status(send, 400)
            return

        # SSRF hardening: refuse internal / metadata destinations.
        if not await destination_allowed(address, port):
            await _grpc_send_status(send, 403)
            return

        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip,
                                "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = conn_handle
        ip_ref_count[uuid][client_ip] += 1

        account_traffic(conn_id, uuid, len(buffer), is_request=True)

        reader, writer = await open_upstream(address, port)

        if initial_payload:
            account_traffic(conn_id, uuid, len(initial_payload))
            writer.write(initial_payload)
            await writer.drain()

        # Begin the gRPC response stream (HTTP/2 200 + application/grpc).
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/grpc"),
                (b"grpc-encoding", b"identity"),
                (b"grpc-accept-encoding", b"identity"),
            ],
        })
        started = True

        async def grpc_to_tcp():
            # Uplink: decode remaining Hunk payloads -> upstream socket.
            try:
                async for chunk in recv_iter:
                    for data in decoder.feed(chunk):
                        if not data:
                            continue
                        size = len(data)
                        if not await check_quota(uuid, size):
                            return
                        account_traffic(conn_id, uuid, size, is_request=True)
                        writer.write(data)
                        await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.write_eof()
                except Exception:
                    pass

        async def tcp_to_grpc():
            # Downlink: upstream socket -> length-prefixed Hunk frames.
            buf_size = DOWNSTREAM_MIN_BUF
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(buf_size), IDLE_TIMEOUT)
                    if not data:
                        break
                    size = len(data)
                    if size == buf_size and buf_size < DOWNSTREAM_MAX_BUF:
                        buf_size = min(DOWNSTREAM_MAX_BUF, buf_size * 2)
                    elif size < buf_size / 2 and buf_size > DOWNSTREAM_MIN_BUF:
                        buf_size = max(DOWNSTREAM_MIN_BUF, buf_size // 2)
                    if not await check_quota(uuid, size):
                        break
                    account_traffic(conn_id, uuid, size)
                    await send({"type": "http.response.body",
                                "body": grpc_encode_frame(data), "more_body": True})
            except Exception:
                pass

        task_up = asyncio.create_task(grpc_to_tcp())
        task_down = asyncio.create_task(tcp_to_grpc())
        watch = asyncio.create_task(conn_handle.closed.wait())
        # The connection is finished when the downlink drains (upstream closed
        # its read side) or the link is deleted. The uplink is only a feeder: a
        # client may half-close its gRPC request stream (END_STREAM) while still
        # reading the response, so uplink completion must NOT tear down the
        # still-active downlink. Hence we wait on the downlink + delete-watch.
        await asyncio.wait({task_down, watch}, return_when=asyncio.FIRST_COMPLETED)
        for t in (task_up, task_down, watch):
            if not t.done():
                t.cancel()
        await asyncio.gather(task_up, task_down, watch, return_exceptions=True)

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": f"grpc: {exc}", "time": datetime.now().isoformat()})
        if not started:
            await _grpc_send_status(send, 500)
            started = True
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        if started:
            try:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            except Exception:
                pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                remove_ip_from_link(info.get("uuid"), info.get("ip"))

# Mount the gRPC engine on the shared port. It only claims the /grpc/* prefix,
# leaving the REST API, subscription, WS and UI routes on HTTP/1.1 untouched.
app.mount("/grpc", grpc_tunnel_asgi)

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
    # Hypercorn (not uvicorn) so a single $PORT listener serves HTTP/1.1 for the
    # REST API + WebSocket transport AND HTTP/2 for the gRPC transport. Cleartext
    # HTTP/2 (h2c) is negotiated per-connection via the prior-knowledge preface or
    # the HTTP/1.1 `Upgrade: h2c` handshake, so no second port is required.
    from hypercorn.config import Config
    from hypercorn.asyncio import serve

    config = Config()
    config.bind = [f"0.0.0.0:{CONFIG.port}"]
    config.workers = 1
    config.h2_max_concurrent_streams = 256
    # Long-lived tunnels: don't let idle-timeouts kill active proxy streams.
    config.keep_alive_timeout = 3600
    asyncio.run(serve(app, config))
