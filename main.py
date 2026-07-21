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

# ---- XHTTP ("SplitHTTP") transport tuning -----------------------------------
# XHTTP replaces the old gRPC transport. Unlike gRPC (which needs HTTP/2
# END-TO-END and therefore broke on PaaS edges that demux HTTP/2 -> HTTP/1.1,
# e.g. Railway and Render's default domain), XHTTP carries the VLESS stream over
# ORDINARY HTTP request/response, so it works over plain HTTP/1.1 straight
# through those edges. No TCP passthrough, no HTTP/2, no extra env vars: the
# links target the normal HTTPS domain on :443, exactly like WebSocket.
#
# We advertise the "packet-up" mode (one long streaming GET for the downlink +
# many short POSTs for the uplink), which has the strongest CDN / HTTP-1.1
# compatibility; a client's `auto` mode also resolves to packet-up for
# security=tls. The share-link path is "/<prefix>/<uuid>", so the link uuid
# routes per-link (like the WS path) while the VLESS header stays the source of
# truth for authentication.
XHTTP_PATH_PREFIX = (os.environ.get("REN_XHTTP_PREFIX", "xhttp").strip("/") or "xhttp")
# Cap VLESS-header accumulation so a malformed uplink can't grow it without bound.
XHTTP_HEADER_MAX = 2048
# Max bytes accepted in a single upload POST body. Must be >= the client's 1 MB
# default (scMaxEachPostBytes); larger bodies get 413, matching Xray's contract.
XHTTP_MAX_POST_BYTES = 4_000_000
# Out-of-order upload reorder bound: if more than this many packets pile up
# waiting for a missing seq, tear the session down (the client is expected to
# open a fresh session and retry).
XHTTP_MAX_BUFFERED_POSTS = 64
# Per-session uplink backpressure threshold (bytes reassembled but not yet
# written upstream) — POST handlers briefly stall above this so a slow
# destination can't balloon memory on the free tier.
XHTTP_MAX_INFLIGHT_BYTES = 4_000_000
# Seconds to wait for the downlink GET to correlate with a freshly seen session
# before reaping it (mirrors Xray-core's 30 s correlation window).
XHTTP_SESSION_GRACE = 30

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

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None,
                        transport: str = "ws") -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()

    if transport == "xhttp":
        # XHTTP ("SplitHTTP") rides ordinary HTTP, so — unlike the old gRPC
        # transport — it works straight through PaaS/CDN edges that only speak
        # HTTP/1.1 (Railway, Render) and needs no TCP passthrough. The client
        # opens a streaming GET for the downlink and short POSTs for the uplink
        # under /<prefix>/<uuid>/...; the VLESS request header travels in the
        # first uplink bytes, exactly like the WS first frame. It reuses the same
        # domain:443 + TLS camouflage as WebSocket and works over clean-IP/CDN
        # addresses too, so it fans out across custom addresses just like WS.
        addr = address if address else domain
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "host": domain,
            "path": f"/{XHTTP_PATH_PREFIX}/{uuid}",
            "mode": "packet-up",
            "sni": domain,
            "fp": DEFAULT_FINGERPRINT,
            "alpn": "http/1.1",
            "allowInsecure": "0",
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

    # ---- WebSocket (default) ----
    # WebSocket early-data (0-RTT): the client carries the first chunk (which
    # holds the VLESS request header) inside the `Sec-WebSocket-Protocol`
    # upgrade header. This shaves a round-trip AND blends the handshake into
    # ordinary CDN traffic, which helps under DPI. Clients that don't understand
    # `ed` simply ignore it and send data as normal frames -> the server handles
    # both paths, so it stays fully compatible with standard v2rayNG / Nekobox /
    # sing-box configs. WS works on Railway's normal HTTPS domain (HTTP/1.1).
    addr = address if address else domain
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
        "vless_link_xhttp": generate_vless_link(uid, remark=f"REN-{label}-XHTTP", transport="xhttp"),
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
            "vless_link_xhttp": generate_vless_link(uid, remark=f"REN-{data['label']}-XHTTP", transport="xhttp"),
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

    # WebSocket and XHTTP both work on the normal HTTPS domain and over every
    # custom (clean-IP / CDN) address, so we fan BOTH transports across all of
    # them. This gives every client a working config no matter which transport
    # its app or network prefers.
    sub_links = [
        generate_vless_link(uid, remark=f"REN-{link['label']}-WS"),
        generate_vless_link(uid, remark=f"REN-{link['label']}-XHTTP", transport="xhttp"),
    ]
    for i, addr in enumerate(CUSTOM_ADDRESSES):
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}-WS", address=addr))
        sub_links.append(generate_vless_link(uid, remark=f"REN-{link['label']}-IP{i+1}-XHTTP", address=addr, transport="xhttp"))

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

# --- Shared transport helpers (reused by both the WS and XHTTP tunnels) ------
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

    Shared by the WebSocket and XHTTP engines so both transports get identical
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
    traffic histogram and per-link usage that the WS and XHTTP pumps both need.
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
        # tuning) so WS and XHTTP behave identically toward the destination.
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
# XHTTP ("SplitHTTP") Transport Engine
# ==========================================
# XHTTP carries the VLESS byte-stream over ORDINARY HTTP request/response, so it
# works through PaaS/CDN edges that only speak HTTP/1.1 (Railway, Render) — the
# very edges that demux HTTP/2 and broke gRPC. There is NO extra framing: the
# transport is a raw duplex byte stream and VLESS runs on top of it, exactly
# like the WebSocket path.
#
# packet-up mode (the mode we advertise, and where a client's `auto` lands for
# security=tls):
#   * DOWNLINK: one long-lived   GET  /<prefix>/<linkuuid>/<sessionId>
#       -> the response body streams upstream->client bytes forever (chunked,
#          flushed per write). Content-Type text/event-stream is masquerade only
#          (defeats intermediary buffering) — we never inject any bytes into it.
#   * UPLINK:  many short         POST /<prefix>/<linkuuid>/<sessionId>/<seq>
#       -> each body is one chunk of client->upstream bytes; <seq> (0,1,2,...)
#          gives ordering. POSTs may arrive out of order / before the GET, so we
#          buffer and reorder by seq, then feed the reassembled stream to the
#          VLESS parser. (A single streaming POST with no <seq> = "stream-up" is
#          also accepted.)
# The <sessionId> in the path is the sole key tying the GET and its POSTs into
# one logical connection; the <linkuuid> first segment routes per-link (like
# /ws/<uuid>), while the VLESS header stays the source of truth for auth.
#
# Reference: XTLS/Xray-core transport/internet/splithttp (hub.go, upload_queue.go)
# and RPRX's "XHTTP: Beyond REALITY" (github.com/XTLS/Xray-core/discussions/4113).

xhttp_sessions: dict = {}   # sessionId -> XhttpSession


def _xhttp_drain_inorder(pending: dict, next_seq: int):
    """Pop the contiguous run of packets from `pending` starting at next_seq.

    Mutates `pending` in place; returns (ordered_chunks, new_next_seq). Pure and
    synchronous so the reorder logic is unit-testable without an ASGI context.
    """
    chunks = []
    while next_seq in pending:
        chunks.append(pending.pop(next_seq))
        next_seq += 1
    return chunks, next_seq


class XhttpSession:
    """Correlates one downlink GET with many uplink POSTs sharing a sessionId.

    POST handlers PRODUCE ordered uplink bytes into `up_queue`; the GET handler
    CONSUMES them (parsing the VLESS header, then feeding the upstream socket)
    and writes the downlink back into its streaming response body. Stored in
    connection_sockets so close_connections_for_link() can tear it down on link
    deletion, the same way it closes a WebSocket.
    """
    def __init__(self, link_uuid: str, expected_bytes: bytes, client_ip: str):
        self.link_uuid = link_uuid
        self.expected_bytes = expected_bytes
        self.client_ip = client_ip
        self.created = time.monotonic()
        self.lock = asyncio.Lock()
        self.pending: dict = {}           # seq -> bytes held awaiting in-order delivery
        self.next_seq = 0
        self.up_queue: asyncio.Queue = asyncio.Queue()   # ordered uplink chunks (None = EOF)
        self.inflight_bytes = 0
        self.get_attached = asyncio.Event()
        self.closed = asyncio.Event()
        self.conn_id = None

    async def close(self, code: int = 1000, reason: str = ""):
        self.closed.set()
        try:
            self.up_queue.put_nowait(None)
        except Exception:
            pass


def _xhttp_client_ip(scope) -> str:
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            return value.decode("latin1").split(",")[0].strip()
    client = scope.get("client")
    if client:
        return client[0]
    return "unknown"


def _xhttp_padding_header() -> tuple:
    """A random-length X-Padding response header (fingerprint camouflage)."""
    return (b"x-padding", b"X" * (100 + secrets.randbelow(901)))


async def _xhttp_send_simple(send, status: int, extra_headers=None):
    """Send a short bodyless HTTP response (acks, rejects, CORS preflight)."""
    headers = [
        (b"cache-control", b"no-store"),
        (b"access-control-allow-origin", b"*"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    try:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"", "more_body": False})
    except Exception:
        pass


async def _xhttp_read_body(receive, limit: int):
    """Collect a bounded request body from ASGI receive events.

    Returns (body_bytes, too_large). Keeps reading to end-of-body so the request
    is fully consumed, but flags anything over `limit`.
    """
    body = bytearray()
    too_large = False
    while True:
        event = await receive()
        et = event["type"]
        if et == "http.request":
            chunk = event.get("body") or b""
            if chunk:
                body.extend(chunk)
                if len(body) > limit:
                    too_large = True
            if not event.get("more_body", False):
                break
        elif et == "http.disconnect":
            break
    return bytes(body), too_large


async def _xhttp_feed_packet(session: "XhttpSession", seq: int, body: bytes) -> bool:
    """Insert an uplink packet by seq, delivering any now-contiguous run in order.

    Returns False if the reorder buffer overflowed (caller must tear the session
    down), True otherwise.
    """
    async with session.lock:
        if session.closed.is_set():
            return True
        if seq < session.next_seq:
            return True  # duplicate / already delivered
        session.pending[seq] = body
        if len(session.pending) > XHTTP_MAX_BUFFERED_POSTS:
            return False
        chunks, session.next_seq = _xhttp_drain_inorder(session.pending, session.next_seq)
        for c in chunks:
            session.up_queue.put_nowait(c)
            session.inflight_bytes += len(c)
    return True


def _xhttp_get_or_create(session_id: str, link_uuid: str, expected_bytes: bytes,
                         client_ip: str) -> "XhttpSession":
    session = xhttp_sessions.get(session_id)
    if session is not None:
        return session
    session = XhttpSession(link_uuid, expected_bytes, client_ip)
    xhttp_sessions[session_id] = session
    asyncio.create_task(_xhttp_reaper(session_id, session))
    return session


async def _xhttp_reaper(session_id: str, session: "XhttpSession"):
    """Drop a session whose downlink GET never arrives (buffered POSTs would
    otherwise linger). Mirrors Xray-core's ~30 s correlation window."""
    try:
        await asyncio.wait_for(session.get_attached.wait(), timeout=XHTTP_SESSION_GRACE)
    except asyncio.TimeoutError:
        if not session.get_attached.is_set():
            session.closed.set()
            if xhttp_sessions.get(session_id) is session:
                xhttp_sessions.pop(session_id, None)


async def _xhttp_uplink_stream(receive, send, session: "XhttpSession"):
    """stream-up: a single long POST whose body IS the whole uplink stream."""
    try:
        while True:
            event = await receive()
            et = event["type"]
            if et == "http.request":
                chunk = event.get("body") or b""
                if chunk:
                    if session.closed.is_set():
                        break
                    session.up_queue.put_nowait(chunk)
                    session.inflight_bytes += len(chunk)
                if not event.get("more_body", False):
                    break
            elif et == "http.disconnect":
                break
    except Exception:
        pass
    await _xhttp_send_simple(send, 200, [_xhttp_padding_header()])


async def _xhttp_uplink(scope, receive, send, session, session_id, seq_str):
    """Handle one uplink request: a packet-up POST (has <seq>) or a stream-up
    POST (no <seq>)."""
    if seq_str is None:
        await _xhttp_uplink_stream(receive, send, session)
        return
    try:
        seq = int(seq_str)
    except ValueError:
        await _xhttp_send_simple(send, 400, [_xhttp_padding_header()])
        return

    body, too_large = await _xhttp_read_body(receive, XHTTP_MAX_POST_BYTES)
    if too_large:
        await _xhttp_send_simple(send, 413, [_xhttp_padding_header()])
        return

    ok = await _xhttp_feed_packet(session, seq, body)
    if not ok:
        await session.close()
        if xhttp_sessions.get(session_id) is session:
            xhttp_sessions.pop(session_id, None)
        await _xhttp_send_simple(send, 400, [_xhttp_padding_header()])
        return

    # Coarse backpressure: if the destination is slower than the client's uplink,
    # briefly stall the POST ack so buffered bytes can drain instead of piling up.
    waited = 0.0
    while (session.inflight_bytes > XHTTP_MAX_INFLIGHT_BYTES
           and not session.closed.is_set() and waited < XHTTP_SESSION_GRACE):
        await asyncio.sleep(0.05)
        waited += 0.05

    await _xhttp_send_simple(send, 200, [_xhttp_padding_header()])


async def _xhttp_downlink(scope, receive, send, session, session_id):
    """Handle the downlink GET: stream upstream->client, and drive the tunnel
    (VLESS header parse, upstream connect, both pumps)."""
    # Only one downlink GET per session; a duplicate would double-drive the tunnel.
    if session.get_attached.is_set():
        await _xhttp_send_simple(send, 409, [_xhttp_padding_header()])
        return
    session.get_attached.set()

    writer = None
    conn_id = None
    started = False
    disconnect_task = None
    try:
        # Open the streaming response immediately so the edge stops buffering and
        # the client's stream is established (flush headers with a ZERO-length
        # body chunk — no bytes enter the VLESS stream).
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"text/event-stream"),
                (b"cache-control", b"no-store"),
                (b"x-accel-buffering", b"no"),
                (b"access-control-allow-origin", b"*"),
                _xhttp_padding_header(),
            ],
        })
        started = True
        await send({"type": "http.response.body", "body": b"", "more_body": True})

        # Watch for the client closing the (bodyless) GET request.
        async def watch_disconnect():
            try:
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        break
            except Exception:
                pass
            session.closed.set()
        disconnect_task = asyncio.create_task(watch_disconnect())

        # Reassemble the VLESS header from the ordered uplink stream.
        buffer = b""
        command = address = port = initial_payload = None
        header_ready = False
        while not header_ready:
            if buffer:
                parsed = await parse_vless_header(buffer, session.expected_bytes)
                if parsed is not None:
                    command, address, port, initial_payload = parsed
                    header_ready = True
                    break
                if len(buffer) > XHTTP_HEADER_MAX:
                    raise ValueError("Header overflow")
            try:
                chunk = await asyncio.wait_for(session.up_queue.get(),
                                               timeout=XHTTP_SESSION_GRACE)
            except asyncio.TimeoutError:
                raise ValueError("uplink header timeout")
            if chunk is None:
                raise ValueError("uplink closed before header")
            session.inflight_bytes -= len(chunk)
            buffer += chunk

        # SSRF hardening: refuse internal / metadata destinations.
        if not await destination_allowed(address, port):
            raise ValueError("destination not allowed")

        uid = session.link_uuid
        link_data = LINKS.get(uid)
        max_conn = link_data.get("max_connections", 0) if link_data else 0
        if max_conn > 0:
            already_connected = ip_ref_count.get(uid, {}).get(session.client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uid) >= max_conn:
                raise ValueError("connection limit reached")

        conn_id = secrets.token_urlsafe(8)
        session.conn_id = conn_id
        connections[conn_id] = {"uuid": uid, "ip": session.client_ip,
                                "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = session
        ip_ref_count[uid][session.client_ip] += 1

        account_traffic(conn_id, uid, len(buffer), is_request=True)

        reader, writer = await open_upstream(address, port)

        if initial_payload:
            account_traffic(conn_id, uid, len(initial_payload))
            writer.write(initial_payload)
            await writer.drain()

        async def uplink_pump():
            # Reassembled uplink bytes -> upstream socket.
            try:
                while True:
                    chunk = await session.up_queue.get()
                    if chunk is None:
                        break
                    session.inflight_bytes -= len(chunk)
                    size = len(chunk)
                    if not await check_quota(uid, size):
                        break
                    account_traffic(conn_id, uid, size, is_request=True)
                    writer.write(chunk)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.write_eof()
                except Exception:
                    pass

        async def downlink_pump():
            # Upstream socket -> the GET response body (raw bytes, no framing).
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
                    if not await check_quota(uid, size):
                        break
                    account_traffic(conn_id, uid, size)
                    await send({"type": "http.response.body",
                                "body": data, "more_body": True})
            except Exception:
                pass

        task_up = asyncio.create_task(uplink_pump())
        task_down = asyncio.create_task(downlink_pump())
        watch = asyncio.create_task(session.closed.wait())
        # Downlink is the master: finish when upstream EOFs (task_down), the
        # client disconnects the GET, or the link is deleted (session.closed).
        # The uplink is only a feeder — in packet-up the client may keep the GET
        # open after it stops POSTing — so uplink completion must NOT tear down
        # the still-active downlink.
        await asyncio.wait({task_down, watch}, return_when=asyncio.FIRST_COMPLETED)
        for t in (task_up, task_down, watch):
            if not t.done():
                t.cancel()
        await asyncio.gather(task_up, task_down, watch, return_exceptions=True)

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": f"xhttp: {exc}", "time": datetime.now().isoformat()})
    finally:
        session.closed.set()
        if disconnect_task and not disconnect_task.done():
            disconnect_task.cancel()
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
        xhttp_sessions.pop(session_id, None)


async def xhttp_tunnel_asgi(scope, receive, send):
    """Raw-ASGI VLESS-over-XHTTP tunnel. Mounted at /<XHTTP_PATH_PREFIX>.

    Path inside the mount: /<linkuuid>/<sessionId>[/<seq>].
      GET  /<linkuuid>/<sessionId>          -> downlink stream
      POST /<linkuuid>/<sessionId>/<seq>    -> uplink packet (packet-up)
      POST /<linkuuid>/<sessionId>          -> uplink stream (stream-up)
    """
    if scope["type"] != "http":
        return

    method = scope.get("method", "GET")
    if method == "OPTIONS":
        # CORS preflight (Xray Browser Dialer / preflighted intermediaries).
        await _xhttp_send_simple(send, 200, [
            (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
            (b"access-control-allow-headers", b"*"),
            (b"access-control-max-age", b"86400"),
            _xhttp_padding_header(),
        ])
        return

    parts = [p for p in scope.get("path", "").split("/") if p]
    if len(parts) < 2:
        await _xhttp_send_simple(send, 404)
        return
    link_uuid = parts[0]
    session_id = parts[1]
    seq_str = parts[2] if len(parts) >= 3 else None

    link_data = LINKS.get(link_uuid)
    if not link_data or not link_data["active"] or is_expired(link_data):
        await _xhttp_send_simple(send, 404)
        return

    expected_bytes = link_data.get("uuid_bytes")
    if not expected_bytes:
        try:
            expected_bytes = uuid_lib.UUID(link_uuid).bytes
        except Exception:
            await _xhttp_send_simple(send, 404)
            return
        link_data["uuid_bytes"] = expected_bytes

    client_ip = _xhttp_client_ip(scope)
    session = _xhttp_get_or_create(session_id, link_uuid, expected_bytes, client_ip)

    if method == "GET":
        await _xhttp_downlink(scope, receive, send, session, session_id)
    elif method == "POST":
        await _xhttp_uplink(scope, receive, send, session, session_id, seq_str)
    else:
        await _xhttp_send_simple(send, 405)


# Mount the XHTTP engine on the shared port. It only claims the /<prefix>/*
# path, leaving the REST API, subscription, WS and UI routes untouched. Because
# XHTTP is plain HTTP/1.1, no HTTP/2 or TCP passthrough is needed.
app.mount(f"/{XHTTP_PATH_PREFIX}", xhttp_tunnel_asgi)

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
    # Hypercorn serves the REST API, WebSocket transport and XHTTP transport on a
    # single $PORT over HTTP/1.1. XHTTP rides ordinary HTTP requests (a streaming
    # GET + short POSTs), so — unlike the old gRPC transport — no end-to-end
    # HTTP/2 and no second/TCP-passthrough port are required. This is exactly why
    # it survives PaaS/CDN edges (Railway, Render) that downgrade HTTP/2.
    from hypercorn.config import Config
    from hypercorn.asyncio import serve

    config = Config()
    config.bind = [f"0.0.0.0:{CONFIG.port}"]
    config.workers = 1
    # Long-lived tunnels: don't let idle-timeouts kill active proxy streams
    # (notably the long streaming XHTTP downlink GET).
    config.keep_alive_timeout = 3600
    asyncio.run(serve(app, config))
