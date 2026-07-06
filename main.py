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
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
import base64

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, APIRouter
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
# NEW IMPLEMENTATION (Performance 2 / 12): GZip Compression
from fastapi.middleware.gzip import GZipMiddleware
import uvicorn
import httpx
import logging
import psutil
from pydantic_settings import BaseSettings

# ==========================================
# Settings Management (pydantic-settings)
# ==========================================
class Settings(BaseSettings):
    port: int = 8000
    secret_key: str = "ren-default-secret-key"
    admin_password: str = "admin"
    
    class Config:
        env_file = ".env"

CONFIG = Settings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# NEW IMPLEMENTATION (Performance 2 / 12): GZip Compression to reduce API & HTML load times
app.add_middleware(GZipMiddleware, minimum_size=1000)

api_router = APIRouter(prefix="/api")

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

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG.secret_key}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(CONFIG.admin_password)}
SESSIONS: dict = {}

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

def ensure_default_link():
    if not LINKS:
        # NEW IMPLEMENTATION (Performance 1 / 11): Pre-compile UUID bytes
        uid = str(uuid_lib.uuid4())
        LINKS[uid] = {
            "label": "Default", "limit_bytes": 0, "used_bytes": 0, 
            "max_connections": 0, "created_at": datetime.now().isoformat(), 
            "active": True, "expiry": "",
            "uuid_bytes": uuid_lib.UUID(uid).bytes
        }

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    ensure_default_link()
    asyncio.create_task(keep_alive())
    asyncio.create_task(cleanup_traffic_task())
    logger.info(f"REN started on port {CONFIG.port}")

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

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
    try: days = float(expiry_days or 0)
    except: days = 0
    if days <= 0: return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp: return False
    try: return datetime.now() >= datetime.fromisoformat(exp)
    except: return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp: return 0
    try: return int(datetime.fromisoformat(exp).timestamp())
    except: return 0

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
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
            try: await ws.close(code=1000, reason="link deleted")
            except: pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    ip_ref_count.pop(uid, None)

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
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
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
    return {"authenticated": await is_valid_session(token)}

@api_router.post("/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    SESSIONS.clear()
    if current_token:
        SESSIONS[current_token] = time.time() + SESSION_TTL
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
        "cpu_percent": psutil.cpu_percent(interval=0.1),
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
    
    # NEW IMPLEMENTATION (Performance 1 / 11): Pre-compile UUID bytes upon creation
    uid_bytes = uuid_lib.UUID(uid).bytes
    LINKS[uid] = {
        "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, 
        "max_connections": max_conn, "created_at": datetime.now().isoformat(), 
        "active": True, "expiry": expiry, "uuid_bytes": uid_bytes
    }
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
    return {"ok": True}

@api_router.delete("/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    LINKS.pop(uid, None)
    await close_connections_for_link(uid)
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
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@api_router.delete("/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    if 0 <= index < len(CUSTOM_ADDRESSES):
        CUSTOM_ADDRESSES.pop(index)
    else:
        raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@api_router.get("/backup")
async def export_data(_=Depends(require_auth)):
    # Create copy to prevent reference mutation during export
    export_links = {}
    for k, v in LINKS.items():
        clean_v = v.copy()
        clean_v.pop("uuid_bytes", None) # Exclude pre-compiled bytes
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
    if "links" in data:
        for k, v in data["links"].items():
            try:
                # NEW IMPLEMENTATION (Performance 1 / 11): Pre-compile UUID bytes on import
                v["uuid_bytes"] = uuid_lib.UUID(k).bytes
                LINKS[k] = v
            except Exception:
                pass
    if "addresses" in data:
        CUSTOM_ADDRESSES = data["addresses"]
    if "domain" in data:
        CUSTOM_DOMAIN = data["domain"]
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

# NEW IMPLEMENTATION (Performance 1 / 11): Use precompiled bytes to skip CPU heavy generation
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
        if len(buffer) < pos + 4: return None
        address = ".".join(str(b) for b in buffer[pos:pos + 4])
        pos += 4
    elif addr_type == 2:
        if len(buffer) < pos + 1: return None
        domain_len = buffer[pos]
        pos += 1
        if len(buffer) < pos + domain_len: return None
        address = buffer[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(buffer) < pos + 16: return None
        address = ":".join(f"{buffer[i]:02x}{buffer[i+1]:02x}" for i in range(pos, pos + 16, 2))
        pos += 16
    else:
        raise ValueError(f"Unknown address type: {addr_type}")
        
    return command, address, port, buffer[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    link = LINKS.get(uid)
    if not link or not link["active"] or is_expired(link): return False
    if link["limit_bytes"] == 0: return True
    return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    if uid in LINKS:
        LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await asyncio.wait_for(websocket.receive(), IDLE_TIMEOUT)
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += size
            await add_usage(link_uid, size)
            
            writer.write(data); await writer.drain()
    except (asyncio.TimeoutError, WebSocketDisconnect): pass
    except Exception: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    # NEW IMPLEMENTATION (Performance 6 / 16): Dynamic Buffer Sizing to boost high-speed proxy downloads
    buf_size = 16384
    try:
        while True:
            data = await asyncio.wait_for(reader.read(buf_size), IDLE_TIMEOUT)
            if not data: break
            size = len(data)
            
            # Dynamically adjust buffer based on throughput saturation
            if size == buf_size and buf_size < 262144:
                buf_size *= 2
            elif size < buf_size / 2 and buf_size > 16384:
                buf_size = max(16384, int(buf_size / 2))
                
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
                
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%Y-%m-%d %H:00")] += size
            await add_usage(link_uid, size)
            
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except (asyncio.TimeoutError, WebSocketDisconnect): pass
    except Exception: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        link_data = LINKS.get(uuid)
        if not link_data or not link_data["active"] or is_expired(link_data):
            await websocket.close(code=1008, reason="forbidden"); return
            
        max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = ip_ref_count.get(uuid, {}).get(client_ip, 0) > 0
            if not already_connected and count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="limit reached"); return

        # NEW IMPLEMENTATION (Performance 1 / 11): Fetch precompiled bytes
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
            if first_msg["type"] == "websocket.disconnect": return
            chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
            if not chunk: continue
            
            buffer += chunk
            parsed = await parse_vless_header(buffer, expected_bytes)
            if parsed is not None:
                command, address, port, initial_payload = parsed
                break
            if len(buffer) > 2048:
                raise ValueError("Header overflow")
                
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        ip_ref_count[uuid][client_ip] += 1
        
        size = len(buffer)
        stats["total_bytes"] += size; stats["total_requests"] += 1
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
            writer.write(initial_payload); await writer.drain()
            
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
        
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                remove_ip_from_link(info.get("uuid"), info.get("ip"))

# ==========================================
# Dashboard & Login UI
# ==========================================
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#050508;--surface:rgba(20,20,20,0.85);--surface2:#1c1c1c;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.15);--accent:#991b1b;--error:#ef4444;--error-bg:rgba(239,68,68,0.08);--orb1:rgba(220,38,38,0.12);--orb2:rgba(153,27,27,0.1);--orb3:rgba(239,68,68,0.06)}
html[data-theme="light"]{--bg:#f8f9fa;--surface:rgba(255,255,255,0.9);--surface2:#f9fafb;--border:rgba(0,0,0,0.06);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#16a34a;--primary-glow:rgba(22,163,74,0.12);--accent:#15803d;--error:#dc2626;--error-bg:rgba(220,38,38,0.06);--orb1:rgba(22,163,74,0.1);--orb2:rgba(21,128,61,0.08);--orb3:rgba(34,197,94,0.05)}
body{font-family:'Inter',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .5s,color .5s;overflow:hidden}
.bg-canvas{position:fixed;inset:0;z-index:0;pointer-events:none}
.orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:0;animation:orbFloat 20s ease-in-out infinite}
.orb-1{width:400px;height:400px;background:var(--orb1);top:-10%;left:-5%;animation-delay:0s}
.orb-2{width:350px;height:350px;background:var(--orb2);bottom:-10%;right:-5%;animation-delay:-7s}
.orb-3{width:250px;height:250px;background:var(--orb3);top:40%;left:60%;animation-delay:-14s}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1);opacity:0.6}25%{transform:translate(60px,-40px) scale(1.1);opacity:0.8}50%{transform:translate(-30px,50px) scale(0.9);opacity:0.5}75%{transform:translate(40px,20px) scale(1.05);opacity:0.7}}
.grid-bg{position:fixed;inset:0;z-index:0;opacity:0.03;background-image:linear-gradient(rgba(255,255,255,0.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.1) 1px,transparent 1px);background-size:60px 60px;pointer-events:none}
.toolbar{position:fixed;top:20px;right:20px;display:flex;gap:6px;z-index:10}
.toolbar button{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .3s;backdrop-filter:blur(20px)}
.toolbar button:hover{border-color:var(--primary);color:var(--primary);transform:scale(1.05)}
.login-page{width:100%;max-width:380px;padding:0 20px;position:relative;z-index:1}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:24px;padding:48px 36px 36px;position:relative;overflow:hidden;backdrop-filter:blur(40px);box-shadow:0 8px 40px rgba(0,0,0,0.15),0 0 80px rgba(220,38,38,0.05);animation:cardIn .8s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(30px) scale(0.96)}
@keyframes cardIn{to{opacity:1;transform:translateY(0) scale(1)}}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 3s ease-in-out infinite}
@keyframes shimmer{0%,100%{opacity:0.5;transform:scaleX(0.5)}50%{opacity:1;transform:scaleX(1)}}
.brand{text-align:center;margin-bottom:36px}
.brand svg{margin-bottom:20px;filter:drop-shadow(0 0 20px rgba(220,38,38,0.3));animation:logoPulse 4s ease-in-out infinite}
@keyframes logoPulse{0%,100%{filter:drop-shadow(0 0 20px rgba(220,38,38,0.3));transform:scale(1)}50%{filter:drop-shadow(0 0 30px rgba(220,38,38,0.5));transform:scale(1.02)}}
.brand h1{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-0.03em;animation:fadeUp .6s .2s ease both}
.brand p{font-size:11px;color:var(--text3);margin-top:6px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;animation:fadeUp .6s .3s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.form-group{margin-bottom:20px;animation:fadeUp .6s .4s ease both}
.form-group label{display:block;font-size:11px;font-weight:700;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em}
.form-group input{width:100%;padding:13px 16px;background:var(--surface2);border:1.5px solid var(--border);border-radius:12px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .3s}
.form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow),0 0 20px var(--primary-glow)}
.login-btn{width:100%;padding:13px;background:var(--primary);border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:700;cursor:pointer;transition:all .3s;animation:fadeUp .6s .5s ease both}
.login-btn:hover{filter:brightness(1.15);transform:translateY(-2px);box-shadow:0 8px 25px rgba(220,38,38,0.35)}
.error-msg{background:var(--error-bg);color:var(--error);padding:10px;border-radius:10px;font-size:13px;display:none;margin-bottom:20px;text-align:center;}
.error-msg.show{display:block}
</style>
</head>
<body>
<div class="bg-canvas"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>
<div class="grid-bg"></div>
<div class="toolbar">
  <button id="lang-toggle" onclick="cycleLang()" title="Language">EN</button>
  <button id="theme-toggle" onclick="toggleTheme()" title="Theme">💡</button>
</div>
<div class="login-page">
  <div class="login-card" id="login-card">
    <div class="brand">
      <svg width="60" height="60" viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="#dc2626"/></svg>
      <h1>REN</h1>
      <p>v1.1 Security Update</p>
    </div>
    <div class="error-msg" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <input type="password" id="password" placeholder="Enter password" autofocus>
      </div>
      <button type="submit" class="login-btn" data-en="Sign In" data-fa="ورود">Sign In</button>
    </form>
  </div>
</div>
<script>
let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
function setLang(l){lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-toggle').textContent=l.toUpperCase();localStorage.setItem('ren_lang',l)}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
applyTheme(theme);setLang(lang);

document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err-box');err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
    if(!r.ok) throw new Error('Failed');
    location.href='/dashboard';
  }catch(e){err.textContent='Invalid password';err.classList.add('show')}
});
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
/* Core Base CSS */
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#0a0a0a;--surface:#141414;--surface2:#1c1c1c;--surface3:#2a2a2a;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#dc2626;--primary-dim:rgba(220,38,38,0.1);--green:#22c55e;--green-dim:rgba(34,197,94,0.1);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--sidebar-bg:#0f0f0f;}
html[data-theme="light"]{--bg:#ffffff;--surface:#ffffff;--surface2:#f9fafb;--surface3:#f3f4f6;--border:rgba(0,0,0,0.06);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#16a34a;--primary-dim:rgba(22,163,74,0.06);--green:#16a34a;--green-dim:rgba(22,163,74,0.06);--red:#dc2626;--red-dim:rgba(220,38,38,0.06);--sidebar-bg:#ffffff;}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh;transition:background 0.3s, color 0.3s;}

/* NEW IMPLEMENTATION (UI 1 & 2): Responsive Sidebar & Theme Toggle */
.topbar{display:none; position:fixed; top:0; left:0; right:0; height:60px; background:var(--sidebar-bg); border-bottom:1px solid var(--border); padding:0 16px; align-items:center; z-index:900; justify-content:space-between;}
.hamburger{background:none; border:none; color:var(--text); font-size:24px; cursor:pointer;}
.topbar-theme-btn {background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:6px 10px; cursor:pointer;}

.sidebar{width:220px;background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0; transition:transform 0.3s ease; z-index:1000;}
.sidebar-overlay{display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); z-index:990;}
.sidebar-overlay.show{display:block;}
.sidebar-brand{padding:16px;border-bottom:1px solid var(--border);font-weight:bold;color:var(--primary)}
.sidebar-nav{flex:1;padding:8px;overflow-y:auto}
.nav-item{display:block;padding:10px;margin:2px 0;color:var(--text2);text-decoration:none;border-radius:8px;cursor:pointer;border:none;background:none;width:100%;text-align:left;}
.nav-item:hover, .nav-item.active{background:var(--primary-dim);color:var(--primary);}
.main{margin-left:220px;flex:1;padding:24px;width:calc(100% - 220px); transition:margin 0.3s ease, width 0.3s ease;}

@media (max-width: 768px) {
    .topbar { display: flex; }
    .sidebar { transform: translateX(-100%); }
    .sidebar.open { transform: translateX(0); }
    .main { margin-left: 0 !important; width: 100% !important; padding-top: 84px; }
    .stats-row { grid-template-columns: repeat(2, 1fr) !important; }
}

.page{display:none;animation:pageIn .4s ease}
.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:12px;}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.btn{padding:8px 14px;border-radius:8px;border:none;cursor:pointer;background:var(--surface3);color:var(--text);font-weight:600; display:inline-flex; align-items:center; justify-content:center; gap:8px;}
.btn-primary{background:var(--primary);color:#fff;}
.btn-danger{background:var(--red-dim);color:var(--red);}
.table{width:100%;border-collapse:collapse;font-size:13px;}
.table th, .table td{padding:10px;text-align:left;border-bottom:1px solid var(--border)}

/* NEW IMPLEMENTATION (UI 5): Form Validation Input Class */
.form-group{margin-bottom:12px;}
.form-input, .form-select{width:100%;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--surface2);color:var(--text); transition:border 0.3s;}
.form-input.invalid {border-color: var(--red) !important; box-shadow: 0 0 5px var(--red-dim);}
.form-input.invalid::placeholder {color: var(--red);}

/* NEW IMPLEMENTATION (UI 10): Toast Notification System */
.toast{position:fixed;top:20px;right:20px;background:var(--surface2);padding:12px 20px;border-radius:8px;border-left:4px solid var(--green);display:flex;align-items:center;gap:10px;box-shadow:0 4px 12px rgba(0,0,0,0.15); transform:translateX(120%); transition:transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); z-index:2000; font-weight:600;}
.toast.show{transform:translateX(0);}
.toast.error{border-left-color:var(--red);}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:none;align-items:center;justify-content:center;z-index:200;}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);padding:24px;border-radius:16px;width:100%;max-width:460px;}
.modal-close{float:right;cursor:pointer;background:none;border:none;color:var(--text2);font-size:18px;}

/* NEW IMPLEMENTATION (UI 4): Live Transitions */
.usage-bar{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;margin-top:4px}
.usage-fill{height:100%;background:var(--primary); transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);}

/* NEW IMPLEMENTATION (UI 8): Action Button Spinners */
@keyframes spin { to { transform: rotate(360deg); } }
.spinner { width:16px; height:16px; border:2px solid transparent; border-top-color:currentColor; border-radius:50%; animation: spin .6s linear infinite; display:inline-block; vertical-align:middle; }
</style>
</head>
<body>

<script>
// Theme Initialization Script before DOM load to prevent flashing
let theme = localStorage.getItem('ren_theme') || 'dark';
document.documentElement.setAttribute('data-theme', theme);
</script>

<div class="toast" id="toast"></div>

<!-- Mobile Header -->
<header class="topbar">
   <button class="hamburger" onclick="toggleSidebar()">☰</button>
   <div style="font-weight:bold; color:var(--primary)">REN Panel</div>
   <button onclick="toggleTheme()" class="topbar-theme-btn" title="Toggle Theme">💡</button>
</header>

<div class="sidebar-overlay" onclick="toggleSidebar()"></div>
<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">REN Panel</div>
  <nav class="sidebar-nav">
    <button class="nav-item active" data-page="dashboard">Dashboard</button>
    <button class="nav-item" data-page="inbounds">Inbounds</button>
    <button class="nav-item" data-page="addresses">Clean IP</button>
    <button class="nav-item" data-page="domain">Domain</button>
    <button class="nav-item" data-page="security">System</button>
  </nav>
  <div style="padding:16px; border-top:1px solid var(--border);">
    <div style="display:flex; gap:8px; margin-bottom:8px;" id="sidebar-theme-toggles">
      <button class="btn" style="flex:1" onclick="toggleTheme()">💡 Theme</button>
    </div>
    <button class="btn btn-danger" style="width:100%" onclick="withLoading(this, logout)">Logout</button>
  </div>
</aside>

<main class="main">
  <!-- DASHBOARD -->
  <section class="page active" id="page-dashboard">
    <h2>Dashboard</h2><br>
    <div class="stats-row">
      <div class="card"><div>Traffic</div><h2 id="s-traffic" style="transition: opacity 0.3s">--</h2></div>
      <div class="card"><div>Inbounds</div><h2 id="s-links" style="transition: opacity 0.3s">--</h2></div>
      <div class="card"><div>Uptime</div><h2 id="s-uptime">--</h2></div>
      <div class="card"><div>Domain</div><div id="s-domain" style="word-break:break-all">--</div></div>
    </div>
    <div class="card"><canvas id="trafficChart" style="height:200px;width:100%"></canvas></div>
  </section>

  <!-- INBOUNDS -->
  <section class="page" id="page-inbounds">
    <div style="display:flex;justify-content:space-between;margin-bottom:12px">
      <h2>Inbounds</h2>
      <button class="btn btn-primary" onclick="$('#add-modal').classList.add('show')">+ Add</button>
    </div>
    <div class="card" style="padding:0;overflow-x:auto;">
      <table class="table">
        <thead><tr><th>Label</th><th>Traffic</th><th>IPs</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody id="links-tbody"></tbody>
      </table>
    </div>
  </section>

  <!-- CLEAN IP -->
  <section class="page" id="page-addresses">
    <div style="display:flex;justify-content:space-between;margin-bottom:12px">
      <h2>Clean IP List</h2>
      <button class="btn btn-primary" onclick="$('#add-address-modal').classList.add('show')">+ Add</button>
    </div>
    <div class="card" id="address-list"></div>
  </section>

  <!-- DOMAIN -->
  <section class="page" id="page-domain">
    <h2>Domain Override</h2><br>
    <div class="card" style="max-width:500px">
      <div class="form-group"><label>New Domain</label><input class="form-input" id="domain-input" placeholder="example.com"></div>
      <button class="btn btn-primary" onclick="withLoading(this, saveDomain)">Save Domain</button>
    </div>
  </section>

  <!-- SYSTEM & SECURITY -->
  <section class="page" id="page-security">
    <h2>System Settings</h2><br>
    <div class="card" style="max-width:400px">
      <h3>Change Password</h3><br>
      <div class="form-group"><input class="form-input" type="password" id="cur-pw" placeholder="Current password"></div>
      <div class="form-group"><input class="form-input" type="password" id="new-pw" placeholder="New password"></div>
      <button class="btn btn-primary" onclick="withLoading(this, changePassword)">Update Password</button>
    </div>
    
    <div class="card" style="max-width:400px;margin-top:16px">
      <h3>Backup & Restore</h3><br>
      <div style="display:flex;gap:8px">
         <button class="btn" onclick="withLoading(this, exportData)">Export JSON</button>
         <button class="btn btn-primary" onclick="document.getElementById('import-file').click()">Import JSON</button>
         <input type="file" id="import-file" style="display:none" onchange="importData(event)" accept=".json">
      </div>
    </div>
  </section>
</main>

<!-- MODALS -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#add-modal').classList.remove('show')">×</button>
    <h3>Add Inbound</h3><br>
    <div class="form-group"><label>Label</label><input class="form-input" id="new-label" placeholder="e.g. Test-Proxy"></div>
    <div class="form-group"><label>Traffic Limit (GB)</label><input class="form-input" type="number" id="new-limit" placeholder="0 for Unlimited" min="0"></div>
    <div class="form-group"><label>Max IPs (0=Unlimited)</label><input class="form-input" type="number" id="new-maxconn" placeholder="0 for Unlimited" min="0"></div>
    <button class="btn btn-primary" style="width:100%" onclick="withLoading(this, createLink)">Create Inbound</button>
  </div>
</div>

<div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#add-address-modal').classList.remove('show')">×</button>
    <h3>Add IPs/Domains</h3><br>
    <textarea class="form-input" id="new-address" rows="5" placeholder="1.1.1.1\nwww.bing.com"></textarea><br><br>
    <button class="btn btn-primary" style="width:100%" onclick="withLoading(this, addAddresses)">Add All</button>
  </div>
</div>

<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#detail-modal').classList.remove('show')">×</button>
    <h3>Details</h3><br>
    <div id="detail-content" style="font-size:13px;line-height:1.8; word-break:break-all;"></div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
let allLinks=[], allAddresses=[], statsData={};

// UI 1: Responsive Sidebar Toggle
function toggleSidebar() {
    $('#sidebar').classList.toggle('open');
    $('.sidebar-overlay').classList.toggle('show');
}

// UI 2: Theme Toggle inside Dashboard
function toggleTheme(){
    theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ren_theme', theme);
}

$$('.nav-item').forEach(el=>el.addEventListener('click',()=>{
  $$('.page').forEach(p=>p.classList.remove('active'));
  $(`#page-${el.dataset.page}`).classList.add('active');
  $$('.nav-item').forEach(n=>n.classList.remove('active'));
  el.classList.add('active');
  if(window.innerWidth <= 768) toggleSidebar(); // Close sidebar on mobile click
}));

// UI 10: Smooth slide-in Toast with Icons
function toast(msg, err=false){
    const t = $('#toast'); 
    t.innerHTML = (err ? '❌ ' : '✅ ') + msg;
    t.className = 'toast ' + (err ? 'error' : '');
    void t.offsetWidth; // force reflow for css animation restart
    t.classList.add('show');
    clearTimeout(t.timer);
    t.timer = setTimeout(() => t.classList.remove('show'), 3000);
}

// UI 8: Action Button Spinner Wrapper
async function withLoading(btn, asyncFn) {
    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<div class="spinner"></div>';
    btn.disabled = true;
    try { await asyncFn(); } 
    catch(e) { console.error(e); } 
    finally { btn.innerHTML = originalHtml; btn.disabled = false; }
}

function fmtBytes(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}

async function logout(){
    await fetch('/api/logout',{method:'POST'});
    location.href='/login';
}

async function loadStats(){
    try{
        const r=await fetch('/stats'); statsData=await r.json();
        
        // Simple DOM update for Live Transitions (UI 4)
        $('#s-traffic').style.opacity = 0; $('#s-links').style.opacity = 0;
        setTimeout(()=>{
            $('#s-traffic').textContent = statsData.total_traffic_mb+' MB';
            $('#s-links').textContent = statsData.links_count;
            $('#s-uptime').textContent = statsData.uptime;
            $('#s-domain').textContent = statsData.domain || 'Not Set';
            $('#s-traffic').style.opacity = 1; $('#s-links').style.opacity = 1;
        }, 150);
        
        updateChart();
    }catch(e){}
}

async function loadLinks(){
    try{
        const r=await fetch('/api/links'); const d=await r.json(); allLinks=d.links;
        $('#links-tbody').innerHTML = allLinks.map(l=>{
            const u=l.used_bytes, lim=l.limit_bytes, pct=lim?Math.min(100,u/lim*100):0;
            return `<tr>
              <td>${l.label}</td>
              <td>${fmtBytes(u)} / ${lim?fmtBytes(lim):'∞'} <div class="usage-bar"><div class="usage-fill" style="width:${pct}%"></div></div></td>
              <td>${l.current_connections}/${l.max_connections||'∞'}</td>
              <td>${l.active?'<span style="color:var(--green)">On</span>':'<span style="color:var(--red)">Off</span>'}</td>
              <td>
                <button class="btn btn-primary" onclick="showDetail('${l.uuid}')">Info</button>
                <button class="btn btn-danger" onclick="deleteLink('${l.uuid}')">x</button>
              </td>
            </tr>`;
        }).join('');
    }catch(e){}
}

function showDetail(uid){
    const l=allLinks.find(x=>x.uuid===uid);
    $('#detail-content').innerHTML = `
      <b>UUID:</b> ${l.uuid}<br><br>
      <b>Connected IPs:</b> ${l.connected_ips && l.connected_ips.length ? l.connected_ips.join(', ') : 'None'}<br><br>
      <b>VLESS Link:</b><br>
      <textarea class="form-input" rows="4" readonly onclick="this.select();document.execCommand('copy');toast('Copied!')">${l.vless_link}</textarea><br><br>
      <b>Sub URL:</b><br>
      <textarea class="form-input" rows="2" readonly onclick="this.select();document.execCommand('copy');toast('Copied!')">https://${location.host}/sub/${l.uuid}</textarea>
    `;
    $('#detail-modal').classList.add('show');
}

// UI 5: Form Validation visual feedback
async function createLink(){
    const labelInput = $('#new-label');
    const limitInput = $('#new-limit');
    let valid = true;
    
    if(!labelInput.value.trim()){ labelInput.classList.add('invalid'); valid=false; } else { labelInput.classList.remove('invalid'); }
    if(limitInput.value < 0 || limitInput.value === ''){ limitInput.classList.add('invalid'); valid=false; } else { limitInput.classList.remove('invalid'); }
    
    if(!valid) { toast('Please fill fields correctly', true); return; }

    try{
        const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({label:labelInput.value, limit_value:limitInput.value, max_connections:$('#new-maxconn').value||0})});
        if(!r.ok) throw new Error(); 
        toast('Inbound Created Successfully!');
        $('#add-modal').classList.remove('show'); 
        labelInput.value=''; limitInput.value='';
        loadLinks(); loadStats();
    }catch(e){toast('Failed to create inbound',true)}
}

async function deleteLink(uid){
    if(!confirm('Are you sure you want to delete this inbound?')) return;
    await fetch(`/api/links/${uid}`,{method:'DELETE'}); 
    toast('Inbound Deleted');
    loadLinks(); loadStats();
}

async function loadAddresses(){
    const r=await fetch('/api/addresses'); const d=await r.json();
    $('#address-list').innerHTML = d.addresses.map((a,i)=>`
      <div style="display:flex;justify-content:space-between;padding:10px;border-bottom:1px solid var(--border); align-items:center;">
        <span>${a}</span> <button class="btn btn-danger" onclick="deleteAddress(${i})">x</button>
      </div>`).join('');
}

async function addAddresses(){
    const lines = $('#new-address').value.split('\n').map(l=>l.trim()).filter(l=>l);
    if(lines.length === 0) return toast('No addresses provided', true);
    for(const a of lines) await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:a})});
    $('#add-address-modal').classList.remove('show'); 
    $('#new-address').value = '';
    toast('Addresses added successfully');
    loadAddresses();
}
async function deleteAddress(i){ await fetch(`/api/addresses/${i}`,{method:'DELETE'}); loadAddresses(); }

async function saveDomain(){
    const input = $('#domain-input');
    await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:input.value})});
    toast('Domain Saved'); loadStats(); loadLinks();
}

async function changePassword(){
    const curr = $('#cur-pw'); const nw = $('#new-pw');
    if(!curr.value || nw.value.length < 4) return toast('Invalid password inputs', true);
    
    const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({current_password:curr.value, new_password:nw.value})});
    if(r.ok){ toast('Password Updated'); curr.value=''; nw.value=''; } else { toast('Incorrect Current Password',true); }
}

async function exportData() {
    try {
        const r = await fetch('/api/backup'); const d = await r.json();
        const blob = new Blob([JSON.stringify(d, null, 2)], {type: 'application/json'});
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'ren_backup.json';
        a.click(); toast('Backup Exported');
    } catch(e) { toast('Export failed', true); }
}

async function importData(e) {
    const file = e.target.files[0]; if(!file) return;
    const reader = new FileReader();
    reader.onload = async(ev) => {
        try {
            const data = JSON.parse(ev.target.result);
            const r = await fetch('/api/backup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
            if(r.ok) { toast('Backup Imported! Reloading...'); setTimeout(()=>location.reload(), 1000); }
        } catch(err) { toast('Import Failed', true); }
    };
    reader.readAsText(file);
}

let chart;
function updateChart(){
    const ctx=$('#trafficChart'); if(!ctx)return;
    const ht=statsData.hourly_traffic; if(!ht)return;
    const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
    
    const labels = sorted.map(e=>e[0].split(' ')[1]);
    const data = sorted.map(e=>Math.round(e[1]/1048576));

    if(!chart) {
        chart = new Chart(ctx,{
            type:'bar',
            data:{ labels: labels, datasets:[{ label:'Traffic', data: data, backgroundColor:'#dc2626', borderRadius: 4 }] },
            options:{
                responsive:true, maintainAspectRatio:false,
                // NEW IMPLEMENTATION (UI 9): Enhanced Chart Tooltips
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) { return context.parsed.y + ' MB at ' + context.label; }
                        }
                    }
                }
            }
        });
    } else { 
        chart.data.labels = labels; 
        chart.data.datasets[0].data = data; 
        chart.update(); 
    }
}

// Remove input validation red border on focus
$$('.form-input').forEach(el => el.addEventListener('focus', () => el.classList.remove('invalid')));

loadStats(); loadLinks(); loadAddresses();
setInterval(loadStats, 10000);
</script>
</body>
</html>"""

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
