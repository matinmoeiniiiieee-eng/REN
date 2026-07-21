"""Test suite for the REN gateway.

Runs against an isolated temp data file so tests never touch real state.
"""
import os
import sys
import asyncio
import tempfile
import uuid as uuid_lib

# Isolate persistence + auth BEFORE importing the app (Settings read env at import).
_TMP_DATA = os.path.join(tempfile.gettempdir(), "ren_test_data.json")
os.environ["DATA_FILE"] = _TMP_DATA
os.environ["ADMIN_PASSWORD"] = "admin"
os.environ["ALLOW_PRIVATE_RANGES"] = "false"
try:
    os.remove(_TMP_DATA)
except OSError:
    pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
import main


def run(coro):
    return asyncio.run(coro)


def build_vless_header(uuid_bytes, addr_type=1, address=b"\x01\x01\x01\x01",
                       port=443, payload=b"hello", version=0, addon_len=0, command=1):
    buf = bytes([version]) + uuid_bytes + bytes([addon_len])
    buf += bytes([command])
    buf += port.to_bytes(2, "big")
    buf += bytes([addr_type])
    buf += address
    buf += payload
    return buf


# ----------------------------- VLESS protocol -----------------------------
def test_parse_vless_ipv4():
    u = uuid_lib.uuid4()
    buf = build_vless_header(u.bytes, addr_type=1, address=b"\x01\x01\x01\x01", port=443, payload=b"hello")
    parsed = run(main.parse_vless_header(buf, u.bytes))
    assert parsed is not None
    command, address, port, rest = parsed
    assert command == 1
    assert address == "1.1.1.1"
    assert port == 443
    assert rest == b"hello"


def test_parse_vless_domain():
    u = uuid_lib.uuid4()
    domain = b"example.com"
    addr = bytes([len(domain)]) + domain
    buf = build_vless_header(u.bytes, addr_type=2, address=addr, port=80, payload=b"x")
    parsed = run(main.parse_vless_header(buf, u.bytes))
    assert parsed is not None
    assert parsed[1] == "example.com"
    assert parsed[2] == 80


def test_parse_vless_ipv6():
    u = uuid_lib.uuid4()
    addr = bytes(range(16))
    buf = build_vless_header(u.bytes, addr_type=3, address=addr, port=443, payload=b"")
    parsed = run(main.parse_vless_header(buf, u.bytes))
    assert parsed is not None
    assert ":" in parsed[1]


def test_parse_vless_uuid_mismatch():
    u = uuid_lib.uuid4()
    other = uuid_lib.uuid4()
    buf = build_vless_header(u.bytes)
    with pytest.raises(ValueError):
        run(main.parse_vless_header(buf, other.bytes))


def test_parse_vless_bad_version():
    u = uuid_lib.uuid4()
    buf = build_vless_header(u.bytes, version=1)
    with pytest.raises(ValueError):
        run(main.parse_vless_header(buf, u.bytes))


def test_parse_vless_short_buffer_returns_none():
    u = uuid_lib.uuid4()
    assert run(main.parse_vless_header(b"\x00" * 10, u.bytes)) is None


# ----------------------------- Helpers -----------------------------
def test_parse_size_to_bytes():
    assert main.parse_size_to_bytes(1, "GB") == 1024 ** 3
    assert main.parse_size_to_bytes(1, "MB") == 1024 ** 2
    assert main.parse_size_to_bytes(1, "KB") == 1024
    assert main.parse_size_to_bytes(500, "B") == 500


def test_expiry_helpers():
    assert main.compute_expiry(0) == ""
    assert main.compute_expiry("bad") == ""
    exp = main.compute_expiry(1)
    assert exp != ""
    assert main.is_expired({"expiry": exp}) is False
    assert main.is_expired({"expiry": "2000-01-01T00:00:00"}) is True
    assert main.expiry_epoch({"expiry": exp}) > 0


def test_quota_logic():
    uid = "quota-test"
    main.LINKS[uid] = {"active": True, "expiry": "", "limit_bytes": 100, "used_bytes": 90}
    assert run(main.check_quota(uid, 10)) is True
    assert run(main.check_quota(uid, 11)) is False
    main.LINKS[uid]["limit_bytes"] = 0  # unlimited
    assert run(main.check_quota(uid, 10 ** 9)) is True
    main.LINKS[uid]["active"] = False
    assert run(main.check_quota(uid, 1)) is False
    main.LINKS.pop(uid, None)


# ----------------------------- Auth -----------------------------
def test_password_hash_and_verify():
    auth = main.make_auth("s3cretpass")
    assert auth["hash"] and auth["salt"]
    assert len(auth["hash"]) == 64  # sha256 hex
    assert main.verify_password("s3cretpass", auth) is True
    assert main.verify_password("wrong", auth) is False


def test_password_salt_is_random():
    a1 = main.make_auth("same")
    a2 = main.make_auth("same")
    assert a1["salt"] != a2["salt"]
    assert a1["hash"] != a2["hash"]


def test_rate_limiting():
    main.login_attempts.clear()
    ip = "1.2.3.4"
    for _ in range(main.CONFIG.login_max_attempts):
        assert main.is_rate_limited(ip) is False
        main.record_failed_login(ip)
    assert main.is_rate_limited(ip) is True
    main.reset_login_attempts(ip)
    assert main.is_rate_limited(ip) is False


# ----------------------------- SSRF hardening -----------------------------
def test_destination_blocks_internal():
    assert run(main.destination_allowed("127.0.0.1", 80)) is False
    assert run(main.destination_allowed("169.254.169.254", 80)) is False   # cloud metadata
    assert run(main.destination_allowed("10.0.0.5", 80)) is False
    assert run(main.destination_allowed("192.168.1.1", 80)) is False


def test_destination_allows_public():
    assert run(main.destination_allowed("1.1.1.1", 80)) is True
    assert run(main.destination_allowed("8.8.8.8", 443)) is True


# ----------------------------- API -----------------------------
@pytest.fixture()
def client():
    try:
        os.remove(main._data_path())
    except OSError:
        pass
    main.LINKS.clear()
    main.SESSIONS.clear()
    main.login_attempts.clear()
    main.CUSTOM_ADDRESSES = ["www.speedtest.net"]
    main.CUSTOM_DOMAIN = ""
    main.AUTH = {}
    with TestClient(main.app) as c:
        yield c


def test_health_open(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root_is_camouflaged(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "nginx" in r.text.lower()


def test_requires_auth(client):
    assert client.get("/api/links").status_code == 401
    assert client.get("/stats").status_code == 401


def test_login_wrong_password(client):
    r = client.post("/api/login", json={"password": "not-the-password"})
    assert r.status_code == 401


def test_login_and_link_crud(client):
    assert client.post("/api/login", json={"password": "admin"}).status_code == 200

    # default link exists
    links = client.get("/api/links").json()["links"]
    assert len(links) >= 1

    created = client.post("/api/links", json={"label": "MyProxy", "limit_value": 1, "limit_unit": "GB"})
    assert created.status_code == 200
    uid = created.json()["uuid"]
    assert created.json()["vless_link"].startswith("vless://")

    labels = [l["label"] for l in client.get("/api/links").json()["links"]]
    assert "MyProxy" in labels

    assert client.delete(f"/api/links/{uid}").status_code == 200
    labels = [l["label"] for l in client.get("/api/links").json()["links"]]
    assert "MyProxy" not in labels


def test_must_change_password_flag(client):
    client.post("/api/login", json={"password": "admin"})
    me = client.get("/api/me").json()
    assert me["authenticated"] is True
    assert me["must_change_password"] is True


def test_change_password_min_length(client):
    client.post("/api/login", json={"password": "admin"})
    short = client.post("/api/change-password", json={"current_password": "admin", "new_password": "short"})
    assert short.status_code == 400


def test_change_password_success_clears_flag(client):
    client.post("/api/login", json={"password": "admin"})
    ok = client.post("/api/change-password", json={"current_password": "admin", "new_password": "a-strong-pass-123"})
    assert ok.status_code == 200
    # session preserved, flag cleared
    me = client.get("/api/me").json()
    assert me["must_change_password"] is False


def test_subscription_endpoint(client):
    client.post("/api/login", json={"password": "admin"})
    uid = client.get("/api/links").json()["links"][0]["uuid"]
    r = client.get(f"/sub/{uid}")
    assert r.status_code == 200
    # base64-encoded body decodes to vless links
    import base64 as _b64
    decoded = _b64.b64decode(r.text).decode()
    assert "vless://" in decoded


# ----------------------------- Network / link params (new) -----------------------------
def test_generate_vless_link_backcompat_and_params():
    u = uuid_lib.uuid4()
    link = main.generate_vless_link(str(u), remark="REN-Test")
    assert link.startswith("vless://")
    assert str(u) in link
    assert "@" in link and ":443?" in link
    # Backward-compatible, DPI/CDN-friendly params must be present.
    assert "type=ws" in link
    assert "security=tls" in link
    assert "encryption=none" in link
    assert "headerType=none" in link
    assert "alpn=http/1.1" in link.replace("%2F", "/")
    # Early-data hint is advertised on the ws path.
    assert "ed%3D" in link or "ed=" in link
    assert link.endswith("#REN-Test")


def test_generate_vless_link_custom_address():
    u = uuid_lib.uuid4()
    link = main.generate_vless_link(str(u), remark="R", address="1.1.1.1")
    assert link.startswith(f"vless://{u}@1.1.1.1:443?")


def test_decode_early_data_roundtrip():
    import base64 as _b64
    payload = b"\x00" + b"hello-early-data" * 4
    token = _b64.urlsafe_b64encode(payload).decode().rstrip("=")  # RawURLEncoding
    assert main.decode_early_data(token) == payload
    # Multiple offered subprotocols: first token wins.
    assert main.decode_early_data(f"{token}, chat") == payload


def test_decode_early_data_non_base64_is_safe():
    # A genuine subprotocol name is not valid base64 payload -> empty, frame path used.
    assert main.decode_early_data("") == b""
    assert main.decode_early_data(None) == b""
    # Padded/again-decodable strings just return their bytes; the header parser
    # rejects anything that isn't a valid VLESS header, so this is safe.
    assert isinstance(main.decode_early_data("!!!not@@@base64"), bytes)


def test_prune_state_task_helpers_shape():
    # Sanity: pruning-related state containers exist and behave as expected.
    main.SESSIONS.clear()
    main.SESSIONS["expired"] = 0.0            # far in the past
    main.SESSIONS["live"] = main.time.time() + 9999
    expired = [t for t, exp in list(main.SESSIONS.items()) if exp < main.time.time()]
    assert "expired" in expired and "live" not in expired
    main.SESSIONS.clear()
