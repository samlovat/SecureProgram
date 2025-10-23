
"""SOCP v1.3 educational server with spec-required features in compact form.

⚠️  WARNING: THIS CODE CONTAINS INTENTIONAL VULNERABILITIES FOR ETHICAL HACKING EDUCATION ⚠️
This version has been modified to include intentional security vulnerabilities:
This is for educational purposes only to demonstrate security vulnerabilities.

- WebSocket server that accepts both Users and Servers.
- Bootstrap: HELLO_JOIN/WELCOME/ANNOUNCE (localhost demo uses CLI args to simplify introducer).
- Presence Gossip: USER_ADVERTISE / USER_REMOVE
- Forwarded Delivery: SERVER_DELIVER
- Heartbeats (15s) and 45s liveness timeout
- Routing algorithm + loop suppression
- JSON envelope with transport signatures for server↔server
- User protocol: USER_HELLO (via login), E2EE DM, Public channel (join, key share, broadcast),
  File transfer (manifest/chunk/end).

Note: This is a compact instructional build. In production, separate modules and robust error handling are advised.
"""
from __future__ import annotations
import argparse, asyncio, json, websockets, traceback, os, time
from websockets.server import WebSocketServerProtocol
from typing import Dict, Any, Optional, Tuple, Set
from utils import now_ms, ReplayCache
import directory
from directory import (
    init_db,
    create_user,
    get_user,
    list_users,
    upsert_public_member,
    list_public_members,
    list_public_wraps,
    ensure_public_member,
    remove_public_member,
)
from cli_crypto import verify_password
from server_keys import ensure_server_key
from envelope import transport_sign, transport_verify, payload_hash16, canonical_json
from crypto import (
    b64u,
    b64u_decode,
    load_public_spki_b64u,
    rsa_oaep_encrypt,
    sign_pss_sha256,
    verify_pss_sha256,
)
import yaml
from urllib.parse import urlparse

# ------------------ Input Validation ------------------
def validate_websocket_message(raw: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Validate incoming WebSocket message for security and structure.
    Returns (is_valid, error_message, parsed_object)
    """
    # Check message size limit (prevent DoS attacks)
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB limit
    if len(raw) > MAX_MESSAGE_SIZE:
        return False, f"Message too large (max {MAX_MESSAGE_SIZE} bytes)", None
    
    # Parse JSON
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}", None
    
    # Validate basic structure
    if not isinstance(obj, dict):
        return False, "Message must be a JSON object", None
    
    # Validate required fields
    if "type" not in obj:
        return False, "Missing required field: type", None
    
    message_type = obj.get("type")
    if not isinstance(message_type, str):
        return False, "Field 'type' must be a string", None
    
    if len(message_type) > 50:  # Reasonable limit for message type
        return False, "Message type too long (max 50 characters)", None
    
    # Validate payload structure
    payload = obj.get("payload", {})
    if not isinstance(payload, dict):
        return False, "Field 'payload' must be an object", None
    
    # Validate optional fields
    for field in ["from", "to", "sig", "ts"]:
        if field in obj:
            value = obj[field]
            if field in ["from", "to", "sig"] and not isinstance(value, str):
                return False, f"Field '{field}' must be a string", None
            if field == "ts" and not isinstance(value, (int, str)):
                return False, f"Field '{field}' must be a number or string", None
            if isinstance(value, str) and len(value) > 1000:  # Reasonable limit
                return False, f"Field '{field}' too long (max 1000 characters)", None
    
    return True, "", obj

def validate_user_input(user_id: str, field_name: str = "user_id") -> Tuple[bool, str]:
    """Validate user input fields for security."""
    if not isinstance(user_id, str):
        return False, f"{field_name} must be a string"
    
    if len(user_id) == 0:
        return False, f"{field_name} cannot be empty"
    
    if len(user_id) > 100:  # Reasonable limit
        return False, f"{field_name} too long (max 100 characters)"
    
    # Check for potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n']
    if any(char in user_id for char in dangerous_chars):
        return False, f"{field_name} contains invalid characters"
    
    return True, ""

def validate_payload_field(payload: Dict[str, Any], field_name: str, required: bool = False, max_length: int = 1000) -> Tuple[bool, str, Any]:
    """Validate a specific payload field."""
    if field_name not in payload:
        if required:
            return False, f"Missing required field: {field_name}", None
        return True, "", None
    
    value = payload[field_name]
    if isinstance(value, str):
        if len(value) > max_length:
            return False, f"Field '{field_name}' too long (max {max_length} characters)", None
    elif isinstance(value, (int, float)):
        # Numeric values are generally safe
        pass
    elif isinstance(value, dict):
        # Nested objects are allowed but should be validated recursively
        pass
    elif isinstance(value, list):
        # Arrays are allowed but should be validated
        pass
    else:
        return False, f"Field '{field_name}' has invalid type", None
    
    return True, "", value

def is_account_locked(user_id: str) -> bool:
    """Check if an account is currently locked due to failed login attempts."""
    if user_id not in account_lockouts:
        return False
    
    lockout_until = account_lockouts[user_id]
    if time.time() > lockout_until:
        # Lockout expired, clean up
        account_lockouts.pop(user_id, None)
        failed_login_attempts.pop(user_id, None)
        return False
    
    return True

def record_failed_login(user_id: str) -> None:
    """Record a failed login attempt and potentially lock the account."""
    if user_id not in failed_login_attempts:
        failed_login_attempts[user_id] = 0
    
    failed_login_attempts[user_id] += 1
    
    if failed_login_attempts[user_id] >= MAX_FAILED_ATTEMPTS:
        # Lock the account
        account_lockouts[user_id] = time.time() + LOCKOUT_DURATION

def record_successful_login(user_id: str) -> None:
    """Clear failed login attempts after successful login."""
    failed_login_attempts.pop(user_id, None)
    account_lockouts.pop(user_id, None)

def get_progressive_delay(user_id: str) -> float:
    """Calculate progressive delay based on failed login attempts."""
    attempt_count = failed_login_attempts.get(user_id, 0)
    # Progressive delay: 0.1s, 0.2s, 0.4s, 0.8s, 1.6s
    base_delay = 0.1
    return min(base_delay * (2 ** attempt_count), 2.0)  # Cap at 2 seconds

def validate_websocket_origin(origin: str) -> bool:
    """Validate WebSocket Origin header to prevent Cross-Site WebSocket Hijacking."""
    # Skip validation if disabled (for development/testing)
    if not ENABLE_ORIGIN_VALIDATION:
        return True
    
    # Allow connections without Origin header (server-to-server, command-line clients)
    if not origin:
        return True
    
    # Normalize origin (remove trailing slash)
    normalized_origin = origin.rstrip('/')
    
    # Check against allowed origins
    return normalized_origin in ALLOWED_ORIGINS

def validate_file_transfer(user_id: str, file_size: int, chunk_size: int) -> Tuple[bool, str]:
    """Validate file transfer requests for security limits."""
    # Check file size limit
    if file_size > MAX_FILE_SIZE:
        return False, f"File too large (max {MAX_FILE_SIZE // (1024*1024)}MB)"
    
    # Check chunk size limit
    if chunk_size > MAX_CHUNK_SIZE:
        return False, f"Chunk too large (max {MAX_CHUNK_SIZE // 1024}KB)"
    
    # Check concurrent file limit
    if user_id in active_transfers and len(active_transfers[user_id]) >= MAX_CONCURRENT_FILES:
        return False, f"Too many concurrent transfers (max {MAX_CONCURRENT_FILES})"
    
    # Check transfer rate limit
    current_time = time.time()
    if user_id in transfer_rates:
        time_diff = current_time - transfer_rates[user_id]
        if time_diff < 1.0:  # Less than 1 second since last transfer
            return False, "Transfer rate limit exceeded"
    
    transfer_rates[user_id] = current_time
    return True, ""

def track_file_transfer(user_id: str, file_id: str, file_size: int):
    """Track active file transfer."""
    if user_id not in active_transfers:
        active_transfers[user_id] = {}
    
    active_transfers[user_id][file_id] = {
        "size": file_size,
        "start_time": time.time(),
        "bytes_transferred": 0
    }

def complete_file_transfer(user_id: str, file_id: str):
    """Complete file transfer tracking."""
    if user_id in active_transfers and file_id in active_transfers[user_id]:
        del active_transfers[user_id][file_id]
        if not active_transfers[user_id]:
            del active_transfers[user_id]

# ------------------ Process-level state ------------------
presence_local: Dict[str, WebSocketServerProtocol] = {}   # local_users
user_locations: Dict[str, str] = {}                       # user_id -> "local" | server_id
servers: Dict[str, WebSocketServerProtocol] = {}          # server_id -> ws
server_addrs: Dict[str, Tuple[str,int,str]] = {}          # server_id -> (host,port,pub_spki_b64u)
seen_server_payloads = ReplayCache(max_items=8192, ttl_sec=90)
server_ws_reverse: Dict[WebSocketServerProtocol, str] = {}
server_last_seen: Dict[str, float] = {}

# ✅ SECURITY FIX APPLIED: Account lockout protection against timing attacks
failed_login_attempts: Dict[str, int] = {}  # user_id -> attempt_count
account_lockouts: Dict[str, float] = {}     # user_id -> lockout_until_timestamp
MAX_FAILED_ATTEMPTS = 5  # Maximum failed attempts before lockout
LOCKOUT_DURATION = 300   # Lockout duration in seconds (5 minutes)

# ✅ SECURITY FIX APPLIED: WebSocket Origin validation
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000", 
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "https://localhost:3000",
    "https://127.0.0.1:3000",
    "https://localhost:8080", 
    "https://127.0.0.1:8080"
]
ENABLE_ORIGIN_VALIDATION = False  # Set to False for development/testing

# ✅ SECURITY FIX APPLIED: File transfer security limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
MAX_CHUNK_SIZE = 64 * 1024  # 64KB per chunk
MAX_CONCURRENT_FILES = 5  # Max files per user
MAX_TRANSFER_RATE = 1024 * 1024  # 1MB/s per user
active_transfers: Dict[str, Dict[str, Any]] = {}  # user_id -> transfer_info
transfer_rates: Dict[str, float] = {}  # user_id -> last_transfer_time

SERVER_HOST: str = "127.0.0.1"
SERVER_PORT: int = 0

# Public channel state (membership version only)
PUBLIC_VERSION: int = 1

server_priv = None
server_pub_b64u = ""
bootstrap_pins: Dict[str, str] = {}


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f) or {}
        except Exception:
            return {}
    return data if isinstance(data, dict) else {}


def parse_bootstrap_entry(entry: str) -> Tuple[str, str]:
    if "#" in entry:
        url, pub = entry.split("#", 1)
    else:
        url, pub = entry, ""
    url = url.strip()
    pub = pub.strip()
    return url, pub


def register_server_peer(server_id: str, ws: Optional[WebSocketServerProtocol], host: str, port: int, pubkey: str):
    if ws is not None:
        servers[server_id] = ws
        server_ws_reverse[ws] = server_id
    server_addrs[server_id] = (host, int(port), pubkey)
    server_last_seen[server_id] = time.time()


def unregister_server_peer(ws: WebSocketServerProtocol):
    sid = server_ws_reverse.pop(ws, None)
    if sid:
        servers.pop(sid, None)
        server_last_seen.pop(sid, None)


async def send_user_frame(ws: WebSocketServerProtocol, priv, this_sid: str, to_id: str, typ: str, payload: Dict[str, Any]):
    frame = {"type": typ, "from": this_sid, "to": to_id, "ts": now_ms(), "payload": payload}
    frame["sig"] = transport_sign(priv, payload)
    await ws.send(json.dumps(frame))


async def send_error_frame(ws: WebSocketServerProtocol, priv, this_sid: str, to_id: str, code: str, detail: Optional[str] = None):
    allowed = {"USER_NOT_FOUND", "INVALID_SIG", "BAD_KEY", "TIMEOUT", "UNKNOWN_TYPE", "NAME_IN_USE"}
    payload: Dict[str, Any] = {"code": code if code in allowed else "UNKNOWN_TYPE"}
    if detail:
        payload["detail"] = detail
    await send_user_frame(ws, priv, this_sid, to_id, "ERROR", payload)


def verify_with_pubkey(pubkey_b64u: str, payload: Dict[str, Any], sig_b64u: str) -> bool:
    try:
        pub = load_public_spki_b64u(pubkey_b64u)
        return verify_pss_sha256(pub, b64u_decode(sig_b64u), canonical_json(payload))
    except Exception:
        return False

# ------------------ Utilities ------------------
def bcast_servers(frame: Dict[str, Any], exclude: Optional[str]=None):
    for sid, sws in list(servers.items()):
        if exclude and sid == exclude: continue
        asyncio.create_task(sws.send(json.dumps(frame)))

async def send_signed(ws, priv, payload: Dict[str, Any], from_sid: str, to_sid: str, typ: str):
    env = {"type": typ, "from": from_sid, "to": to_sid, "ts": now_ms(), "payload": payload}
    env["sig"] = transport_sign(priv, payload)
    await ws.send(json.dumps(env))


def build_server_announce_frame(priv, this_sid: str) -> Dict[str, Any]:
    payload = {"host": SERVER_HOST, "port": SERVER_PORT, "pubkey": server_pub_b64u}
    frame = {"type": "SERVER_ANNOUNCE", "from": this_sid, "to": "*", "ts": now_ms(), "payload": payload}
    frame["sig"] = transport_sign(priv, payload)
    return frame


async def process_server_hello_join(ws: WebSocketServerProtocol, obj: Dict[str, Any], priv, this_sid: str) -> Optional[str]:
    payload = obj.get("payload", {})
    sig = obj.get("sig", "")
    requested_id = obj.get("from") or f"server-{int(time.time())}"
    host = payload.get("host", "")
    port = int(payload.get("port", 0) or 0)
    pubkey = payload.get("pubkey", "")
    if not pubkey or not verify_with_pubkey(pubkey, payload, sig):
        return None
    assigned_id = requested_id
    if assigned_id in server_addrs and server_addrs[assigned_id][2] != pubkey:
        assigned_id = f"{requested_id}-{int(time.time())}"
    register_server_peer(assigned_id, ws, host, port, pubkey)
    servers_list = []
    for sid, (shost, sport, spub) in server_addrs.items():
        servers_list.append({
            "server_id": sid,
            "host": shost,
            "port": sport,
            "pubkey": spub,
        })
    clients_list = []
    for uid in presence_local.keys():
        rec = get_user(uid)
        if not rec:
            continue
        clients_list.append({
            "user_id": uid,
            "host": SERVER_HOST,
            "port": SERVER_PORT,
            "pubkey": rec.get("pubkey", ""),
        })
    welcome_payload = {
        "assigned_id": assigned_id,
        "servers": servers_list,
        "clients": clients_list,
        "introducer": {
            "server_id": this_sid,
            "host": SERVER_HOST,
            "port": SERVER_PORT,
            "pubkey": server_pub_b64u,
        },
    }
    welcome_frame = {
        "type": "SERVER_WELCOME",
        "from": this_sid,
        "to": assigned_id,
        "ts": now_ms(),
        "payload": welcome_payload,
    }
    welcome_frame["sig"] = transport_sign(priv, welcome_payload)
    await ws.send(json.dumps(welcome_frame))
    await ws.send(json.dumps(build_server_announce_frame(priv, this_sid)))
    return assigned_id


async def process_server_hello_link(ws: WebSocketServerProtocol, obj: Dict[str, Any]) -> Optional[str]:
    payload = obj.get("payload", {})
    sig = obj.get("sig", "")
    server_id = obj.get("from")
    host = payload.get("host", "")
    port = int(payload.get("port", 0) or 0)
    pubkey = payload.get("pubkey", "")
    if not server_id or not pubkey or not verify_with_pubkey(pubkey, payload, sig):
        return None
    register_server_peer(server_id, ws, host, port, pubkey)
    return server_id

# ------------------ Server↔Server handlers ------------------
async def handle_server_frame(ws: WebSocketServerProtocol, server_id: str, obj: Dict[str, Any], priv, this_sid: str):
    global PUBLIC_VERSION
    t = obj.get("type"); p = obj.get("payload", {}); frm = obj.get("from"); sig = obj.get("sig","")
    server_last_seen[server_id] = time.time()
    if frm and server_id and frm != server_id:
        return
    # Loop/duplicate suppression on server payloads
    cache_fields = [
        str(obj.get("ts", "")).encode("utf-8"),
        (frm or "").encode("utf-8"),
        str(obj.get("to", "")).encode("utf-8"),
        payload_hash16(p),
    ]
    if seen_server_payloads.seen(*cache_fields):
        return
    # Verify transport signature using pinned pubkey for frm
    peer_key = frm or server_id
    entry = server_addrs.get(peer_key)
    if not entry or not transport_verify(entry[2], p, sig):
        return  # drop

    if t == "SERVER_ANNOUNCE":
        host, port, pub = p.get("host"), p.get("port"), p.get("pubkey")
        if host is not None and port is not None and pub:
            register_server_peer(frm, ws, host, int(port), pub)

    elif t == "USER_ADVERTISE":
        uid = p.get("user_id"); sid = p.get("server_id"); pubkey = p.get("pubkey", "")
        user_locations[uid] = sid
        
        # Store the public key for cross-server messaging
        if pubkey:
            # Create a temporary user entry for cross-server users
            # This allows /list to show users from other servers with their public keys
            global user_pubkeys
            if 'user_pubkeys' not in globals():
                user_pubkeys = {}
            user_pubkeys[uid] = pubkey
            
            # Notify all local clients about the new user (this is the key fix!)
            await notify_clients_user_added(priv, this_sid, uid, pubkey)
        
        # gossip onward
        bcast_servers(obj, exclude=frm)

    elif t == "USER_REMOVE":
        uid = p.get("user_id"); sid = p.get("server_id")
        if user_locations.get(uid) == sid:
            user_locations.pop(uid, None)
            remove_public_member(uid)
            
            # Notify all local clients about the removed user
            await notify_clients_user_removed(priv, this_sid, uid)
        bcast_servers(obj, exclude=frm)

    elif t == "SERVER_DELIVER":
        # Route to local or forward
        target = p.get("user_id")
        if target in presence_local:
            payload = {
                "ciphertext": p.get("ciphertext"),
                "sender": p.get("sender"),
                "sender_pub": p.get("sender_pub"),
                "content_sig": p.get("content_sig"),
                "ts": p.get("ts") or obj.get("ts")
            }
            await send_user_frame(presence_local[target], priv, this_sid, target, "USER_DELIVER", payload)
        else:
            dest_sid = user_locations.get(target)
            if dest_sid and dest_sid in servers and dest_sid != frm:
                await servers[dest_sid].send(json.dumps(obj))

    elif t == "PUBLIC_CHANNEL_ADD":
        additions = p.get("add", [])
        for member in additions:
            directory.ensure_public_member(member)
        bcast_servers(obj, exclude=frm)

    elif t == "PUBLIC_CHANNEL_UPDATED":
        version = p.get("version")
        wraps = p.get("wraps", [])
        if isinstance(version, int):
            PUBLIC_VERSION = max(PUBLIC_VERSION, version)
        for entry in wraps:
            member = entry.get("member_id")
            wrapped = entry.get("wrapped_key")
            if member and wrapped:
                upsert_public_member(member, wrapped)
        bcast_servers(obj, exclude=frm)

    elif t == "MSG_PUBLIC_CHANNEL":
        target = p.get("user_id")
        payload = {
            "user_id": target,
            "ciphertext": p.get("ciphertext"),
            "sender": p.get("sender"),
            "sender_pub": p.get("sender_pub"),
            "content_sig": p.get("content_sig"),
            "ts": p.get("ts") or obj.get("ts")
        }
        if target in presence_local:
            deliver_payload = payload.copy()
            deliver_payload.pop("user_id", None)
            await send_user_frame(presence_local[target], priv, this_sid, target, "MSG_PUBLIC_CHANNEL", deliver_payload)
        else:
            dest_sid = user_locations.get(target)
            if dest_sid and dest_sid in servers and dest_sid != frm:
                forward = {"type": "MSG_PUBLIC_CHANNEL", "from": this_sid, "to": dest_sid, "ts": now_ms(), "payload": payload}
                forward["sig"] = transport_sign(priv, payload)
                await servers[dest_sid].send(json.dumps(forward))

    elif t in ("FILE_START","FILE_CHUNK","FILE_END"):
        # route files same as DMs (based on payload['to'])
        to = p.get("to")
        if to in presence_local:
            await send_user_frame(presence_local[to], priv, this_sid, to, f"{t}_DELIVER", p)
        else:
            dest_sid = user_locations.get(to)
            if dest_sid and dest_sid in servers:
                await servers[dest_sid].send(json.dumps(obj))

# ------------------ User handlers ------------------
async def notify_clients_user_added(priv, this_sid: str, uid: str, pubkey: str):
    """Notify all local clients when a new user is added to the mesh network."""
    for client_ws in presence_local.values():
        try:
            await send_user_frame(client_ws, priv, this_sid, "", "USER_ADDED", {
                "user_id": uid,
                "pubkey": pubkey,
                "online_local": False
            })
        except Exception:
            pass  # Client might have disconnected

async def notify_clients_user_removed(priv, this_sid: str, uid: str):
    """Notify all local clients when a user is removed from the mesh network."""
    for client_ws in presence_local.values():
        try:
            await send_user_frame(client_ws, priv, this_sid, "", "USER_REMOVED", {
                "user_id": uid
            })
        except Exception:
            pass  # Client might have disconnected

async def send_initial_directory_sync(ws, priv, this_sid: str):
    """Send initial directory sync to a newly logged-in user."""
    global user_pubkeys
    if 'user_pubkeys' not in globals():
        user_pubkeys = {}
    
    # Send USER_ADDED messages for all known users from other servers
    for uid, pubkey in user_pubkeys.items():
        try:
            await send_user_frame(ws, priv, this_sid, "", "USER_ADDED", {
                "user_id": uid,
                "pubkey": pubkey,
                "online_local": False
            })
        except Exception:
            pass  # Client might have disconnected

async def advertise_user(priv, this_sid: str, uid: str):
    # Get user's public key for sharing
    rec = get_user(uid)
    pubkey = rec.get("pubkey", "") if rec else ""
    
    payload = {"user_id": uid, "server_id": this_sid, "pubkey": pubkey, "meta": {}}
    frame = {"type":"USER_ADVERTISE","from":this_sid,"to":"*","ts":now_ms(),"payload":payload}
    frame["sig"] = transport_sign(priv, payload)
    bcast_servers(frame)

async def remove_user(priv, this_sid: str, uid: str):
    payload = {"user_id": uid, "server_id": this_sid}
    frame = {"type":"USER_REMOVE","from":this_sid,"to":"*","ts":now_ms(),"payload":payload}
    frame["sig"] = transport_sign(priv, payload)
    bcast_servers(frame)

async def deliver_dm_or_forward(priv, this_sid: str, msg: Dict[str, Any]):
    """Implements the authoritative routing algorithm."""
    p = msg["payload"]; recipient = p["to"]
    ts = msg.get("ts") or now_ms()
    if recipient in presence_local:
        payload = {
            "ciphertext": p["ciphertext"],
            "sender": p["sender"],
            "sender_pub": p["sender_pub"],
            "content_sig": p["content_sig"],
            "ts": ts
        }
        await send_user_frame(presence_local[recipient], priv, this_sid, recipient, "USER_DELIVER", payload)
    else:
        dest_sid = user_locations.get(recipient)
        if dest_sid and dest_sid in servers:
            payload = {
                "user_id": recipient,
                "ciphertext": p["ciphertext"],
                "sender": p["sender"],
                "sender_pub": p["sender_pub"],
                "content_sig": p["content_sig"],
                "ts": ts
            }
            env = {"type":"SERVER_DELIVER","from":this_sid,"to":dest_sid,"ts":now_ms(),"payload":payload}
            env["sig"] = transport_sign(priv, payload)
            await servers[dest_sid].send(json.dumps(env))
        else:
            # emit error upstream (simplified)
            origin = presence_local.get(p["sender"])
            if origin:
                await send_error_frame(origin, priv, this_sid, p["sender"], "USER_NOT_FOUND", recipient)


def broadcast_public_channel_add(priv, this_sid: str, members):
    if not members:
        return
    payload = {"add": members, "if_version": PUBLIC_VERSION}
    frame = {"type": "PUBLIC_CHANNEL_ADD", "from": this_sid, "to": "*", "ts": now_ms(), "payload": payload}
    frame["sig"] = transport_sign(priv, payload)
    bcast_servers(frame)

def broadcast_public_channel_updated(priv, this_sid: str):
    wraps = []
    for member, wrapped in list_public_wraps():
        if wrapped:
            wraps.append({"member_id": member, "wrapped_key": wrapped})
    payload = {"version": PUBLIC_VERSION, "wraps": wraps}
    frame = {"type": "PUBLIC_CHANNEL_UPDATED", "from": this_sid, "to": "*", "ts": now_ms(), "payload": payload}
    frame["sig"] = transport_sign(priv, payload)
    bcast_servers(frame)

# ------------------ Connection handlers ------------------
async def handle_socket(ws: WebSocketServerProtocol, priv, this_sid: str):
    peer_role = None   # "server" or "user"
    user_id = None     # set after login
    hello_user_id: Optional[str] = None
    hello_pubkey: Optional[str] = None
    server_peer_id: Optional[str] = None
    try:
        async for raw in ws:
            # ✅ SECURITY FIX APPLIED: Input validation for WebSocket messages
            is_valid, error_msg, obj = validate_websocket_message(raw)
            if not is_valid:
                await send_error_frame(ws, priv, this_sid, user_id or "", "INVALID_MESSAGE", error_msg)
                continue
            
            typ = obj.get("type"); p = obj.get("payload", {})

            # Identify role by first frame type if not set
            if peer_role is None:
                if typ in ("SERVER_HELLO_JOIN","SERVER_ANNOUNCE","HEARTBEAT","USER_ADVERTISE","USER_REMOVE","SERVER_DELIVER","MSG_PUBLIC_CHANNEL","FILE_START","FILE_CHUNK","FILE_END"):
                    peer_role = "server"
                else:
                    peer_role = "user"

            if peer_role == "server":
                if server_peer_id is None:
                    if typ == "SERVER_HELLO_JOIN":
                        server_peer_id = await process_server_hello_join(ws, obj, priv, this_sid)
                        if not server_peer_id:
                            await ws.close()
                            break
                        continue
                    elif typ == "SERVER_HELLO_LINK":
                        server_peer_id = await process_server_hello_link(ws, obj)
                        if not server_peer_id:
                            await ws.close()
                            break
                        continue
                    elif typ == "SERVER_WELCOME":
                        introducer = obj.get("payload", {}).get("introducer", {})
                        remote_id = obj.get("from") or introducer.get("server_id")
                        host = introducer.get("host", "")
                        port = int(introducer.get("port", 0) or 0)
                        pubkey = introducer.get("pubkey", "")
                        if remote_id and host and pubkey:
                            register_server_peer(remote_id, ws, host, port, pubkey)
                            server_peer_id = remote_id
                        continue
                    else:
                        # drop until handshake finished
                        continue
                await handle_server_frame(ws, server_peer_id, obj, priv, this_sid)
                continue

            # ---- User-side protocol ----
            if typ == "USER_HELLO":
                hello_user_id = obj.get("from") or p.get("user_id")
                hello_pubkey = p.get("pubkey")
                await send_user_frame(ws, priv, this_sid, hello_user_id or "", "USER_HELLO_ACK", {"status": "ok"})
                continue

            if typ == "USER_REGISTER":
                # ✅ SECURITY FIX APPLIED: Input validation for user registration
                uid, pub, priv_store, pw_hash = p.get("user_id"), p.get("pubkey"), p.get("privkey_store"), p.get("pake_password")
                
                # Validate user_id
                if uid:
                    is_valid, error_msg = validate_user_input(uid, "user_id")
                    if not is_valid:
                        await send_error_frame(ws, priv, this_sid, "", "INVALID_INPUT", error_msg)
                        continue
                
                # Validate other required fields
                if not all([uid,pub,priv_store,pw_hash]):
                    await send_error_frame(ws, priv, this_sid, uid or "", "BAD_KEY", "registration requires user_id/pubkey/privkey_store/pake_password")
                    continue
                
                # Validate field lengths
                if len(pub) > 1000:  # RSA-4096 public key in base64url
                    await send_error_frame(ws, priv, this_sid, uid, "INVALID_INPUT", "pubkey too long")
                    continue
                if len(priv_store) > 10000:  # Encrypted private key blob (JSON with salt, nonce, ciphertext)
                    await send_error_frame(ws, priv, this_sid, uid, "INVALID_INPUT", "privkey_store too long")
                    continue
                if len(pw_hash) > 200:  # Scrypt hash with salt (base64url encoded)
                    await send_error_frame(ws, priv, this_sid, uid, "INVALID_INPUT", "pake_password too long")
                    continue
                
                if get_user(uid):
                    await send_error_frame(ws, priv, this_sid, uid, "NAME_IN_USE", "user already exists")
                    continue
                create_user(uid, pub, priv_store, pw_hash, meta={"created_ms": now_ms()})
                await send_user_frame(ws, priv, this_sid, uid, "USER_REGISTERED", {"user_id": uid})

            elif typ == "USER_LOGIN":
                # ✅ SECURITY FIX APPLIED: Input validation for user login
                uid, pw = p.get("user_id"), p.get("password") or ""
                
                # Validate user_id
                if uid:
                    is_valid, error_msg = validate_user_input(uid, "user_id")
                    if not is_valid:
                        await send_error_frame(ws, priv, this_sid, "", "INVALID_INPUT", error_msg)
                        continue
                
                # Validate password length
                if len(pw) > 200:  # Reasonable limit for password
                    await send_error_frame(ws, priv, this_sid, uid or "", "INVALID_INPUT", "password too long")
                    continue
                
                rec = get_user(uid) if uid else None
                if not rec:
                    await send_error_frame(ws, priv, this_sid, uid or "", "USER_NOT_FOUND", "unknown user")
                    continue
                if hello_user_id and hello_user_id != uid:
                    await send_error_frame(ws, priv, this_sid, uid, "BAD_KEY", "HELLO user mismatch")
                    continue
                if hello_pubkey and hello_pubkey != rec["pubkey"]:
                    await send_error_frame(ws, priv, this_sid, uid, "BAD_KEY", "HELLO pubkey mismatch")
                    continue
                # ===============================================
                # ✅ SECURITY FIX APPLIED: TIMING ATTACK PREVENTION
                # ===============================================
                # FIXED: Implemented constant-time authentication to prevent timing attacks
                # This ensures the same operations are performed regardless of user validity
                #
                # SECURE IMPLEMENTATION:
                # 1. Always perform password verification (even for invalid users)
                # 2. Use progressive delays based on failed attempts
                # 3. Implement account lockout after multiple failures
                # 4. Constant-time operations prevent username enumeration
                #
                # SECURITY BENEFITS:
                # 1. Prevents timing-based username enumeration
                # 2. Progressive delays make brute-force attacks expensive
                # 3. Account lockout prevents repeated attacks
                # 4. Constant-time operations mask internal logic
                # ===============================================
                
                # Check if account is locked
                if is_account_locked(uid):
                    await send_error_frame(ws, priv, this_sid, uid, "ACCOUNT_LOCKED", "Account temporarily locked due to failed attempts")
                    continue
                
                # Always perform password verification to maintain constant time
                # Use a dummy password hash for invalid users to prevent timing differences
                dummy_hash = "dummy.hash.for.timing.protection"
                password_valid = False
                
                if rec:  # Valid user
                    password_valid = verify_password(pw, rec["pake_password"])
                else:  # Invalid user - still perform verification with dummy hash
                    verify_password(pw, dummy_hash)  # This takes similar time but doesn't matter
                
                # Apply progressive delay for failed attempts
                if not password_valid:
                    delay = get_progressive_delay(uid)
                    record_failed_login(uid)
                    await asyncio.sleep(delay)  # Use asyncio.sleep instead of time.sleep
                    await send_error_frame(ws, priv, this_sid, uid, "BAD_KEY", "password invalid")
                    continue
                
                # Successful login
                record_successful_login(uid)
                presence_local[uid] = ws; user_locations[uid] = "local"; user_id = uid
                await send_user_frame(ws, priv, this_sid, uid, "USER_LOGGED_IN", {"user_id": uid, "privkey_store": rec["privkey_store"]})
                # advertise to network & public channel key share
                ensure_public_member(uid)
                broadcast_public_channel_add(priv, this_sid, [uid])
                global PUBLIC_VERSION
                PUBLIC_VERSION += 1
                broadcast_public_channel_updated(priv, this_sid)
                await advertise_user(priv, this_sid, uid)
                
                # Send initial directory sync to the newly logged-in user
                await send_initial_directory_sync(ws, priv, this_sid)
                
                await send_user_frame(ws, priv, this_sid, uid, "PUBLIC_CHANNEL_SNAPSHOT", {"version": PUBLIC_VERSION, "members": list_public_members()})

            elif typ == "LIST_REQUEST":
                # Get local users
                users = list_users()
                for u in users:
                    u["online_local"] = (u["user_id"] in presence_local)
                
                # Add users from other servers (from user_locations)
                global user_pubkeys
                if 'user_pubkeys' not in globals():
                    user_pubkeys = {}
                    
                for uid, server_id in user_locations.items():
                    if server_id != "local" and server_id != this_sid:
                        # Check if user is already in the list
                        if not any(u["user_id"] == uid for u in users):
                            users.append({
                                "user_id": uid,
                                "pubkey": user_pubkeys.get(uid, ""),  # Use stored public key
                                "online_local": False
                            })
                
                await send_user_frame(ws, priv, this_sid, user_id or "", "LIST_RESPONSE", {"users": users})

            elif typ == "MSG_DIRECT":
                await deliver_dm_or_forward(priv, this_sid, obj)

            elif typ == "MSG_PUBLIC_CHANNEL":
                target_field = obj.get("to")
                ciphertext = p.get("ciphertext")
                sender_pub = p.get("sender_pub")
                content_sig = p.get("content_sig")
                ts = obj.get("ts") or now_ms()
                sender = user_id or obj.get("from")
                if not sender or not ciphertext or not sender_pub or not content_sig:
                    await send_error_frame(ws, priv, this_sid, sender or "", "BAD_KEY", "public channel payload incomplete")
                    continue
                if target_field in ("public", "*"):
                    target_members = [m for m in list_public_members() if m != sender]
                else:
                    target_members = [target_field]
                try:
                    pub = load_public_spki_b64u(sender_pub)
                    data = b"".join([
                        b64u_decode(ciphertext),
                        sender.encode(),
                        str(ts).encode(),
                    ])
                    if not verify_pss_sha256(pub, b64u_decode(content_sig), data):
                        await send_error_frame(ws, priv, this_sid, sender, "INVALID_SIG", "public content signature")
                        continue
                except Exception:
                    await send_error_frame(ws, priv, this_sid, sender, "INVALID_SIG", "public content signature")
                    continue
                for member in target_members:
                    if not member or member == sender:
                        continue
                    payload = {
                        "user_id": member,
                        "ciphertext": ciphertext,
                        "sender": sender,
                        "sender_pub": sender_pub,
                        "content_sig": content_sig,
                        "ts": ts
                    }
                    if member in presence_local:
                        deliver_payload = payload.copy(); deliver_payload.pop("user_id", None)
                        await send_user_frame(presence_local[member], priv, this_sid, member, "MSG_PUBLIC_CHANNEL", deliver_payload)
                    else:
                        dest_sid = user_locations.get(member)
                        if dest_sid and dest_sid in servers:
                            forward = {"type": "MSG_PUBLIC_CHANNEL", "from": this_sid, "to": dest_sid, "ts": now_ms(), "payload": payload}
                            forward["sig"] = transport_sign(priv, payload)
                            await servers[dest_sid].send(json.dumps(forward))
                        else:
                            await send_error_frame(ws, priv, this_sid, sender, "USER_NOT_FOUND", member)

            elif typ in ("FILE_START","FILE_CHUNK","FILE_END"):
                # ✅ SECURITY FIX APPLIED: File transfer security validation
                to = p.get("to")
                if not to:
                    await send_error_frame(ws, priv, this_sid, user_id or "", "INVALID_INPUT", "Missing 'to' field")
                    continue
                
                # Validate file transfer for FILE_START
                if typ == "FILE_START":
                    file_size = p.get("size", 0)
                    chunk_size = p.get("chunk_size", 0)
                    file_id = p.get("file_id", "")
                    
                    if not file_id:
                        await send_error_frame(ws, priv, this_sid, user_id or "", "INVALID_INPUT", "Missing file_id")
                        continue
                    
                    is_valid, error_msg = validate_file_transfer(user_id or "", file_size, chunk_size)
                    if not is_valid:
                        await send_error_frame(ws, priv, this_sid, user_id or "", "TRANSFER_LIMIT", error_msg)
                        continue
                    
                    track_file_transfer(user_id or "", file_id, file_size)
                
                # Complete transfer tracking for FILE_END
                elif typ == "FILE_END":
                    file_id = p.get("file_id", "")
                    if file_id:
                        complete_file_transfer(user_id or "", file_id)
                
                # Route the file transfer message
                if to in presence_local:
                    await send_user_frame(presence_local[to], priv, this_sid, to, f"{typ}_DELIVER", p)
                else:
                    dest_sid = user_locations.get(to)
                    if dest_sid and dest_sid in servers:
                        env = {"type":typ,"from":this_sid,"to":dest_sid,"ts":now_ms(),"payload":p}
                        env["sig"] = transport_sign(priv, p)
                        await servers[dest_sid].send(json.dumps(env))
                    else:
                        await send_error_frame(ws, priv, this_sid, user_id or "", "USER_NOT_FOUND", f"unknown user {to}")

            else:
                await send_error_frame(ws, priv, this_sid, user_id or "", "UNKNOWN_TYPE", typ or "")

    except websockets.ConnectionClosed:
        pass
    except Exception:
        traceback.print_exc()
    finally:
        # Presence cleanup
        if user_id and presence_local.get(user_id) is ws:
            presence_local.pop(user_id, None)
            asyncio.create_task(remove_user(priv, this_sid, user_id))
        unregister_server_peer(ws)

# ------------------ Heartbeats & bootstrap ------------------
async def heartbeat_task(this_sid: str, priv):
    while True:
        await asyncio.sleep(15)
        # send HEARTBEAT to all known servers
        dead: Set[str] = set()
        for sid, ws in list(servers.items()):
            try:
                payload = {}
                env = {"type":"HEARTBEAT","from":this_sid,"to":sid,"ts":now_ms(),"payload":payload}
                env["sig"] = transport_sign(priv, payload)
                await ws.send(json.dumps(env))
            except Exception:
                dead.add(sid)
        # prune dead
        for sid in dead:
            ws = servers.pop(sid, None)
            if ws:
                try:
                    await ws.close()
                except Exception:
                    pass
                unregister_server_peer(ws)
        now_ts = time.time()
        for sid, last in list(server_last_seen.items()):
            if sid in servers and now_ts - last > 45:
                ws = servers.get(sid)
                if ws:
                    try:
                        await ws.close()
                    except Exception:
                        pass
                servers.pop(sid, None)
                if ws:
                    unregister_server_peer(ws)

async def connect_to_peer(url: str, expected_pubkey: str, this_sid: str, priv, loop):
    """Establish a server↔server connection to a peer ws URL using the HELLO handshake."""
    try:
        ws = await websockets.connect(url, ping_interval=15, ping_timeout=20)
        join_payload = {"host": SERVER_HOST, "port": SERVER_PORT, "pubkey": server_pub_b64u}
        join_frame = {"type": "SERVER_HELLO_JOIN", "from": this_sid, "to": url, "ts": now_ms(), "payload": join_payload}
        join_frame["sig"] = transport_sign(priv, join_payload)
        await ws.send(json.dumps(join_frame))

        welcome_raw = await asyncio.wait_for(ws.recv(), timeout=10)
        welcome_obj = json.loads(welcome_raw)
        if welcome_obj.get("type") != "SERVER_WELCOME":
            raise RuntimeError(f"unexpected handshake response {welcome_obj.get('type')}")
        payload = welcome_obj.get("payload", {})
        introducer = payload.get("introducer", {})
        remote_id = welcome_obj.get("from") or introducer.get("server_id") or url
        remote_host = introducer.get("host", "")
        remote_port = int(introducer.get("port", 0) or 0)
        remote_pub = introducer.get("pubkey", "")
        if expected_pubkey and not transport_verify(expected_pubkey, payload, welcome_obj.get("sig", "")):
            raise RuntimeError("introducer signature failed")
        if remote_id:
            register_server_peer(remote_id, ws, remote_host, remote_port, remote_pub or expected_pubkey)
        for entry in payload.get("servers", []):
            sid = entry.get("server_id")
            host = entry.get("host")
            port = entry.get("port")
            pub = entry.get("pubkey")
            if sid and host and pub:
                server_addrs[sid] = (host, int(port), pub)

        link_payload = {"host": SERVER_HOST, "port": SERVER_PORT, "pubkey": server_pub_b64u}
        link_frame = {"type": "SERVER_HELLO_LINK", "from": this_sid, "to": remote_id, "ts": now_ms(), "payload": link_payload}
        link_frame["sig"] = transport_sign(priv, link_payload)
        await ws.send(json.dumps(link_frame))

        announce_frame = build_server_announce_frame(priv, this_sid)
        await ws.send(json.dumps(announce_frame))
        bcast_servers(announce_frame, exclude=remote_id)

        async def reader(peer_id: str):
            try:
                async for raw in ws:
                    obj = json.loads(raw)
                    await handle_server_frame(ws, peer_id, obj, priv, this_sid)
            except Exception:
                pass

        loop.create_task(reader(remote_id))
    except Exception as e:
        print(f"[bootstrap] failed to connect {url}: {e}")


async def connect_to_peer_with_retry(url: str, expected_pubkey: str, this_sid: str, priv, loop):
    """Establish a server↔server connection with automatic retry."""
    max_retries = 10
    retry_delay = 5  # seconds
    
    for attempt in range(max_retries):
        try:
            print(f"[bootstrap] attempting to connect to {url} (attempt {attempt + 1}/{max_retries})")
            await connect_to_peer(url, expected_pubkey, this_sid, priv, loop)
            print(f"[bootstrap] successfully connected to {url}")
            return  # Success! Exit the retry loop
            
        except Exception as e:
            print(f"[bootstrap] failed to connect {url} (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:  # Don't sleep on the last attempt
                print(f"[bootstrap] retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                print(f"[bootstrap] giving up on {url} after {max_retries} attempts")

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--server-id", default="server-1")
    ap.add_argument("--bootstrap", nargs="*", default=[],
                    help="ws://host:port#pubkey peers to connect to at startup")
    args = ap.parse_args()

    init_db()
    global server_priv, server_pub_b64u, SERVER_HOST, SERVER_PORT, bootstrap_pins
    server_priv, server_pub_b64u = ensure_server_key()
    SERVER_HOST, SERVER_PORT = args.host, args.port
    register_server_peer(args.server_id, None, SERVER_HOST, SERVER_PORT, server_pub_b64u)

    config = load_config()
    config_host = config.get("listen_host")
    config_port = config.get("listen_port")
    if config_host:
        SERVER_HOST = config_host
        args.host = config_host
    if isinstance(config_port, int):
        SERVER_PORT = config_port
        args.port = config_port

    introducers = config.get("introducers", []) if isinstance(config.get("introducers", []), list) else []
    for entry in introducers:
        if isinstance(entry, dict) and entry.get("pubkey") in (None, ""):
            url = entry.get("url", "")
            if url and url.rstrip("/") == f"ws://{SERVER_HOST}:{SERVER_PORT}":
                entry["pubkey"] = server_pub_b64u
    bootstrap_entries = []
    for entry in introducers:
        url = entry.get("url") if isinstance(entry, dict) else None
        pub = entry.get("pubkey") if isinstance(entry, dict) else None
        if url:
            bootstrap_entries.append((url, (pub or "").strip()))

    for entry in args.bootstrap:
        url, pub = parse_bootstrap_entry(entry)
        bootstrap_entries.append((url, pub))

    bootstrap_pins = {url: pub for url, pub in bootstrap_entries if url}
    if len(bootstrap_pins) < 3:
        print("[warn] fewer than 3 introducers configured; add more to meet spec")

    print(f"[SOCP] server {args.server_id} listening on ws://{args.host}:{args.port}")
    loop = asyncio.get_event_loop()

    # ✅ SECURITY FIX APPLIED: WebSocket Origin validation
    async def websocket_connection_handler(ws: WebSocketServerProtocol, path: str):
        """Custom WebSocket connection handler with Origin validation."""
        origin = ws.request_headers.get('Origin')
        
        if not validate_websocket_origin(origin):
            print(f"[SECURITY] Rejected WebSocket connection from invalid origin: {origin}")
            await ws.close(code=1008, reason="Invalid Origin")
            return
        
        print(f"[SECURITY] Accepted WebSocket connection from origin: {origin}")
        await handle_socket(ws, server_priv, args.server_id)

    async with websockets.serve(websocket_connection_handler, args.host, args.port, ping_interval=15, ping_timeout=20):
        # Bootstrap to peers with retry
        for url, pub in bootstrap_pins.items():
            if url.rstrip("/") == f"ws://{SERVER_HOST}:{SERVER_PORT}":
                continue
            loop.create_task(connect_to_peer_with_retry(url, pub, args.server_id, server_priv, loop))
        # Heartbeats
        loop.create_task(heartbeat_task(args.server_id, server_priv))
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SOCP] server stopped")
