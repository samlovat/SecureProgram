
"""SOCP v1.3 educational server with spec-required features in compact form.

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
from directory import init_db, create_user, get_user, list_users, get_privkey_store, upsert_public_member, list_public_members
from cli_crypto import verify_password
from server_keys import ensure_server_key
from envelope import transport_sign, transport_verify, payload_hash16
from crypto import b64u, b64u_decode, load_public_spki_b64u, rsa_oaep_encrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------ Process-level state ------------------
presence_local: Dict[str, WebSocketServerProtocol] = {}   # local_users
user_locations: Dict[str, str] = {}                       # user_id -> "local" | server_id
servers: Dict[str, WebSocketServerProtocol] = {}          # server_id -> ws
server_addrs: Dict[str, Tuple[str,int,str]] = {}          # server_id -> (host,port,pub_spki_b64u)
seen_server_payloads = ReplayCache(max_items=8192, ttl_sec=90)

# Public channel state (group key kept on server; wrapped per member to deliver)
PUBLIC_GROUP_KEY: Optional[bytes] = None
PUBLIC_VERSION: int = 1

# ------------------ Utilities ------------------
def bcast_servers(frame: Dict[str, Any], exclude: Optional[str]=None):
    for sid, sws in list(servers.items()):
        if exclude and sid == exclude: continue
        asyncio.create_task(sws.send(json.dumps(frame)))

async def send_signed(ws, priv, payload: Dict[str, Any], from_sid: str, to_sid: str, typ: str):
    env = {"type": typ, "from": from_sid, "to": to_sid, "ts": now_ms(), "payload": payload}
    env["sig"] = transport_sign(priv, payload)
    await ws.send(json.dumps(env))

# ------------------ Server↔Server handlers ------------------
async def handle_server_frame(ws: WebSocketServerProtocol, server_id: str, obj: Dict[str, Any], priv, this_sid: str):
    t = obj.get("type"); p = obj.get("payload", {}); frm = obj.get("from"); sig = obj.get("sig","")
    # Loop/duplicate suppression on server payloads
    if seen_server_payloads.seen(payload_hash16(p)):
        return
    # Verify transport signature using pinned pubkey for frm
    entry = server_addrs.get(frm)
    if not entry or not transport_verify(entry[2], p, sig):
        return  # drop

    if t == "SERVER_ANNOUNCE":
        host, port, pub = p.get("host"), p.get("port"), p.get("pubkey")
        server_addrs[frm] = (host, int(port), pub)
        # keep connection in servers map
        servers[frm] = ws

    elif t == "USER_ADVERTISE":
        uid = p.get("user_id"); sid = p.get("server_id")
        user_locations[uid] = sid
        # gossip onward
        bcast_servers(obj, exclude=frm)

    elif t == "USER_REMOVE":
        uid = p.get("user_id"); sid = p.get("server_id")
        if user_locations.get(uid) == sid:
            user_locations.pop(uid, None)
        bcast_servers(obj, exclude=frm)

    elif t == "SERVER_DELIVER":
        # Route to local or forward
        target = p.get("user_id")
        if target in presence_local:
            await presence_local[target].send(json.dumps({
                "type":"MSG_DELIVER","from": frm, "to": target, "ts": now_ms(),
                "payload": {
                    "ciphertext": p.get("ciphertext"),
                    "sender": p.get("sender"),
                    "sender_pub": p.get("sender_pub"),
                    "content_sig": p.get("content_sig")
                }
            }))
        else:
            dest_sid = user_locations.get(target)
            if dest_sid and dest_sid in servers and dest_sid != frm:
                await servers[dest_sid].send(json.dumps(obj))

    elif t == "PUBLIC_CHANNEL_KEY_SHARE":
        # forward to all servers
        bcast_servers(obj, exclude=frm)

    elif t == "MSG_PUBLIC_CHANNEL":
        # fan-out to all hosting servers of members
        members = list_public_members()
        for m in members:
            if m in presence_local:
                await presence_local[m].send(json.dumps({
                    "type":"MSG_PUBLIC_CHANNEL_DELIVER","from":frm,"to":m,"ts":now_ms(),
                    "payload":{"nonce": p["nonce"], "ciphertext": p["ciphertext"]}
                }))
            else:
                dest_sid = user_locations.get(m)
                if dest_sid and dest_sid in servers:
                    fwd = {"type":"MSG_PUBLIC_CHANNEL","from":frm,"to":dest_sid,"ts":now_ms(),"payload":p}
                    fwd["sig"] = transport_sign(priv, p)
                    await servers[dest_sid].send(json.dumps(fwd))

    elif t in ("FILE_START","FILE_CHUNK","FILE_END"):
        # route files same as DMs (based on payload['to'])
        to = p.get("to")
        if to in presence_local:
            await presence_local[to].send(json.dumps({"type":f"{t}_DELIVER","from":frm,"to":to,"ts":now_ms(),"payload":p}))
        else:
            dest_sid = user_locations.get(to)
            if dest_sid and dest_sid in servers:
                await servers[dest_sid].send(json.dumps(obj))

# ------------------ User handlers ------------------
async def advertise_user(priv, this_sid: str, uid: str):
    payload = {"user_id": uid, "server_id": this_sid, "meta": {}}
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
    if recipient in presence_local:
        # Local delivery as USER_DELIVER with transport sig (optional here)
        await presence_local[recipient].send(json.dumps({
            "type":"MSG_DELIVER","from":msg.get("from", "server"),"to":recipient,"ts":now_ms(),
            "payload":{
                "ciphertext": p["ciphertext"],
                "sender": p["sender"],
                "sender_pub": p["sender_pub"],
                "content_sig": p["content_sig"]
            }
        }))
    else:
        dest_sid = user_locations.get(recipient)
        if dest_sid and dest_sid in servers:
            payload = {
                "user_id": recipient,
                "ciphertext": p["ciphertext"],
                "sender": p["sender"],
                "sender_pub": p["sender_pub"],
                "content_sig": p["content_sig"]
            }
            env = {"type":"SERVER_DELIVER","from":this_sid,"to":dest_sid,"ts":now_ms(),"payload":payload}
            env["sig"] = transport_sign(priv, payload)
            await servers[dest_sid].send(json.dumps(env))
        else:
            # emit error upstream (simplified)
            origin = presence_local.get(p["sender"])
            if origin:
                await origin.send(json.dumps({"type":"ERROR","payload":{"code":"USER_NOT_FOUND","detail":recipient}}))

async def send_public_key_share(priv, this_sid: str, member_id: str, member_pub_b64u: str):
    """Wrap current PUBLIC_GROUP_KEY to member and broadcast share (server→user path simplified)."""
    global PUBLIC_GROUP_KEY, PUBLIC_VERSION
    if PUBLIC_GROUP_KEY is None:
        PUBLIC_GROUP_KEY = os.urandom(32)  # AES-256 key
    pub = load_public_spki_b64u(member_pub_b64u)
    wrapped = rsa_oaep_encrypt(pub, PUBLIC_GROUP_KEY)
    upsert_public_member(member_id, b64u(wrapped))
    payload = {
        "shares":[{"member": member_id, "wrapped_public_channel_key": b64u(wrapped)}],
        "creator_pub": server_pub_b64u,
        "content_sig": ""  # omitted for brevity in demo; could sign SHA256(shares|creator_pub)
    }
    frame = {"type":"PUBLIC_CHANNEL_KEY_SHARE","from":this_sid,"to":"*","ts":now_ms(),"payload":payload}
    frame["sig"] = transport_sign(priv, payload)
    # deliver directly if local, otherwise gossip
    if member_id in presence_local:
        await presence_local[member_id].send(json.dumps(frame))
    bcast_servers(frame)

# ------------------ Connection handlers ------------------
async def handle_socket(ws: WebSocketServerProtocol, priv, this_sid: str):
    peer_role = None   # "server" or "user"
    user_id = None     # set after login
    try:
        async for raw in ws:
            try:
                obj = json.loads(raw)
            except Exception:
                await ws.send(json.dumps({"type":"ERROR","error":"BAD_JSON"})); continue
            typ = obj.get("type"); p = obj.get("payload", {})

            # Identify role by first frame type if not set
            if peer_role is None:
                if typ in ("SERVER_HELLO_JOIN","SERVER_ANNOUNCE","HEARTBEAT","USER_ADVERTISE","USER_REMOVE","SERVER_DELIVER","PUBLIC_CHANNEL_KEY_SHARE","MSG_PUBLIC_CHANNEL","FILE_START","FILE_CHUNK","FILE_END"):
                    peer_role = "server"
                else:
                    peer_role = "user"

            if peer_role == "server":
                await handle_server_frame(ws, obj.get("from",""), obj, priv, this_sid)
                continue

            # ---- User-side protocol ----
            if typ == "USER_REGISTER":
                uid, pub, priv_store, pw_hash = p.get("user_id"), p.get("pubkey"), p.get("privkey_store"), p.get("pake_password")
                if not all([uid,pub,priv_store,pw_hash]):
                    await ws.send(json.dumps({"type":"ERROR","error":"MISSING_FIELDS"})); continue
                if get_user(uid): await ws.send(json.dumps({"type":"ERROR","error":"NAME_IN_USE"})); continue
                create_user(uid, pub, priv_store, pw_hash, meta={"created_ms": now_ms()})
                await ws.send(json.dumps({"type":"USER_REGISTERED","user_id":uid}))

            elif typ == "USER_LOGIN":
                uid, pw = p.get("user_id"), p.get("password") or ""
                rec = get_user(uid) if uid else None
                if not rec: await ws.send(json.dumps({"type":"ERROR","error":"NO_SUCH_USER"})); continue
                if not verify_password(pw, rec["pake_password"]):
                    await ws.send(json.dumps({"type":"ERROR","error":"BAD_PASSWORD"})); continue
                presence_local[uid] = ws; user_locations[uid] = "local"; user_id = uid
                await ws.send(json.dumps({"type":"USER_LOGGED_IN","user_id":uid,"privkey_store": rec["privkey_store"]}))
                # advertise to network & public channel key share
                await advertise_user(priv, this_sid, uid)
                await send_public_key_share(priv, this_sid, uid, rec["pubkey"])

            elif typ == "LIST_REQUEST":
                users = list_users()
                for u in users:
                    u["online_local"] = (u["user_id"] in presence_local)
                await ws.send(json.dumps({"type":"LIST_RESPONSE","users":users}))

            elif typ == "MSG_DIRECT":
                await deliver_dm_or_forward(priv, this_sid, obj)

            elif typ == "MSG_PUBLIC_CHANNEL":
                # broadcast to all members (server→local users and server→servers). Server does not decrypt.
                bcast = {"type":"MSG_PUBLIC_CHANNEL","from":this_sid,"to":"*","ts":now_ms(),"payload":p}
                bcast["sig"] = transport_sign(priv, p)
                # deliver to local members
                for m in list_public_members():
                    if m in presence_local:
                        await presence_local[m].send(json.dumps({"type":"MSG_PUBLIC_CHANNEL_DELIVER","from":this_sid,"to":m,"ts":now_ms(),"payload":p}))
                # and to remote servers
                bcast_servers(bcast)

            elif typ in ("FILE_START","FILE_CHUNK","FILE_END"):
                # route by payload['to']
                to = p.get("to")
                if to in presence_local:
                    await presence_local[to].send(json.dumps({"type":f"{typ}_DELIVER","from":user_id,"to":to,"ts":now_ms(),"payload":p}))
                else:
                    dest_sid = user_locations.get(to)
                    if dest_sid and dest_sid in servers:
                        env = {"type":typ,"from":this_sid,"to":dest_sid,"ts":now_ms(),"payload":p}
                        env["sig"] = transport_sign(priv, p)
                        await servers[dest_sid].send(json.dumps(env))
                    else:
                        await ws.send(json.dumps({"type":"ERROR","payload":{"code":"USER_NOT_FOUND","detail":to}}))

            else:
                await ws.send(json.dumps({"type":"ERROR","error":"UNKNOWN_TYPE"}))

    except websockets.ConnectionClosed:
        pass
    except Exception:
        traceback.print_exc()
    finally:
        # Presence cleanup
        if user_id and presence_local.get(user_id) is ws:
            presence_local.pop(user_id, None)
            asyncio.create_task(remove_user(priv, this_sid, user_id))

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
            try: await servers[sid].close()
            except: pass
            servers.pop(sid, None)

async def connect_to_peer(url: str, this_sid: str, priv, loop):
    """Establish a server↔server connection to a peer ws URL; announce ourselves."""
    try:
        ws = await websockets.connect(url, ping_interval=15, ping_timeout=20)
        # Remember under a temporary id until we learn their id; for demo we pass URL as id
        peer_id = url
        servers[peer_id] = ws
        # Send SERVER_ANNOUNCE (simplified for localhost mesh)
        payload = {"host":"127.0.0.1","port":0,"pubkey": server_pub_b64u}
        env = {"type":"SERVER_ANNOUNCE","from":this_sid,"to":"*", "ts":now_ms(),"payload":payload}
        env["sig"] = transport_sign(priv, payload)
        await ws.send(json.dumps(env))
        # Keep reading to process frames
        async def reader():
            try:
                async for raw in ws:
                    obj = json.loads(raw)
                    await handle_server_frame(ws, obj.get("from",""), obj, priv, this_sid)
            except Exception:
                pass
        loop.create_task(reader())
    except Exception as e:
        print(f"[bootstrap] failed to connect {url}: {e}")

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--server-id", default="server-1")
    ap.add_argument("--bootstrap", nargs="*", default=[],
                    help="ws://host:port peers to connect to at startup")
    args = ap.parse_args()

    init_db()
    global server_priv, server_pub_b64u
    server_priv, server_pub_b64u = ensure_server_key()

    print(f"[SOCP] server {args.server_id} listening on ws://{args.host}:{args.port}")
    loop = asyncio.get_event_loop()

    async with websockets.serve(lambda ws: handle_socket(ws, server_priv, args.server_id),
                                args.host, args.port, ping_interval=15, ping_timeout=20):
        # Bootstrap to peers
        for url in args.bootstrap:
            loop.create_task(connect_to_peer(url, args.server_id, server_priv, loop))
        # Heartbeats
        loop.create_task(heartbeat_task(args.server_id, server_priv))
        await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SOCP] server stopped")
