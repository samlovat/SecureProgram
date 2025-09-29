
"""
SOCP v1.3 Client (educational). Implements:
- /register, /login, /list, /tell, /all, /file
- E2EE DM: RSA-OAEP ciphertext + content_sig
- Public channel: receives PUBLIC_CHANNEL_KEY_SHARE (wrapped AES key), decrypts and caches;
  /all encrypts plaintext under group key and broadcasts.
- File transfer: sends FILE_START / FILE_CHUNK / FILE_END (DM mode), encrypted per chunk.

Note: For simplicity, AES-GCM(256) is used for the public channel group key.
"""
from __future__ import annotations
import argparse, asyncio, websockets, json, shlex, sys, os, math
from typing import Optional, Dict
from crypto import b64u, b64u_decode, rsa_oaep_encrypt, rsa_oaep_decrypt, sign_pss_sha256, export_public_spki_b64u, load_public_spki_b64u
from cli_crypto import generate_and_encrypt, decrypt_private_key
from utils import now_ms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def sha256(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()

class Client:
    def __init__(self, url: str):
        self.url = url
        self.user_id: Optional[str] = None
        self.password: Optional[str] = None
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.priv = None  # RSA private key object (in-memory after login)
        self.pub_b64u: Optional[str] = None
        # Directory cache
        self.pubkeys: Dict[str, str] = {}  # user_id -> spki b64u
        # Public channel state
        self.group_key: Optional[bytes] = None  # AES-256 key

    async def connect(self):
        self.ws = await websockets.connect(self.url, ping_interval=15, ping_timeout=20)

    async def send(self, obj):
        await self.ws.send(json.dumps(obj))

    async def recv_loop(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "MSG_DELIVER":
                    # E2EE DM delivery: decrypt ciphertext with our private key
                    p = msg.get("payload", {})
                    ct = b64u_decode(p.get("ciphertext",""))
                    sender = p.get("sender")
                    sender_pub = p.get("sender_pub")
                    if self.priv is None:
                        print("\n[warn] no private key in memory; cannot decrypt DM")
                    else:
                        try:
                            pt = rsa_oaep_decrypt(self.priv, ct)
                            print(f"\n[DM from {sender}] {pt.decode('utf-8', 'ignore')}")
                        except Exception as e:
                            print(f"\n[DM decrypt error] {e}")
                    print("> ", end="", flush=True)

                elif t == "LIST_RESPONSE":
                    # cache pubkeys (if provided)
                    for u in msg.get("users", []):
                        if "pubkey" in u and u["pubkey"]:
                            self.pubkeys[u["user_id"]] = u["pubkey"]
                    print(f"\n{msg}")
                    print("> ", end="", flush=True)

                elif t == "PUBLIC_CHANNEL_KEY_SHARE":
                    # Server sends wrapped group key for public channel
                    p = msg.get("payload", {})
                    wraps = p.get("shares", [])
                    for w in wraps:
                        if w.get("member") == self.user_id and self.priv is not None:
                            wrapped = b64u_decode(w.get("wrapped_public_channel_key",""))
                            try:
                                key = rsa_oaep_decrypt(self.priv, wrapped)
                                self.group_key = key
                                print("\n[public] group key received & stored")
                            except Exception as e:
                                print(f"\n[public] key unwrap failed: {e}")
                    print("> ", end="", flush=True)

                elif t == "MSG_PUBLIC_CHANNEL_DELIVER":
                    # Public channel ciphertext under AES-GCM; decrypt
                    p = msg.get("payload", {})
                    if self.group_key is None:
                        print("\n[public] no group key; cannot decrypt")
                        print("> ", end="", flush=True); continue
                    try:
                        nonce = b64u_decode(p["nonce"])
                        ct = b64u_decode(p["ciphertext"])
                        aes = AESGCM(self.group_key)
                        pt = aes.decrypt(nonce, ct, None)
                        print(f"\n[public] {pt.decode('utf-8','ignore')}")
                    except Exception as e:
                        print(f"\n[public decrypt error] {e}")
                    print("> ", end="", flush=True)

                else:
                    print(f"\n{msg}")
                    print("> ", end="", flush=True)
        except websockets.ConnectionClosed:
            print("\n[disconnected]")

    async def cmd_register(self, user: str, password: str):
        # Generate RSA-4096; keep priv in-memory for this session; store encrypted blob server-side for demo
        self.priv, self.pub_b64u, enc_blob, pw_hash = generate_and_encrypt(password)
        await self.send({
            "type":"USER_REGISTER", "ts": now_ms(),
            "payload": {"user_id": user, "pubkey": self.pub_b64u, "privkey_store": enc_blob, "pake_password": pw_hash}
        })

    async def cmd_login(self, user: str, password: str):
        # Request login; server returns your encrypted private key blob so you can decrypt locally
        self.user_id, self.password = user, password
        await self.send({"type":"USER_LOGIN","ts":now_ms(),"payload":{"user_id":user,"password":password}})

    async def cmd_list(self):
        await self.send({"type":"LIST_REQUEST", "ts": now_ms()})

    async def cmd_tell(self, to: str, text: str):
        # E2EE DM: encrypt to recipient pubkey, include content_sig over (ciphertext||from||to||ts)
        if not self.user_id or not self.priv:
            print("login first"); return
        if to not in self.pubkeys:
            print("unknown recipient pubkey; try /list"); return
        pub = load_public_spki_b64u(self.pubkeys[to])
        ts = now_ms()
        ct = rsa_oaep_encrypt(pub, text.encode("utf-8"))
        # content signature by sender over tuple
        tuple_bytes = b"".join([ct, self.user_id.encode(), to.encode(), str(ts).encode()])
        content_sig = sign_pss_sha256(self.priv, tuple_bytes)
        await self.send({
            "type":"MSG_DIRECT","ts":ts,
            "payload":{
                "to": to,
                "ciphertext": b64u(ct),
                "sender": self.user_id,
                "sender_pub": self.pub_b64u,
                "content_sig": b64u(content_sig)
            }
        })

    async def cmd_all(self, text: str):
        # Public channel broadcast: AES-GCM under group key provided by server
        if self.group_key is None:
            print("no public channel key yet; wait for PUBLIC_CHANNEL_KEY_SHARE"); return
        aes = AESGCM(self.group_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, text.encode("utf-8"), None)
        await self.send({
            "type":"MSG_PUBLIC_CHANNEL","ts":now_ms(),
            "payload":{"nonce": b64u(nonce), "ciphertext": b64u(ct)}
        })

    async def cmd_file(self, to: str, path: str, chunk_size=32*1024):
        if to not in self.pubkeys:
            print("unknown recipient pubkey; try /list"); return
        pub = load_public_spki_b64u(self.pubkeys[to])
        if not os.path.exists(path):
            print(f"file not found: {path}"); return
        size = os.path.getsize(path)
        file_id = f"file-{now_ms()}"
        await self.send({"type":"FILE_START","ts":now_ms(),
                         "payload":{"file_id":file_id,"name":os.path.basename(path),"size":size,"sha256":"","mode":"dm","to":to}})
        idx = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                ct = rsa_oaep_encrypt(pub, chunk)
                await self.send({"type":"FILE_CHUNK","ts":now_ms(),
                                 "payload":{"file_id":file_id,"index":idx,"ciphertext":b64u(ct),"to":to}})
                idx += 1
        await self.send({"type":"FILE_END","ts":now_ms(),"payload":{"file_id":file_id,"to":to}})

async def repl(url: str):
    c = Client(url)
    await c.connect()
    asyncio.create_task(c.recv_loop())
    print("SOCP client ready. Commands: /register, /login, /list, /tell, /all, /file")
    print("> ", end="", flush=True)

    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line: break
        line = line.strip()
        if not line:
            print("> ", end="", flush=True); continue
        if line.startswith("/"):
            parts = shlex.split(line)
            cmd = parts[0][1:]
            try:
                if cmd == "register":
                    _, user, password = parts
                    await c.cmd_register(user, password)
                elif cmd == "login":
                    _, user, password = parts
                    await c.cmd_login(user, password)
                elif cmd == "list":
                    await c.cmd_list()
                elif cmd == "tell":
                    _, to, *rest = parts
                    await c.cmd_tell(to, " ".join(rest))
                elif cmd == "all":
                    _, *rest = parts
                    await c.cmd_all(" ".join(rest))
                elif cmd == "file":
                    _, to, path = parts
                    await c.cmd_file(to, path)
                else:
                    print(f"unknown command: {cmd}")
            except ValueError:
                print("bad usage")
        else:
            print("Commands start with /. Try /list or /tell <user> <msg>")
        print("> ", end="", flush=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765")
    args = ap.parse_args()
    try:
        asyncio.run(repl(args.url))
    except KeyboardInterrupt:
        pass
