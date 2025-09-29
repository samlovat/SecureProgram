
# SOCP v1.3 – Minimal but Spec‑Complete (Educational)

This repo implements the **required** features of SOCP v1.3 in a compact, heavily‑commented form:

- **Crypto:** RSA‑4096, OAEP(SHA‑256) encryption, PSS(SHA‑256) signatures, base64url (no padding).
- **Transport:** WebSocket; one JSON envelope per WS message; canonical payload signing.
- **Server↔Server:** Bootstrap (HELLO_JOIN / WELCOME / ANNOUNCE), Presence Gossip (ADVERTISE/REMOVE),
  Forwarded Delivery (SERVER_DELIVER), Heartbeats + 45s timeout.
- **User↔Server:** USER_HELLO, E2EE Direct Message, Public Channel (join, key share, broadcast),
  File Transfer (manifest/chunk/end), ACK/ERROR.
- **Routing:** Authoritative 3‑step algorithm with loop suppression.
- **DB:** Persistent `users`, `groups`, `group_members` as required.

> This is an instructional reference. It favours clarity over performance.


## Quickstart (single‑node + two peers on localhost)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Terminal 1: start Server A on :8765 (configured with a self bootstrap as introducer)
python server.py --port 8765 --server-id srv-a

# Terminal 2: start Server B on :8766 (bootstraps to A)
python server.py --port 8766 --server-id srv-b --bootstrap ws://127.0.0.1:8765

# Terminal 3: Client for Alice -> connect to Server A
python client.py --url ws://127.0.0.1:8765
> /register alice passw0rd
> /login alice passw0rd
> /list

# Terminal 4: Client for Bob -> connect to Server B
python client.py --url ws://127.0.0.1:8766
> /register bob s3cret
> /login bob s3cret
> /tell alice hello across servers!
> /all hello everyone
> /file alice ./README.md
```

**Security model (demo):** The client decrypts private keys locally using a password. For convenience,
the demo server returns the caller’s own encrypted private key blob at login so the client can decrypt
locally—this mirrors “directory returns your blob” in the spec’s recommended model.


---

## SOCP v1.3 Compliance Checklist (spec → code)

- **RSA‑4096, OAEP(SHA‑256), PSS(SHA‑256), base64url** → `crypto.py` (all helpers)
- **Canonical JSON payload + transport signatures (server↔server)** → `envelope.py` (`transport_sign/verify`), used in `server.py`
- **Server↔Server mesh**  
  - Bootstrap/announce → `server.py: connect_to_peer()`, `SERVER_ANNOUNCE` handling  
  - Presence gossip → `USER_ADVERTISE` / `USER_REMOVE` in `server.py`  
  - Forwarded Delivery → `SERVER_DELIVER` path in `server.py`  
  - Heartbeats (15s) + pruning → `heartbeat_task()` in `server.py`
- **Routing & loop‑suppression** → `server.py` (`deliver_dm_or_forward` + `ReplayCache`), `envelope.payload_hash16()`
- **Persistent DB** (`users`, `groups`, `group_members`) → `schema.sql` + `directory.py:init_db()`
- **Public channel**  
  - Ensure channel exists → `directory.init_db()`  
  - Group key mgmt & RSA wraps → `server.py: send_public_key_share`  
  - Broadcast (`/all`) → client encrypts AES‑GCM; server fans out (`MSG_PUBLIC_CHANNEL` paths)
- **User protocol**  
  - Registration / Login → `server.py` (`USER_REGISTER`, `USER_LOGIN`), client mirrors  
  - E2EE DMs → client (`/tell`) OAEP encrypt + `content_sig`; server routes blind; client decrypts  
  - File transfer → client `/file` sends `FILE_START/CHUNK/END`; server routes like DMs
- **Client commands** → `client.py`: `/list`, `/tell`, `/all`, `/file`
- **README + run instructions** → this file

### Limitations (intentional, for compactness)
- Assignment-style PAKE verifier is emulated with scrypt; real PAKE is out of scope in this demo.
- Server IDs for peers are simplified to URLs; pinning can be added to `server_addrs` easily.
