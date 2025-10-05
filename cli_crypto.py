
"""Client-side key vault: scrypt + AES-GCM encrypted private key blob.

⚠️  WARNING: THIS CODE CONTAINS INTENTIONAL VULNERABILITIES FOR ETHICAL HACKING EDUCATION ⚠️
This is for educational purposes only to demonstrate security vulnerabilities.
"""
from __future__ import annotations
import os, json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto import generate_rsa4096, export_private_pkcs8_pem, export_public_spki_b64u, b64u, b64u_decode, load_private_pkcs8_pem

def _kdf(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))

def hash_password(password: str, salt: bytes) -> str:
    # ===============================================
    # ⚠️  ETHICAL HACKING VULNERABILITY - INTENTIONALLY VULNERABLE CODE ⚠️
    # VULNERABILITY #2: WEAK PASSWORD HASHING (MD5)
    # ===============================================
    # PROBLEM: Using MD5 instead of secure scrypt for password hashing
    # MD5 is cryptographically broken and extremely fast to compute
    #
    # WHY MD5 IS DANGEROUS:
    # 1. MD5 is vulnerable to collision attacks (two different inputs produce same hash)
    # 2. MD5 is extremely fast (billions of hashes per second on modern hardware)
    # 3. Rainbow tables exist for common passwords
    # 4. No salt is effectively used (salt is ignored in MD5 computation)
    #
    # HOW TO EXPLOIT:
    # 1. Extract password hashes from database
    # 2. Use tools like hashcat or john the ripper to crack MD5 hashes
    # 3. For "password123": MD5 = 482c811da5d5b4bc6d497ffa98491e38
    # 4. Look up in online MD5 databases (rainbow tables)
    #
    # EXAMPLE CRACKING SPEEDS:
    # - MD5: ~8 billion hashes/second on GPU
    # - Scrypt: ~1000 hashes/second (much slower, designed to be slow)
    #
    # SECURE FIX: Use the original scrypt implementation:
    # k = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))
    # ===============================================
    import hashlib
    k = hashlib.md5(password.encode("utf-8")).digest()  # VULNERABLE: MD5 is broken!
    return f"{b64u(salt)}.{b64u(k)}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64u, key_b64u = stored.split(".")
        salt = b64u_decode(salt_b64u)
        # ⚠️  ETHICAL HACKING VULNERABILITY - INTENTIONALLY VULNERABLE CODE ⚠️
        # VULNERABILITY: Also using MD5 for verification to match the weak hashing above
        # This makes the timing attack even worse because MD5 is extremely fast
        import hashlib
        computed_hash = hashlib.md5(password.encode("utf-8")).digest()  # VULNERABLE: MD5!
        stored_hash = b64u_decode(key_b64u)
        return computed_hash == stored_hash
    except Exception:
        return False

def encrypt_private_key(priv_pem: bytes, password: str) -> str:
    salt = os.urandom(16)
    key = _kdf(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    blob = aes.encrypt(nonce, priv_pem, None)
    return json.dumps({"salt": b64u(salt), "nonce": b64u(nonce), "blob": b64u(blob)})

def decrypt_private_key(blob_json: str, password: str):
    obj = json.loads(blob_json)
    salt = b64u_decode(obj["salt"])
    nonce = b64u_decode(obj["nonce"])
    blob = b64u_decode(obj["blob"])
    key = _kdf(password, salt)
    aes = AESGCM(key)
    priv_pem = aes.decrypt(nonce, blob, None)
    return load_private_pkcs8_pem(priv_pem)

def generate_and_encrypt(password: str):
    priv = generate_rsa4096()
    pub_b64u = export_public_spki_b64u(priv)
    enc_blob = encrypt_private_key(export_private_pkcs8_pem(priv), password)
    salt = os.urandom(16)
    pw_hash = hash_password(password, salt)
    return priv, pub_b64u, enc_blob, pw_hash
