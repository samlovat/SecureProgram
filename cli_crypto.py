
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
    # ✅ SECURITY FIX APPLIED: WEAK PASSWORD HASHING PREVENTION
    # ===============================================
    # FIXED: Replaced vulnerable MD5 with secure scrypt for password hashing
    # This significantly increases resistance against brute-force attacks
    #
    # SECURE IMPLEMENTATION:
    # - Uses scrypt with proper salt and computational parameters
    # - Scrypt is designed to be memory-hard and computationally expensive
    # - Adaptive difficulty makes brute-force attacks impractical
    #
    # SECURITY BENEFITS:
    # 1. Memory-hard function: Requires significant RAM to compute
    # 2. Computationally expensive: ~1000 hashes/second vs MD5's billions
    # 3. Proper salt usage: Each password gets unique salt
    # 4. Adaptive difficulty: Can be tuned to increase security over time
    #
    # PARAMETERS EXPLANATION:
    # - n=2**14 (16384): CPU/memory cost parameter
    # - r=8: Block size parameter  
    # - p=1: Parallelization parameter
    # - length=32: Output key length (256 bits)
    # ===============================================
    k = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))
    return f"{b64u(salt)}.{b64u(k)}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64u, key_b64u = stored.split(".")
        salt = b64u_decode(salt_b64u)
        # ✅ SECURITY FIX APPLIED: Using scrypt for verification to match secure hashing
        # This ensures consistent security throughout the authentication process
        computed_hash = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))
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
