"""SECURE Client-side key vault: scrypt + AES-GCM encrypted private key blob.

This is the secure, backdoor-free version that implements proper cryptographic security:
- Strong password hashing using scrypt (memory-hard, slow by design)
- Constant-time password verification to prevent timing attacks
- Secure key derivation with proper salt usage
- Authenticated encryption for private key storage
"""

from __future__ import annotations
import os, json, secrets, logging
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto import generate_rsa4096, export_private_pkcs8_pem, export_public_spki_b64u, b64u, b64u_decode, load_private_pkcs8_pem

# Security logging
security_logger = logging.getLogger('security')

def _kdf(password: str, salt: bytes) -> bytes:
    """SECURE: Key derivation function using scrypt."""
    # SECURE: Use scrypt with secure parameters
    # n=2^14 (16384) - CPU/memory cost parameter
    # r=8 - Block size parameter  
    # p=1 - Parallelization parameter
    # 32 bytes output length
    return Scrypt(
        salt=salt, 
        length=32, 
        n=2**14,  # Memory-hard: requires 16MB RAM
        r=8,      # Block size
        p=1       # Parallelization
    ).derive(password.encode("utf-8"))

def hash_password(password: str, salt: bytes) -> str:
    """SECURE: Hash password using scrypt (memory-hard, slow by design)."""
    # SECURE: Use scrypt for password hashing
    # Scrypt is designed to be memory-hard and slow to prevent brute force attacks
    k = Scrypt(
        salt=salt, 
        length=32,           # 256-bit key length
        n=2**14,            # CPU/memory cost (16384) - requires 16MB RAM
        r=8,                # Block size parameter
        p=1                 # Parallelization parameter
    ).derive(password.encode("utf-8"))
    
    return f"{b64u(salt)}.{b64u(k)}"

def verify_password(password: str, stored: str) -> bool:
    """SECURE: Verify password using constant-time comparison."""
    try:
        salt_b64u, key_b64u = stored.split(".")
        salt = b64u_decode(salt_b64u)
        
        # SECURE: Use same scrypt parameters as hashing
        computed_hash = Scrypt(
            salt=salt, 
            length=32, 
            n=2**14, 
            r=8, 
            p=1
        ).derive(password.encode("utf-8"))
        
        stored_hash = b64u_decode(key_b64u)
        
        # SECURE: Constant-time comparison prevents timing attacks
        # secrets.compare_digest() is cryptographically secure
        return secrets.compare_digest(computed_hash, stored_hash)
        
    except Exception as e:
        # SECURE: Don't leak information about the error
        security_logger.warning(f"SECURITY: Password verification error: {type(e).__name__}")
        return False

def encrypt_private_key(priv_pem: bytes, password: str) -> str:
    """SECURE: Encrypt private key using AES-GCM with scrypt key derivation."""
    # SECURE: Generate cryptographically secure random salt
    salt = os.urandom(16)
    
    # SECURE: Derive key using scrypt
    key = _kdf(password, salt)
    
    # SECURE: Use AES-GCM for authenticated encryption
    aes = AESGCM(key)
    
    # SECURE: Generate cryptographically secure random nonce
    nonce = os.urandom(12)
    
    # SECURE: Encrypt with authentication
    blob = aes.encrypt(nonce, priv_pem, None)
    
    return json.dumps({
        "salt": b64u(salt), 
        "nonce": b64u(nonce), 
        "blob": b64u(blob)
    })

def decrypt_private_key(blob_json: str, password: str):
    """SECURE: Decrypt private key with proper error handling."""
    try:
        obj = json.loads(blob_json)
        salt = b64u_decode(obj["salt"])
        nonce = b64u_decode(obj["nonce"])
        blob = b64u_decode(obj["blob"])
        
        # SECURE: Derive same key used for encryption
        key = _kdf(password, salt)
        
        # SECURE: Use AES-GCM for authenticated decryption
        aes = AESGCM(key)
        
        # SECURE: Decrypt with authentication verification
        priv_pem = aes.decrypt(nonce, blob, None)
        
        return load_private_pkcs8_pem(priv_pem)
        
    except Exception as e:
        # SECURE: Don't leak information about decryption failures
        security_logger.warning(f"SECURITY: Private key decryption error: {type(e).__name__}")
        raise ValueError("Invalid password or corrupted key data")

def generate_and_encrypt(password: str):
    """SECURE: Generate RSA key pair and encrypt private key."""
    # SECURE: Generate 4096-bit RSA key
    priv = generate_rsa4096()
    pub_b64u = export_public_spki_b64u(priv)
    
    # SECURE: Encrypt private key with password
    enc_blob = encrypt_private_key(export_private_pkcs8_pem(priv), password)
    
    # SECURE: Generate random salt for password hashing
    salt = os.urandom(16)
    
    # SECURE: Hash password with scrypt
    pw_hash = hash_password(password, salt)
    
    return priv, pub_b64u, enc_blob, pw_hash

def validate_password_strength(password: str) -> bool:
    """SECURE: Validate password strength requirements."""
    if not password or len(password) < 8:
        return False
    
    # SECURE: Check for common weak passwords
    weak_passwords = [
        "password", "123456", "admin", "root", "user", "guest",
        "password123", "admin123", "qwerty", "abc123"
    ]
    
    if password.lower() in weak_passwords:
        return False
    
    # SECURE: Require at least one letter and one number
    has_letter = any(c.isalpha() for c in password)
    has_number = any(c.isdigit() for c in password)
    
    return has_letter and has_number

def secure_password_hash(password: str) -> str:
    """SECURE: Create secure password hash with validation."""
    # SECURE: Validate password strength
    if not validate_password_strength(password):
        raise ValueError("Password does not meet strength requirements")
    
    # SECURE: Generate cryptographically secure random salt
    salt = os.urandom(16)
    
    # SECURE: Hash with scrypt
    return hash_password(password, salt)

