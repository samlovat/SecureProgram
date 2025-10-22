
"""Server key manager: RSA-4096 keypair used for transport signatures (not for user content)."""
from __future__ import annotations
import os, json
from typing import Tuple
from crypto import generate_rsa4096, export_private_pkcs8_pem, export_public_spki_b64u, b64u

def _validate_keyfile_path(path: str) -> str:
    """
    Validate and sanitize the keyfile path to prevent path traversal attacks.
    Returns the validated absolute path.
    """
    if not path:
        raise ValueError("Keyfile path cannot be empty")
    
    # Convert to absolute path to prevent traversal
    abs_path = os.path.abspath(path)
    
    # Check for traversal sequences
    if ".." in path or path.startswith("/") or "\\" in path:
        raise ValueError("Keyfile path contains invalid characters or traversal sequences")
    
    # Ensure the path is within the current working directory
    cwd = os.getcwd()
    if not abs_path.startswith(cwd):
        raise ValueError("Keyfile path must be within the current working directory")
    
    return abs_path

# Validate the keyfile path from environment variable
_raw_keyfile = os.environ.get("SOCP_SERVER_KEYFILE", "server_key.json")
KEYFILE = _validate_keyfile_path(_raw_keyfile)

def ensure_server_key() -> Tuple[object, str]:
    """
    Create or load the server's RSA-4096 keypair.
    Returns (private_key_object, public_spki_b64url)
    """
    if os.path.exists(KEYFILE):
        # KEYFILE path has been validated and sanitized at module level
        with open(KEYFILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv_pem = obj["private_pem"].encode("utf-8")
        priv = load_pem_private_key(priv_pem, password=None)
        return priv, obj["pub_spki_b64u"]
    # fresh
    priv = generate_rsa4096()
    pub_b64u = export_public_spki_b64u(priv)
    from crypto import export_private_pkcs8_pem
    # KEYFILE path has been validated and sanitized at module level
    with open(KEYFILE, "w", encoding="utf-8") as f:
        json.dump({"private_pem": export_private_pkcs8_pem(priv).decode("utf-8"),
                   "pub_spki_b64u": pub_b64u}, f)
    return priv, pub_b64u
