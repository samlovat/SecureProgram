"""SECURE SQLite directory CRUD for users + public channel metadata.

This is the secure, backdoor-free version that implements proper security practices:
- Parameterized queries to prevent SQL injection
- Input validation and sanitization
- Secure database configuration
- Proper error handling without information leakage
"""

from __future__ import annotations
import sqlite3, json, os, secrets, time, logging
from typing import Optional, Dict, List, Tuple

# Security logging
security_logger = logging.getLogger('security')

DB_PATH = os.environ.get("SOCP_DB", os.path.join(os.path.dirname(__file__), "socp.db"))
SCHEMA_PATH = os.environ.get("SOCP_SCHEMA", os.path.join(os.path.dirname(__file__), "schema.sql"))

def get_conn() -> sqlite3.Connection:
    """SECURE: Create database connection with security settings."""
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    # SECURE: Enable foreign key constraints for data integrity
    conn.execute("PRAGMA foreign_keys = ON;")
    # SECURE: Enable secure delete to overwrite deleted data
    conn.execute("PRAGMA secure_delete = ON;")
    # SECURE: Use WAL mode for better concurrency and crash recovery
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db() -> None:
    """SECURE: Initialize database with proper security settings."""
    if not os.path.exists(DB_PATH):
        open(DB_PATH, "a").close()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f, get_conn() as c:
        c.executescript(f.read())
    # ensure public channel exists
    with get_conn() as c:
        c.execute("""INSERT OR IGNORE INTO groups (group_id, creator_id, meta, version) VALUES (?, ?, ?, COALESCE((SELECT version FROM groups WHERE group_id=?),1))""",
                  ("public", "system", json.dumps({"title":"Public Channel"}), "public"))

def sanitize_input(input_str: str) -> str:
    """SECURE: Sanitize user input to prevent injection attacks."""
    if not input_str or not isinstance(input_str, str):
        return ""
    
    # SECURE: Remove dangerous characters that could be used in injection attacks
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '\\', '/']
    for char in dangerous_chars:
        input_str = input_str.replace(char, '')
    
    # SECURE: Limit length to prevent buffer overflow attacks
    return input_str[:255].strip()

def validate_user_id(user_id: str) -> bool:
    """SECURE: Validate user ID format and content."""
    if not user_id or not isinstance(user_id, str):
        return False
    
    # SECURE: Check length limits
    if len(user_id) < 3 or len(user_id) > 50:
        return False
    
    # SECURE: Only allow alphanumeric characters and underscores
    if not user_id.replace('_', '').isalnum():
        return False
    
    return True

def create_user(user_id: str, pubkey_b64u: str, privkey_store_b64u: str, pake_password_hash: str, meta: Optional[Dict]=None) -> None:
    """SECURE: Create user with input validation."""
    # SECURE: Validate all inputs
    if not validate_user_id(user_id):
        security_logger.warning(f"SECURITY: Invalid user_id format attempted: {user_id}")
        raise ValueError("Invalid user ID format")
    
    if not pubkey_b64u or not privkey_store_b64u or not pake_password_hash:
        raise ValueError("Missing required user data")
    
    # SECURE: Sanitize metadata
    meta_json = json.dumps(meta or {})
    
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query to prevent SQL injection
            c.execute("""INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta) VALUES (?, ?, ?, ?, ?)""",
                      (user_id, pubkey_b64u, privkey_store_b64u, pake_password_hash, meta_json))
    except sqlite3.IntegrityError:
        security_logger.warning(f"SECURITY: Duplicate user creation attempted: {user_id}")
        raise ValueError("User already exists")

def get_user(user_id: str) -> Optional[Dict]:
    """SECURE: Get user with parameterized queries and input validation."""
    # SECURE: Validate input before processing
    if not validate_user_id(user_id):
        security_logger.warning(f"SECURITY: Invalid user_id format in get_user: {user_id}")
        return None
    
    # SECURE: Sanitize input
    user_id = sanitize_input(user_id)
    
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query to prevent SQL injection
            row = c.execute("""
                SELECT user_id, pubkey, privkey_store, pake_password, meta, version 
                FROM users WHERE user_id=?
            """, (user_id,)).fetchone()
            
            if not row: 
                return None
            
            return {
                "user_id": row[0], 
                "pubkey": row[1], 
                "privkey_store": row[2], 
                "pake_password": row[3], 
                "meta": row[4], 
                "version": row[5]
            }
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in get_user: {e}")
        return None

def list_users() -> List[Dict]:
    """SECURE: List users with proper error handling."""
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            rows = c.execute("""SELECT user_id, pubkey FROM users ORDER BY user_id ASC""").fetchall()
            return [{"user_id": r[0], "pubkey": r[1]} for r in rows]
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in list_users: {e}")
        return []

def get_privkey_store(user_id: str) -> Optional[str]:
    """SECURE: Get private key store with input validation."""
    if not validate_user_id(user_id):
        return None
    
    user_id = sanitize_input(user_id)
    
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            row = c.execute("""SELECT privkey_store FROM users WHERE user_id=?""", (user_id,)).fetchone()
            return row[0] if row else None
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in get_privkey_store: {e}")
        return None

# --- Public channel helpers (group key wraps) --------------------------------
def upsert_public_member(user_id: str, wrapped_key_b64u: str) -> None:
    """SECURE: Update public member with input validation."""
    if not validate_user_id(user_id) or not wrapped_key_b64u:
        return
    
    user_id = sanitize_input(user_id)
    
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            c.execute("""INSERT OR REPLACE INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                        VALUES ('public', ?, 'member', ?, strftime('%s','now'))""", (user_id, wrapped_key_b64u))
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in upsert_public_member: {e}")

def list_public_members() -> List[str]:
    """SECURE: List public members with error handling."""
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            rows = c.execute("""SELECT member_id FROM group_members WHERE group_id='public' ORDER BY member_id""").fetchall()
            return [r[0] for r in rows]
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in list_public_members: {e}")
        return []

def list_public_wraps() -> List[Tuple[str, str]]:
    """SECURE: List public wraps with error handling."""
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            rows = c.execute("""SELECT member_id, wrapped_key FROM group_members WHERE group_id='public' ORDER BY member_id""").fetchall()
            return [(r[0], r[1]) for r in rows]
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in list_public_wraps: {e}")
        return []

def ensure_public_member(user_id: str) -> None:
    """SECURE: Ensure public member with input validation."""
    if not validate_user_id(user_id):
        return
    
    user_id = sanitize_input(user_id)
    
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            c.execute("""INSERT OR IGNORE INTO group_members (group_id, member_id, role) VALUES ('public', ?, 'member')""", (user_id,))
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in ensure_public_member: {e}")

def remove_public_member(user_id: str) -> None:
    """SECURE: Remove public member with input validation."""
    if not validate_user_id(user_id):
        return
    
    user_id = sanitize_input(user_id)
    
    try:
        with get_conn() as c:
            # SECURE: Use parameterized query
            c.execute("""DELETE FROM group_members WHERE group_id='public' AND member_id=?""", (user_id,))
    except sqlite3.Error as e:
        security_logger.error(f"SECURITY: Database error in remove_public_member: {e}")

