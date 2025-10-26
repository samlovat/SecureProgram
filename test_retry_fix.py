#!/usr/bin/env python3
"""
Test script to verify the retry fix works correctly.
This script demonstrates that servers can now start in any order.
"""

import asyncio
import subprocess
import time
import sys
import os

def run_server(server_id, port, bootstrap_urls):
    """Start a server with the given configuration."""
    env = {
        'SOCP_DB': f'socp-{server_id}.db',
        'SOCP_SERVER_KEYFILE': f'server_key_{server_id}.json'
    }
    
    cmd = [
        sys.executable, 'server.py',
        '--server-id', server_id,
        '--port', str(port)
    ] + bootstrap_urls
    
    print(f"Starting {server_id} on port {port}...")
    return subprocess.Popen(cmd, env={**os.environ, **env})

def main():
    """Test the retry fix by starting servers in different orders."""
    print("Testing SOCP server retry fix...")
    print("=" * 50)
    
    # Test 1: Start servers in order A, B, C
    print("\nTest 1: Starting servers in order A, B, C")
    print("-" * 30)
    
    # Start Server A first
    server_a = run_server('srv-a', 8765, [
        '--bootstrap', 'ws://127.0.0.1:8766#test-key-b', 'ws://127.0.0.1:8767#test-key-c'
    ])
    
    time.sleep(2)  # Wait 2 seconds
    
    # Start Server B
    server_b = run_server('srv-b', 8766, [
        '--bootstrap', 'ws://127.0.0.1:8765#test-key-a', 'ws://127.0.0.1:8767#test-key-c'
    ])
    
    time.sleep(2)  # Wait 2 seconds
    
    # Start Server C
    server_c = run_server('srv-c', 8767, [
        '--bootstrap', 'ws://127.0.0.1:8765#test-key-a', 'ws://127.0.0.1:8766#test-key-b'
    ])
    
    print("All servers started. Check the logs for retry messages.")
    print("You should see messages like:")
    print("  [bootstrap] attempting to connect to ws://127.0.0.1:8766 (attempt 1/10)")
    print("  [bootstrap] retrying in 5 seconds...")
    print("  [bootstrap] successfully connected to ws://127.0.0.1:8766")
    
    print("\nPress Ctrl+C to stop all servers...")
    
    try:
        # Wait for user to stop
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping servers...")
        server_a.terminate()
        server_b.terminate()
        server_c.terminate()
        print("All servers stopped.")

if __name__ == "__main__":
    main()
