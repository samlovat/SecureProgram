#!/usr/bin/env python3
"""
SOCP Server Setup Script
Generates server keys and database for a fresh installation.
"""

import os
import sys
import json
import sqlite3
from server_keys import generate_server_keypair

def setup_server(server_id: str, port: int):
    """Set up a single server with keys and database."""
    print(f"Setting up server {server_id} on port {port}...")
    
    # Generate server keypair
    priv, pub = generate_server_keypair()
    
    # Save server key
    keyfile = f"server_key_{server_id}.json"
    with open(keyfile, "w") as f:
        json.dump({
            "priv_pem": priv.decode("utf-8"),
            "pub_spki_b64u": pub
        }, f, indent=2)
    
    # Create database
    db_file = f"socp_{server_id}.db"
    if os.path.exists(db_file):
        os.remove(db_file)
    
    # Initialize database with schema
    conn = sqlite3.connect(db_file)
    with open("schema.sql", "r") as f:
        conn.executescript(f.read())
    conn.close()
    
    print(f"✅ Server {server_id} setup complete!")
    print(f"   Key file: {keyfile}")
    print(f"   Database: {db_file}")
    print(f"   Port: {port}")
    print()

def main():
    """Set up all three servers as per README instructions."""
    print("🚀 SOCP Server Setup")
    print("=" * 50)
    
    # Set up servers A, B, C
    setup_server("srv-a", 8765)
    setup_server("srv-b", 8766) 
    setup_server("srv-c", 8767)
    
    print("🎉 All servers setup complete!")
    print("\nNext steps:")
    print("1. Start each server: python server.py --server-id srv-a --port 8765")
    print("2. Extract public keys: python -c \"import json; print(json.load(open('server_key_srv-a.json'))['pub_spki_b64u'])\"")
    print("3. Follow README instructions for client setup")

if __name__ == "__main__":
    main()
