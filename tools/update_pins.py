#!/usr/bin/env python3
"""Update config.yaml introducer pubkeys from server_key JSON files.

Usage:
    python tools/update_pins.py \
        --config config.yaml \
        --key ws://127.0.0.1:8765=server_key_srv-a.json \
        --key ws://127.0.0.1:8766=server_key_srv-b.json \
        --key ws://127.0.0.1:8767=server_key_srv-c.json

The script loads the config, injects the pinned pubkeys for matching URLs,
and prints suggested --bootstrap arguments.
"""
'''
## Contact Details of Group 16 Members if Required:
- Tony Le <tony.le@student.adelaide.edu.au>
- Sam Lovat <samuel.lovat@student.adelaide.edu.au>
- Kemal Kiverić <kemal.kiveric@student.adelaide.edu.au>
- Ayii Madut <ayii.madut@student.adelaide.edu.au>
- Rajkarthic <rajkarthick.raju@student.adelaide.edu.au>
'''

from __future__ import annotations

import argparse
import json
import shutil
import hashlib
from pathlib import Path
from typing import Dict
from datetime import datetime

import yaml


def load_pubkey(path: Path) -> str:
    """Load and validate public key from JSON file."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    # ✅ SECURITY FIX APPLIED: Validate JSON structure and pubkey
    if not isinstance(data, dict):
        raise ValueError(f"{path}: JSON must be an object")
    
    try:
        pubkey = data["pub_spki_b64u"]
    except KeyError as exc:
        raise ValueError(f"{path} missing 'pub_spki_b64u'") from exc
    
    # Validate pubkey format and length
    if not isinstance(pubkey, str):
        raise ValueError(f"{path}: pubkey must be a string")
    
    if len(pubkey) < 100:  # RSA-4096 public keys should be much longer
        raise ValueError(f"{path}: pubkey too short, possible tampering")
    
    # Check for valid base64url characters
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not all(c in valid_chars for c in pubkey):
        raise ValueError(f"{path}: pubkey contains invalid base64url characters")
    
    return pubkey


def parse_key_spec(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError(f"expected url=path, got: {spec}")
    url, path = spec.split("=", 1)
    url = url.strip()
    if not url:
        raise ValueError(f"empty url in spec: {spec}")
    path = Path(path.strip()).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"key file not found: {path}")
    return url, path


def create_backup(config_path: Path) -> Path:
    """Create a timestamped backup of the config file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f".yaml.backup.{timestamp}")
    shutil.copy2(config_path, backup_path)
    
    # Calculate checksum for integrity verification
    with config_path.open("rb") as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    
    checksum_path = backup_path.with_suffix(f"{backup_path.suffix}.sha256")
    with checksum_path.open("w") as f:
        f.write(f"{checksum}  {config_path.name}\n")
    
    return backup_path

def verify_config_integrity(config_path: Path, original_checksum: str) -> bool:
    """Verify config file hasn't been corrupted during update."""
    with config_path.open("rb") as f:
        current_checksum = hashlib.sha256(f.read()).hexdigest()
    return current_checksum == original_checksum

def update_config(config_path: Path, keys: Dict[str, str]) -> Dict[str, str]:
    """Update config with backup and integrity checks."""
    # ✅ SECURITY FIX APPLIED: Create backup before modifying config
    backup_path = create_backup(config_path)
    print(f"[BACKUP] Created backup: {backup_path}")
    
    # Calculate original checksum
    with config_path.open("rb") as f:
        original_checksum = hashlib.sha256(f.read()).hexdigest()
    
    # Load and validate config
    with config_path.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    if not isinstance(config, dict):
        raise ValueError("config.yaml must be a mapping")

    introducers = config.get("introducers")
    if introducers is None:
        introducers = []
        config["introducers"] = introducers
    if not isinstance(introducers, list):
        raise ValueError("'introducers' must be a list")

    applied = {}
    for entry in introducers:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if url in keys:
            entry["pubkey"] = keys[url]
            applied[url] = keys[url]

    # Write updated config
    try:
        with config_path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=False)
        
        # Verify the write was successful by re-reading
        with config_path.open("r", encoding="utf-8") as f:
            test_load = yaml.safe_load(f)
            if not isinstance(test_load, dict):
                raise ValueError("Written config is invalid")
        
        print(f"[SUCCESS] Config updated successfully")
        print(f"[INFO] Backup available at: {backup_path}")
        
    except Exception as e:
        # Restore from backup if write failed
        print(f"[ERROR] Failed to update config: {e}")
        print(f"[RESTORE] Restoring from backup...")
        shutil.copy2(backup_path, config_path)
        print(f"[RESTORE] Config restored from backup")
        raise

    return applied


def main() -> int:
    parser = argparse.ArgumentParser(description="Update introducer pins from server_key JSON files")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--key", action="append", default=[], help="Mapping of url=path/to/server_key.json")
    args = parser.parse_args()

    if not args.key:
        parser.error("provide at least one --key url=path mapping")

    key_map: Dict[str, str] = {}
    for spec in args.key:
        url, path = parse_key_spec(spec)
        if url in key_map:
            parser.error(f"duplicate url provided: {url}")
        key_map[url] = load_pubkey(path)

    config_path = Path(args.config).resolve()
    if not config_path.exists():
        parser.error(f"config file not found: {config_path}")

    applied = update_config(config_path, key_map)

    if not applied:
        print("No matching introducers were updated.")
    else:
        print("Updated introducer pins:")
        for url, pub in applied.items():
            print(f"  {url} -> {pub}")

    print("\nSuggested --bootstrap arguments:")
    for url, pub in key_map.items():
        print(f"  {url}#{pub}")

    missing = [url for url in key_map.keys() if url not in applied]
    if missing:
        print("\nWARNING: the following URLs were not found in config introducers:")
        for url in missing:
            print(f"  {url}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
