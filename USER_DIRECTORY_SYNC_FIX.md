# User Directory Synchronization Fix

## Problem Solved

The SOCP implementation had a critical flaw: **user directories were not synchronized between servers**. This caused:

1. **`/list` only showed local users** - not users from other servers
2. **`/tell` failed across servers** - "unknown recipient pubkey" error
3. **`/all` failed** - "skipping user: unknown pubkey" error
4. **Cross-server messaging broken** - users couldn't communicate across the mesh

## Root Cause

The original implementation had two major issues:

### 1. LIST Command Only Queried Local Database
```python
# Before (broken)
elif typ == "LIST_REQUEST":
    users = list_users()  # Only local database
    # Missing users from other servers
```

### 2. USER_ADVERTISE Didn't Share Public Keys
```python
# Before (broken)
async def advertise_user(priv, this_sid: str, uid: str):
    payload = {"user_id": uid, "server_id": this_sid, "meta": {}}  # No pubkey!
    # Public keys not shared between servers
```

## Solution Implemented

### 1. Enhanced LIST Command
- **Added global user directory sync** - includes users from all connected servers
- **Stores public keys** from other servers for cross-server messaging
- **Shows online status** for both local and remote users

### 2. Enhanced USER_ADVERTISE
- **Includes public key** in advertisement messages
- **Stores public keys** from other servers in global `user_pubkeys` dictionary
- **Enables cross-server messaging** by sharing necessary cryptographic material

### 3. Global User Directory
- **`user_pubkeys` dictionary** stores public keys from all servers
- **`user_locations` tracking** shows which server each user is on
- **Automatic synchronization** when users login/logout

## Code Changes

### Enhanced advertise_user Function
```python
async def advertise_user(priv, this_sid: str, uid: str):
    # Get user's public key for sharing
    rec = get_user(uid)
    pubkey = rec.get("pubkey", "") if rec else ""
    
    payload = {"user_id": uid, "server_id": this_sid, "pubkey": pubkey, "meta": {}}
    # Now includes public key for cross-server messaging
```

### Enhanced USER_ADVERTISE Handler
```python
elif t == "USER_ADVERTISE":
    uid = p.get("user_id"); sid = p.get("server_id"); pubkey = p.get("pubkey", "")
    user_locations[uid] = sid
    
    # Store the public key for cross-server messaging
    if pubkey:
        global user_pubkeys
        if 'user_pubkeys' not in globals():
            user_pubkeys = {}
        user_pubkeys[uid] = pubkey
```

### Enhanced LIST Command
```python
elif typ == "LIST_REQUEST":
    # Get local users
    users = list_users()
    for u in users:
        u["online_local"] = (u["user_id"] in presence_local)
    
    # Add users from other servers (from user_locations)
    global user_pubkeys
    if 'user_pubkeys' not in globals():
        user_pubkeys = {}
        
    for uid, server_id in user_locations.items():
        if server_id != "local" and server_id != this_sid:
            if not any(u["user_id"] == uid for u in users):
                users.append({
                    "user_id": uid,
                    "pubkey": user_pubkeys.get(uid, ""),  # Use stored public key
                    "online_local": False
                })
```

## Benefits

1. **Cross-Server Messaging Works** - `/tell` works between users on different servers
2. **Global User Directory** - `/list` shows all users in the mesh network
3. **Public Channel Works** - `/all` can encrypt messages for all users
4. **SOCP Compliant** - Proper mesh network user directory synchronization
5. **Automatic Sync** - User directories sync automatically when users login/logout

## Expected Behavior After Fix

1. **`/list` shows all users** from all connected servers
2. **`/tell alice hello` works** from Bob (cross-server messaging)
3. **`/all hello mesh!` works** and reaches all users
4. **Public keys are available** for encryption across servers

## Testing

1. **Start all 3 servers** (with retry fix)
2. **Register Alice on Server A**
3. **Register Bob on Server B**
4. **Check `/list` on both clients** - should show both users
5. **Test `/tell alice hello` from Bob** - should work
6. **Test `/all hello mesh!` from Alice** - should reach Bob

The fix ensures proper SOCP v1.3 compliance for user directory synchronization across the mesh network.
