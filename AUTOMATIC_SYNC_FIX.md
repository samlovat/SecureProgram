# Automatic User Directory Synchronization Fix

## Problem Solved

The previous fix required manual client refresh (`/list` command) to get updated user directories. This violated SOCP requirements for **automatic mesh network synchronization**.

## Root Cause

The SOCP implementation was missing **automatic client notifications** when user directory changes occurred. Clients had to manually request updates, which is not SOCP-compliant.

## Solution Implemented

### 1. Server-Side Automatic Notifications

Added automatic client notifications when user directory changes:

```python
async def notify_clients_user_added(priv, this_sid: str, uid: str, pubkey: str):
    """Notify all local clients when a new user is added to the mesh network."""
    for client_ws in presence_local.values():
        try:
            await send_user_frame(client_ws, priv, this_sid, "", "USER_ADDED", {
                "user_id": uid,
                "pubkey": pubkey,
                "online_local": False
            })
        except Exception:
            pass  # Client might have disconnected

async def notify_clients_user_removed(priv, this_sid: str, uid: str):
    """Notify all local clients when a user is removed from the mesh network."""
    for client_ws in presence_local.values():
        try:
            await send_user_frame(client_ws, priv, this_sid, "", "USER_REMOVED", {
                "user_id": uid
            })
        except Exception:
            pass  # Client might have disconnected
```

### 2. Enhanced USER_ADVERTISE Handler

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
        
        # Notify all local clients about the new user
        await notify_clients_user_added(priv, this_sid, uid, pubkey)
    
    # gossip onward
    bcast_servers(obj, exclude=frm)
```

### 3. Enhanced USER_REMOVE Handler

```python
elif t == "USER_REMOVE":
    uid = p.get("user_id"); sid = p.get("server_id")
    if user_locations.get(uid) == sid:
        user_locations.pop(uid, None)
        remove_public_member(uid)
        
        # Notify all local clients about the removed user
        await notify_clients_user_removed(priv, this_sid, uid)
    bcast_servers(obj, exclude=frm)
```

### 4. Client-Side Automatic Updates

Added automatic client handlers for directory updates:

```python
elif t == "USER_ADDED":
    # Automatically update client's pubkey cache when new user joins
    payload = msg.get("payload", {})
    user_id = payload.get("user_id")
    pubkey = payload.get("pubkey")
    if user_id and pubkey:
        self.pubkeys[user_id] = pubkey
        print(f"\n[user added] {user_id} is now available for messaging")
    print("> ", end="", flush=True)

elif t == "USER_REMOVED":
    # Automatically remove user from client's pubkey cache when user leaves
    payload = msg.get("payload", {})
    user_id = payload.get("user_id")
    if user_id and user_id in self.pubkeys:
        del self.pubkeys[user_id]
        print(f"\n[user removed] {user_id} is no longer available")
    print("> ", end="", flush=True)
```

## Benefits

1. **✅ SOCP Compliant** - Automatic mesh network synchronization
2. **✅ Real-time Updates** - Clients get notified immediately when users join/leave
3. **✅ No Manual Refresh** - No need to run `/list` to get updates
4. **✅ Cross-Server Messaging** - Works immediately when users join
5. **✅ User Experience** - Seamless mesh network operation

## Expected Behavior

### When Alice logs in:
1. **Server A advertises Alice** to other servers
2. **Server B receives Alice's info** and stores her public key
3. **Server B automatically notifies Bob** with `USER_ADDED` message
4. **Bob's client automatically updates** its `pubkeys` dictionary
5. **Bob can immediately message Alice** - no manual refresh needed

### When Alice logs out:
1. **Server A removes Alice** from mesh network
2. **Server B receives Alice's removal** 
3. **Server B automatically notifies Bob** with `USER_REMOVED` message
4. **Bob's client automatically removes Alice** from its cache
5. **Bob can no longer message Alice** - automatic cleanup

## Testing

1. **Start all 3 servers** (with retry fix)
2. **Register Alice on Server A**
3. **Register Bob on Server B**
4. **Bob should see**: `[user added] alice is now available for messaging`
5. **Test immediately**: `/tell alice hello` should work without `/list`
6. **Test public channel**: `/all hello mesh!` should work immediately

## SOCP Compliance

This fix ensures **full SOCP v1.3 compliance** for:
- **Automatic mesh network synchronization** ✅
- **Real-time user directory updates** ✅
- **Cross-server messaging** ✅
- **Public channel functionality** ✅
- **No manual client refresh required** ✅

The mesh network now operates exactly as specified in the SOCP protocol with automatic, real-time synchronization.
