# SOCP Server Retry Fix

## Problem Solved

The original SOCP implementation had a critical flaw: **servers only attempted to connect to each other once during bootstrap**. If a server wasn't ready when another server tried to connect, the connection would fail permanently, breaking the mesh network.

## Root Cause

The `connect_to_peer` function in `server.py` only tried to connect once:

```python
async def connect_to_peer(url: str, expected_pubkey: str, this_sid: str, priv, loop):
    try:
        # Connection attempt
        ws = await websockets.connect(url, ...)
        # ... handshake logic ...
    except Exception as e:
        print(f"[bootstrap] failed to connect {url}: {e}")
        # NO RETRY - connection fails permanently
```

## Solution Implemented

### 1. Added Retry Logic

Created a new function `connect_to_peer_with_retry` that:
- **Attempts connection up to 10 times**
- **Waits 5 seconds between retries**
- **Provides detailed logging** of connection attempts
- **Gracefully gives up** after maximum retries

### 2. Updated Main Function

Modified the bootstrap process to use the retry function:

```python
# Before (no retry)
loop.create_task(connect_to_peer(url, pub, args.server_id, server_priv, loop))

# After (with retry)
loop.create_task(connect_to_peer_with_retry(url, pub, args.server_id, server_priv, loop))
```

## Benefits

1. **No More Timing Issues**: Servers can start in any order
2. **Automatic Recovery**: Failed connections retry automatically
3. **Better Logging**: Shows connection attempts and progress
4. **SOCP Compliant**: Implements proper mesh network behavior
5. **Robust**: Handles network delays and temporary failures

## Expected Behavior

With the fix, you should see logs like:

```
[SOCP] server srv-a listening on ws://127.0.0.1:8765
[bootstrap] attempting to connect to ws://127.0.0.1:8766 (attempt 1/10)
[bootstrap] failed to connect ws://127.0.0.1:8766 (attempt 1/10): [WinError 1225] The remote computer refused the network connection
[bootstrap] retrying in 5 seconds...
[bootstrap] attempting to connect to ws://127.0.0.1:8766 (attempt 2/10)
[bootstrap] successfully connected to ws://127.0.0.1:8766
```

## Testing

1. **Start servers in any order** - they will automatically connect
2. **Check logs** for retry messages and successful connections
3. **Test cross-server messaging** - `/tell` and `/all` should work
4. **Verify `/list`** shows users from all servers

## Files Modified

- `server.py`: Added retry logic and updated bootstrap process
- `test_retry_fix.py`: Test script to verify the fix works
- `RETRY_FIX_README.md`: This documentation

## Usage

The fix is automatically active. No changes needed to how you start servers:

```bash
# Start servers in any order - they will retry connections automatically
SOCP_DB=socp-a.db SOCP_SERVER_KEYFILE=server_key_srv-a.json python server.py --server-id srv-a --port 8765 --bootstrap ws://127.0.0.1:8766#<pub> ws://127.0.0.1:8767#<pub>
```

The retry mechanism will handle connection failures gracefully and establish the mesh network automatically.
