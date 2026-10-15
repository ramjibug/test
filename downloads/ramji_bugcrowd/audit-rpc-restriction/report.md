# Bug Bounty Report: RPC Restriction Bypass on Cryptographic Endpoints

## Title

Missing `!m_restricted` Guard on `generate_ed25519_keypair` and `sign_message` RPC Endpoints

## CWE

CWE-284: Improper Access Control

## Severity

**Medium**

CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L — **6.5**

## Affected Version

Electroneum legacy daemon (CryptoNote-based chain) — current `master` branch.

## Summary

The `generate_ed25519_keypair` and `sign_message` RPC endpoints are registered using `MAP_JON_RPC_WE` instead of `MAP_JON_RPC_WE_IF(..., !m_restricted)`, making them accessible on restricted (public-facing) RPC ports. Adjacent endpoints `set_validator_key` and `inject_emergency_vlist` correctly use the restricted guard.

This is a confirmed access control deficiency. However, it is **not** a signing oracle or key disclosure of existing secrets: `generate_ed25519_keypair` returns a new random keypair (not the node's validator key), and `sign_message` requires the caller to supply their own private key.

## Technical Details

### Root Cause

In `src/rpc/core_rpc_server.h:176-179`, the endpoint registration is:

```
176: MAP_JON_RPC_WE_IF("set_validator_key", ..., !m_restricted)      // RESTRICTED ✓
177: MAP_JON_RPC_WE("generate_ed25519_keypair", ...)                  // UNRESTRICTED ✗
178: MAP_JON_RPC_WE("sign_message", ...)                              // UNRESTRICTED ✗
179: MAP_JON_RPC_WE_IF("inject_emergency_vlist", ..., !m_restricted)  // RESTRICTED ✓
```

The macros are defined in `contrib/epee/include/net/http_server_handlers_map2.h`:

- `MAP_JON_RPC_WE_IF(name, fn, type, cond)` — dispatches only when `(callback_name == method_name) && (cond)` (line 177-193)
- `MAP_JON_RPC_WE(name, fn, type)` — expands to `MAP_JON_RPC_WE_IF(name, fn, type, true)` (line 194)

The `true` condition means the endpoint dispatches regardless of whether `m_restricted` is set.

### Endpoint Behavior

**`generate_ed25519_keypair`** (`core_rpc_server.cpp:2625-2639`):
- Takes no parameters
- Calls `crypto::create_ed25519_keypair()` which generates 32 random bytes and derives a public key
- Returns `{privateKey: hex, publicKey: hex}` — a **new random** keypair
- Does **not** access the node's validator key, wallet keys, or any stored secret

**`sign_message`** (`core_rpc_server.cpp:2642-2664`):
- Takes `{privateKey: hex, message: string}` — the caller supplies the private key
- Calls `ed25519_sign()` using the **caller-supplied** key
- Returns `{signature: hex}`
- Does **not** use the node's own keys — the caller must already possess the private key

### Configuration Context

- Default RPC bind address: `127.0.0.1` (loopback only) — not remotely reachable without explicit `--rpc-bind-ip 0.0.0.0 --confirm-external-bind`
- Restricted mode: activated via `--restricted-rpc` or `--rpc-restricted-bind-port`
- No TLS by default (`--rpc-ssl autodetect`)

## Threat Model

### Confirmed Risks

1. **Access control inconsistency**: Administrative/utility endpoints available on the public-facing restricted port alongside read-only endpoints, violating the principle of least privilege
2. **Key material in transit**: `generate_ed25519_keypair` returns private keys over potentially unencrypted HTTP — a passive eavesdropper on the network path obtains a usable private key
3. **Caller key exposure**: `sign_message` accepts private keys over the network — if a caller uses this to sign validator operations, their secret traverses an unencrypted channel
4. **Computational DoS**: Both endpoints perform cryptographic operations (key generation, signing) callable by any remote client without authentication or rate limiting

### What This Is NOT

1. **Not a signing oracle**: A signing oracle uses a server-held secret. `sign_message` uses the caller's key — no privilege escalation occurs.
2. **Not disclosure of existing secrets**: `generate_ed25519_keypair` creates new random keys. It does not expose the node's validator key, spend key, or any stored secret.
3. **Not validator impersonation**: An attacker cannot use these endpoints to sign blocks or validator operations on behalf of the node.

## Reproduction Steps

**Environment**: Local testnet build only. Do NOT test against production nodes.

1. Build `electroneumd` from source
2. Start with restricted port:
   ```bash
   ./electroneumd --testnet \
       --rpc-bind-port 26968 \
       --rpc-restricted-bind-port 26969
   ```
3. Verify admin endpoint is blocked on restricted port:
   ```bash
   curl -s http://127.0.0.1:26969/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"set_validator_key","params":{}}'
   # Expected: blocked / method not found
   ```
4. Demonstrate bypass:
   ```bash
   curl -s http://127.0.0.1:26969/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"generate_ed25519_keypair"}'
   # Actual: returns {privateKey, publicKey, status: "OK"}
   ```
5. Run logic test: `python3 test_macro_expansion.py` — simulates macro dispatch and confirms the guard is missing

## PoC Evidence

The `test_macro_expansion.py` script simulates the C++ macro dispatch logic and confirms:
- In restricted mode (`m_restricted=true`): `set_validator_key` → blocked, `generate_ed25519_keypair` → dispatched, `sign_message` → dispatched, `inject_emergency_vlist` → blocked
- The bypass occurs because `MAP_JON_RPC_WE` hardcodes condition `true`, never checking `m_restricted`

## Impact

- **Confidentiality**: Low — newly generated key material transmitted over potentially unencrypted connections. No existing secrets exposed.
- **Integrity**: None — no state modification occurs.
- **Availability**: Low — computational DoS via unbounded key generation / signing requests on restricted port.
- **Scope**: Limited to nodes configured with `--rpc-restricted-bind-port` or `--restricted-rpc` with network-accessible binding.

## Remediation

Replace `MAP_JON_RPC_WE` with `MAP_JON_RPC_WE_IF` for both endpoints in `src/rpc/core_rpc_server.h`:

```diff
- MAP_JON_RPC_WE("generate_ed25519_keypair", on_generate_ed25519_keypair, COMMAND_RPC_GENERATE_ED25519_KEYPAIR)
- MAP_JON_RPC_WE("sign_message", on_sign_message, COMMAND_RPC_SIGN_MESSAGE)
+ MAP_JON_RPC_WE_IF("generate_ed25519_keypair", on_generate_ed25519_keypair, COMMAND_RPC_GENERATE_ED25519_KEYPAIR, !m_restricted)
+ MAP_JON_RPC_WE_IF("sign_message", on_sign_message, COMMAND_RPC_SIGN_MESSAGE, !m_restricted)
```

This is a one-line-per-endpoint fix that brings these endpoints in line with adjacent `set_validator_key` and `inject_emergency_vlist`.

## Disclosure

This finding was identified through static code analysis under the authorized Bugcrowd bug bounty program. No production systems were tested or affected.
