# RPC Restriction Bypass — Code Path Analysis

## Macro Definitions

The RPC registration macros are defined in:
`contrib/epee/include/net/http_server_handlers_map2.h`

**Line 177-193** — `MAP_JON_RPC_WE_IF`:
```cpp
#define MAP_JON_RPC_WE_IF(method_name, callback_f, command_type, cond) \
    else if((callback_name == method_name) && (cond)) \
    { \
      PREPARE_OBJECTS_FROM_JSON(command_type) \
      // ... dispatch to callback_f ...
    }
```

The `cond` parameter gates whether the endpoint is dispatched. When `cond` is `!m_restricted`, the endpoint is blocked on restricted RPC instances.

**Line 194** — `MAP_JON_RPC_WE`:
```cpp
#define MAP_JON_RPC_WE(method_name, callback_f, command_type) \
    MAP_JON_RPC_WE_IF(method_name, callback_f, command_type, true)
```

`MAP_JON_RPC_WE` is syntactic sugar for `MAP_JON_RPC_WE_IF(..., true)`. The condition is hardcoded `true`, meaning the endpoint is **always** dispatched regardless of `m_restricted`.

## Registration (src/rpc/core_rpc_server.h:176-178)

```
176: MAP_JON_RPC_WE_IF("set_validator_key", ..., !m_restricted)    // RESTRICTED
177: MAP_JON_RPC_WE("generate_ed25519_keypair", ...)               // UNRESTRICTED
178: MAP_JON_RPC_WE("sign_message", ...)                           // UNRESTRICTED
```

Adjacent `set_validator_key` (line 176) and `inject_emergency_vlist` (line 179) both use the `!m_restricted` guard. The two endpoints between them do not.

## Endpoint Implementations

### `generate_ed25519_keypair` (core_rpc_server.cpp:2625-2639)

1. **Request**: empty — no parameters (`COMMAND_RPC_GENERATE_ED25519_KEYPAIR::request_t` has no fields)
2. Calls `m_core.generate_ed25519_keypair()` → `crypto::create_ed25519_keypair()`
3. `crypto::create_ed25519_keypair()` (crypto.cpp:768-780):
   - Generates 32 random bytes via `ed25519_randombytes_unsafe(sk, 32)`
   - Derives public key via `ed25519_publickey(sk, pk)`
   - Returns `{hex(sk), hex(pk)}` as a vector of strings
4. **Response**: `{privateKey: hex, publicKey: hex, status: "OK"}`
5. **Critical observation**: This generates a **fresh random keypair**. It does NOT return the node's validator key, spend key, or any pre-existing secret.

### `sign_message` (core_rpc_server.cpp:2642-2664)

1. **Request**: `{privateKey: hex_string, message: string}`
2. Unhexes `req.privateKey` and calls `m_core.sign_message(unhex(req.privateKey), req.message)`
3. `crypto::sign_message()` (crypto.cpp:728-741):
   - Validates `privateKey.size() == 32`
   - Derives public key from the provided private key
   - Signs with `ed25519_sign(message, message_len, sk, pk, signature)`
   - Returns 64-byte signature
4. **Response**: `{signature: hex_string, status: "OK"}`
5. **Critical observation**: The private key is **supplied by the caller** in the request. The node does NOT use its own validator key or any stored secret. The caller must already possess the private key.

## Restricted Mode Configuration

- `--restricted-rpc`: Sets `m_restricted = true` (core_rpc_server.cpp:121)
- `--rpc-restricted-bind-port`: Creates a second RPC listener in restricted mode
- Default `--rpc-bind-ip`: `127.0.0.1` (loopback only) (rpc_args.cpp:93)
- External binding requires explicit `--rpc-bind-ip 0.0.0.0` plus `--confirm-external-bind`
- No TLS by default (`--rpc-ssl autodetect`)

## Threat Model

### What the finding IS:
1. **Access control deficiency**: Both endpoints bypass the `m_restricted` guard, making them available on restricted (public-facing) RPC ports alongside read-only endpoints
2. `generate_ed25519_keypair` returns private key material in the HTTP response — if the connection is unencrypted and intercepted, a passive eavesdropper obtains a usable private key
3. `sign_message` accepts private key material over the network — a caller who uses this to sign validator operations transmits their secret key over potentially unencrypted HTTP
4. Both can be used for computational DoS (generating keys or computing signatures)

### What the finding is NOT:
1. **Not a signing oracle**: `sign_message` uses the CALLER's key, not the node's validator key. A traditional signing oracle uses a server-held secret; this does not.
2. **Not key disclosure of existing secrets**: `generate_ed25519_keypair` creates a NEW random key. It does not expose the node's validator key, any stored wallet keys, or any pre-existing secret.
3. **Not an authentication bypass for validator operations**: The caller cannot use these endpoints to impersonate the node's validator or sign blocks on its behalf (that requires the validator's specific key, not a random new one).

### Prerequisites for exploitation:
1. Node must be running with a restricted RPC port exposed to the network (`--rpc-restricted-bind-port` or `--restricted-rpc` with `--rpc-bind-ip 0.0.0.0`)
2. Attacker must be able to reach the RPC port

### Counterevidence:
- Default binding is `127.0.0.1` — not remotely reachable without explicit configuration
- Neither endpoint accesses the node's private key store
- `sign_message` requires the caller to already have the private key (no privilege escalation)
- The same signing functionality is trivially reproducible offline with any ed25519 library

## Conclusion

The missing `!m_restricted` guard on lines 177-178 is a **confirmed access control deficiency**. The endpoints are sensitive administrative utilities that should not be available on public-facing restricted RPC. However, the impact is significantly lower than "critical key disclosure" because neither endpoint exposes pre-existing node secrets or acts as a signing oracle using node-held keys.

**Recommended severity: Medium (CWE-284: Improper Access Control)**
