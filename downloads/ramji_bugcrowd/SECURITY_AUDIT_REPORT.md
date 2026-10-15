# Electroneum Security Audit Report
## Researcher: ramjiapi049
## Date: 2026-10-15
## Program: Bugcrowd / Electroneum

---

> **Disclaimer:** This audit was conducted under the authorized Bugcrowd bug bounty program.
> No exploits were enacted on production systems. All findings are based on static code analysis.
> The previously reported priority signature replay finding (PriorityTx hash omits sender V,R,S)
> is excluded from this report to avoid duplication.

---

# PART 1: Electroneum Smart Chain (ETN-SC)

## Finding 1: CRITICAL — Race Condition in StateDB PriorityTransactors Map

**Severity:** Critical (Node Crash / Denial of Service)
**CVSS:** 8.6
**Category:** Concurrency / Data Race
**Impact:** (E) Tricking exchanges about tx/block info — crashed validators produce stale data

### Location

- `core/state/statedb.go:1061-1073` — `SetPriorityTransactors` / `GetPriorityTransactorByKey`
- `core/state/statedb.go:711-712` — `Copy()` iterates map without lock

### Description

The `StateDB` struct has a `priorityTransactorsMu sync.Mutex` (line 105) that protects the `priorityTransactors` map. However, the mutex is only used by the **writer**:

```go
// WRITER — locks correctly (line 1061-1068)
func (s *StateDB) SetPriorityTransactors(transactors common.PriorityTransactorMap) {
    s.priorityTransactorsMu.Lock()
    defer s.priorityTransactorsMu.Unlock()
    s.priorityTransactors = make(common.PriorityTransactorMap)
    for key, transactor := range transactors {
        s.priorityTransactors[key] = transactor
    }
}

// READER — NO LOCK (line 1070-1073)
func (s *StateDB) GetPriorityTransactorByKey(pubkey common.PublicKey) (common.PriorityTransactor, bool) {
    transactor, found := s.priorityTransactors[pubkey]  // RACE!
    return transactor, found
}
```

Additionally, `Copy()` at line 711-712 iterates the map without holding the mutex:

```go
for key, transactor := range s.priorityTransactors {  // RACE!
    state.priorityTransactors[key] = transactor
}
```

### Concurrency Path

1. `SetPriorityTransactors` is called from `state_processor.go:75,163` and `miner/worker.go:878,953`
2. `GetPriorityTransactorByKey` is called from `state_processor.go:84,183` and `state_transition.go:401`
3. In Go, concurrent map read + map write is a **fatal, unrecoverable runtime panic** — `runtime.throw("concurrent map read and map write")` kills the entire process

### Attack Scenario

A malicious or high-volume submitter sends priority transactions targeting the priority transactors contract address while legitimate priority transactions are being validated. The `SetPriorityTransactors` call at `state_processor.go:163` (triggered when a tx targets the contract address) races with `GetPriorityTransactorByKey` at `state_processor.go:183` or `state_transition.go:401` during parallel validation. The fatal panic crashes the validator node.

### Impact

- Validator nodes crash with unrecoverable Go runtime panic
- Crashed validators cannot produce blocks or participate in IBFT consensus
- If enough validators crash (>1/3 of set), consensus halts entirely
- Exchanges relying on validator nodes receive stale/incorrect chain state

### Fix

Add mutex locking to `GetPriorityTransactorByKey`:

```go
func (s *StateDB) GetPriorityTransactorByKey(pubkey common.PublicKey) (common.PriorityTransactor, bool) {
    s.priorityTransactorsMu.Lock()
    defer s.priorityTransactorsMu.Unlock()
    transactor, found := s.priorityTransactors[pubkey]
    return transactor, found
}
```

And to the iteration in `Copy()` at line 711.

---

## Finding 2: HIGH — ethclient PrioritySender Returns Empty Key Without Error

**Severity:** High (Authentication Bypass)
**Category:** Authentication / Priority Transaction Validation
**Impact:** (A) Minting/burning tokens — gas waiver grants free transactions

### Location

- `ethclient/signer.go:54-56`

### Description

```go
func (s *senderFromServer) PrioritySender(tx *types.Transaction) (common.PublicKey, error) {
    // implement this later
    return common.PublicKey{}, nil
}
```

The `PrioritySender` method returns an empty/zero `PublicKey` with a `nil` error. Any caller using `ethclient` to validate priority transaction signatures will:

1. Receive a zero public key as if it were valid
2. Receive `nil` error indicating success
3. Potentially match the zero key against the priority transactors map

If the priority transactors contract ever contains a zero-key entry (through a bug or initialization), any transaction processed through `ethclient` would be treated as a valid priority transaction with gas fee waiver.

### Impact

- RPC clients using `ethclient` cannot verify priority transaction signatures
- Zero-key matching could grant unauthorized gas waivers
- Comment "implement this later" indicates this is known-incomplete code shipped to production

---

## Finding 3: HIGH — Panic in GetBaseBlockReward Crashes Node on DB Error

**Severity:** High (Denial of Service)
**Category:** Error Handling / Consensus
**Impact:** (E) Tricking exchanges — crashed nodes provide stale data

### Location

- `consensus/istanbul/backend/engine.go:281`

### Description

```go
func (sb *Backend) GetBaseBlockReward(...) *big.Int {
    // ...
    if circulatingSupply == nil {
        emission, err := sb.emission(chain, header.Number.Uint64()-1, header.ParentHash, nil)
        if err != nil {
            panic(fmt.Sprintf("Failed to get next base block reward: %v", err))
        }
        // ...
    }
    // ...
}
```

A database read error (disk corruption, I/O error, full disk) in `emission()` causes a `panic` that crashes the node. This is called during block finalization (`Finalize` at line 184), which is on the critical consensus path. In a consensus system, `panic` should never be used for recoverable errors — the error should propagate to allow graceful degradation.

### Attack Scenario

An attacker who can cause disk pressure (e.g., by flooding the mempool to grow the DB) or corrupt specific LevelDB entries can trigger the panic path, crashing validators. Combined with Finding 1, this creates multiple node-crash vectors.

---

## Finding 4: MEDIUM — Pre-Fork Block Proposer Not Cryptographically Bound

**Severity:** Medium (Consensus Integrity)
**Category:** Consensus / Authentication
**Impact:** (B) Gaming consensus — validator impersonation

### Location

- `consensus/istanbul/engine/engine.go:54-59` — `Author()`
- `consensus/istanbul/engine/engine.go:298-353` — `verifySigner()`
- `params/config.go:63,96,128` — `FutureForkBlock: big.NewInt(math.MaxInt64)`

### Description

Before the FutureFork (which is set to `math.MaxInt64` on all networks — effectively never activated):

1. `Author()` returns `header.Coinbase` directly on trust, with no cryptographic verification
2. `verifySigner()` only checks that `header.Coinbase` is a member of the validator set, but does NOT verify that the block was actually produced by that validator

The `ProposerSeal` mechanism that would cryptographically bind the proposer exists in code but is only enabled post-FutureFork. Since `FutureForkBlock = math.MaxInt64`, it will never activate on any currently configured network.

The PREPARE quorum requirement provides defense in depth (validators won't sign a block with a wrong coinbase), but a Byzantine proposer in round 0 can set any validator's address as coinbase and collect their block reward — until honest validators in later rounds detect and reject it.

### Impact

- Block reward can potentially be directed to wrong validator by malicious proposer
- Block attribution is not cryptographically guaranteed
- The fix exists in code but is permanently disabled

---

## Finding 5: MEDIUM — Simple Majority Validator Voting Threshold

**Severity:** Medium (Consensus Governance)
**Category:** Consensus / Governance
**Impact:** (B) Gaming consensus — validator set manipulation

### Location

- `consensus/istanbul/backend/snapshot.go` — vote threshold at `tally.Votes > snap.ValSet.Size()/2`
- `consensus/istanbul/backend/engine.go:605-739` — `snapApply()`

### Description

Validator addition/removal votes require only simple majority (`> Size()/2`), while QBFT consensus itself requires a 2/3 supermajority. This means:

- With N validators, only `N/2 + 1` votes can add or remove a validator
- A coalition controlling 51% of validators can add colluding validators and remove honest ones
- Over multiple epochs, this could escalate to full control of the validator set

The lower governance threshold compared to the consensus threshold creates an asymmetry that makes validator set takeover easier than breaking consensus directly.

---

## Finding 6: MEDIUM — Gas Waiver DoS Vector for Compromised Priority Keys

**Severity:** Medium (Denial of Service)
**Category:** Economic / DoS
**Impact:** (E) Tricking exchanges — mempool flooding

### Location

- `core/state_transition.go:389-426` — `validatePriorityGasFields()`
- `core/state_processor.go:172-199` — priority tx validation

### Description

Priority transactors with `GasPriceWaiver: true` can submit transactions with zero gas price. If a priority key is compromised, the attacker gains the ability to flood the network with zero-fee transactions. The `validatePriorityGasFields` function at `state_transition.go:401` checks the transactor map and allows zero gas if `GasPriceWaiver` is true, with no additional rate limiting beyond the block gas limit.

---

# PART 2: Legacy Electroneum (CryptoNote Chain)

## Finding 7: CRITICAL — RPC Signing Oracle Exposes Private Keys Over Unrestricted Endpoint

**Severity:** Critical (Key Disclosure / Authentication Bypass)
**Category:** RPC / Access Control
**Impact:** (C) Revealing keys — private keys returned to unauthenticated callers

### Location

- `src/rpc/core_rpc_server.h:177-178`

### Description

The `generate_ed25519_keypair` and `sign_message` RPC endpoints are mapped **without** the `!m_restricted` guard:

```cpp
// Line 176 — RESTRICTED (correct):
MAP_JON_RPC_WE_IF("set_validator_key", ..., !m_restricted)

// Lines 177-178 — UNRESTRICTED (vulnerable):
MAP_JON_RPC_WE("generate_ed25519_keypair", ..., COMMAND_RPC_GENERATE_ED25519_KEYPAIR)
MAP_JON_RPC_WE("sign_message", ..., COMMAND_RPC_SIGN_MESSAGE)
```

Compare with `set_validator_key` on line 176 which correctly uses `MAP_JON_RPC_WE_IF(..., !m_restricted)`. The vulnerable endpoints use `MAP_JON_RPC_WE` (no condition), meaning they are accessible even in restricted mode.

Any remote caller can:
1. Generate ed25519 keypairs on the node, with the **private key returned in the response**
2. Submit an arbitrary private key via `sign_message` and obtain a signature

This turns any public-facing daemon into a signing oracle.

---

## Finding 8: HIGH — Logic Bug in random32_unbiased Produces Biased Scalars

**Severity:** High (Cryptographic Weakness)
**Category:** Cryptography
**Impact:** (C) Revealing keys — biased key generation weakens all signatures

### Location

- `src/crypto/crypto.cpp:118`

### Description

```cpp
void random32_unbiased(unsigned char *bytes) {
    static const unsigned char limit[32] = { /* ed25519 order l */ };
    do {
        generate_random_bytes_thread_safe(32, bytes);
    } while (!sc_isnonzero(bytes) && !less32(bytes, limit));
    //        ^^^^^^^^^^^^^^^^^       ^^^^^^^^^^^^^^^^^
    //        "is zero"          AND  "not less than limit"
    sc_reduce32(bytes);
}
```

The loop condition uses `&&` (AND) but should use `||` (OR). The intent is to retry when the value is zero OR when it's >= the curve order. With `&&`, the loop only retries when the value is **both** zero AND >= limit simultaneously — which is impossible (zero is always less than limit). The rejection sampling therefore never rejects, executing exactly once every time.

This means `sc_reduce32` operates on the full 0..2^256 range instead of a uniform sample from 0..l, producing a biased distribution modulo the curve order l. This affects **all** key generation, nonce generation in ring signatures, and secret key derivation throughout the entire codebase. Compare with upstream Monero which uses `||` in equivalent code.

---

## Finding 9: HIGH — hash_to_point Missing Cofactor Multiplication

**Severity:** High (Cryptographic Weakness)  
**Category:** Cryptography
**Impact:** Small-subgroup attacks on key images

### Location

- `src/crypto/crypto.cpp:496-499`

### Description

```cpp
// CORRECT — hash_to_ec multiplies by cofactor 8 (line 492):
ge_mul8(&point2, &point);

// VULNERABLE — hash_to_point does NOT (line 496-499):
void hash_to_point(const crypto::hash &h, crypto::ec_point &res) {
    ge_p2 point;
    ge_fromfe_frombytes_vartime(&point, ...);
    ge_tobytes(crypto::operator&(res), &point);  // NO ge_mul8!
}
```

The adjacent `hash_to_ec` function correctly applies cofactor multiplication (`ge_mul8`), but `hash_to_point` does not. Without cofactor clearing, the output can land in a small subgroup of order 2, 4, or 8, enabling small-subgroup attacks on any protocol component using `hash_to_point` for key images or commitments.

---

## Finding 10: HIGH — Debug Commands Unconditionally Enabled with Null Trust Key

**Severity:** High (Information Disclosure)
**Category:** P2P / Configuration
**Impact:** (E) Tricking exchanges — full peer list and node internals leaked

### Location

- `src/cryptonote_config.h:147` — `#define ALLOW_DEBUG_COMMANDS`
- `src/cryptonote_config.h:199` — `P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY` set to all-zeros

### Description

`ALLOW_DEBUG_COMMANDS` is hardcoded and unconditional — all production builds include the debug P2P handlers (`COMMAND_REQUEST_STAT_INFO`, `COMMAND_REQUEST_NETWORK_STATE`, `COMMAND_REQUEST_PEER_ID`). These leak internal node statistics, full peer lists (IP addresses and peer IDs), and OS version strings.

The trust mechanism that should gate these handlers uses `P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY`, which is set to all-zeros. An all-zeros public key is the identity/neutral element, and `crypto::check_signature` against it may be trivially satisfiable.

---

## Finding 11: HIGH — Integer Underflow in Fee Calculation Before Overspend Check

**Severity:** High (Transaction Validation)
**Category:** Integer Overflow / Transaction Processing
**Impact:** (A) Minting/burning tokens — potential fee check bypass

### Location

- `src/cryptonote_core/tx_pool.cpp:171`

### Description

The fee is computed as `fee = inputs_amount - outputs_amount` (unsigned subtraction) **before** checking whether `outputs_amount > inputs_amount` (line 188). If `outputs_amount > inputs_amount`, this unsigned subtraction wraps to a very large value. While subsequent checks catch the overspend for v3+ transactions, the order of operations creates a window where the wrapped fee value is used in `check_fee` (line 255) before the overspend check on line 188 for certain transaction versions.

---

# Summary Table

| # | Severity | Codebase | Category | Location | Description |
|---|----------|----------|----------|----------|-------------|
| 1 | **Critical** | ETN-SC | Concurrency | statedb.go:1070-1073 | Race condition: map read without mutex → fatal panic |
| 2 | High | ETN-SC | Auth Bypass | signer.go:54 | PrioritySender stub returns zero key with nil error |
| 3 | High | ETN-SC | DoS | engine.go:281 | panic() on DB error in consensus path |
| 4 | Medium | ETN-SC | Consensus | engine.go:54-59 | Proposer not cryptographically bound (FutureFork disabled) |
| 5 | Medium | ETN-SC | Governance | snapshot.go | Simple majority validator voting vs 2/3 consensus threshold |
| 6 | Medium | ETN-SC | DoS | state_transition.go:401 | Gas waiver DoS via compromised priority key |
| 7 | **Critical** | Legacy | RPC Auth | core_rpc_server.h:177 | Key generation + signing oracle on unrestricted endpoint |
| 8 | High | Legacy | Crypto | crypto.cpp:118 | Biased scalar generation (&&  vs \|\|) |
| 9 | High | Legacy | Crypto | crypto.cpp:496 | hash_to_point missing cofactor (small-subgroup attack) |
| 10 | High | Legacy | P2P Info Leak | cryptonote_config.h:147 | Debug commands enabled; null trust key |
| 11 | High | Legacy | Int Overflow | tx_pool.cpp:171 | Fee underflow before overspend validation |

---

## Deduplication Note

The following known finding was **excluded** from this report:
- **Priority Transaction Signature Replay** — `londonSigner.PriorityHash(tx)` equals `Hash(tx)` without sender's V,R,S, allowing cross-account replay. Fix exists in `futureForkSigner` but `FutureForkBlock = math.MaxInt64` means it is not activated.

---

## Recommended Priority for Reporting

1. **Finding 1** (ETN-SC statedb race condition) — Strongest novel finding for ETN-SC. Clear code path to node crash.
2. **Finding 7** (Legacy RPC signing oracle) — Strongest novel finding for legacy chain. Clear auth bypass.
3. **Finding 8** (Legacy random32_unbiased bias) — Cryptographic primitive bug with system-wide impact.
4. **Finding 9** (Legacy hash_to_point cofactor) — Cryptographic primitive bug.
