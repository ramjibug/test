# Priority-Tx Signature Replay — Proof of Concept

## Overview

This PoC demonstrates that the `londonSigner.PriorityHash(tx)` returns the same hash as `londonSigner.Hash(tx)`, allowing a priority signature to be replayed from one sender's transaction onto another sender's transaction. The replayed signature passes all validation because the priority key recovery operates on a body-only hash that is identical for both transactions.

## Prerequisites

- Python 3.6+ (for `test_priority_sig_replay.py`)
- Go toolchain (for running the repository's own tests)
- No network connections required
- No real keys or transactions involved

## Approach

The PoC takes three approaches:

1. **Logic demonstration** (Python): Simulates the hash computation and signature recovery logic to show that identical body fields produce identical priority hashes regardless of sender
2. **Repository test execution** (Go): Runs the Electroneum team's own test suite that proves the vulnerability
3. **Configuration verification**: Confirms `FutureForkBlock = MaxInt64` on all networks

## Running the Tests

### Python Logic Test
```bash
cd audit-priority-sig-replay/
python3 test_priority_sig_replay.py
```

### Go Repository Tests (Authoritative)
```bash
cd core/types/
go test -run TestPrioritySignatureReplay_PreFork -v    # Attack succeeds
go test -run TestPrioritySignatureReplay_PostFork -v   # Attack blocked by fix
go test -run TestPreForkSignerPriorityHashEqualsHash -v # PriorityHash == Hash
```

### Full Test Suite
```bash
cd core/types/
go test -run "Priority" -v
```

## Test Details

### Test 1: Hash Equivalence Proof

Demonstrates that `londonSigner.PriorityHash(tx)` returns the same value as `londonSigner.Hash(tx)`.

For a `PriorityTx` with body fields `{ChainID, Nonce, GasTipCap, GasFeeCap, Gas, To, Value, Data, AccessList}`:
- `Hash(tx)` = `keccak256(RLP(type || body_fields))`
- `PriorityHash(tx)` = `Hash(tx)` (line 358-360 of transaction_signing.go)

Since the sender's V, R, S are excluded from both hashes, two transactions with the same body but different senders produce the same hash.

### Test 2: Replay Simulation

Simulates the attack flow:
1. Victim signs a priority tx → produces `{body, V_v, R_v, S_v, PV, PR, PS}`
2. Attacker copies body fields, signs with own key → `{body, V_a, R_a, S_a}`
3. Attacker pastes PV, PR, PS from victim
4. `PrioritySender(londonSigner, attackerTx)` recovers the same priority pubkey
5. Attack succeeds: attacker has valid priority authorization

### Test 3: Fix Verification

With `futureForkSigner`:
- `PriorityHash(tx)` includes V, R, S from the sender
- `PriorityHash(victimTx) != PriorityHash(attackerTx)` because V, R, S differ
- Replayed priority signature fails to recover the correct pubkey
- Attack blocked

### Test 4: Fork Configuration Check

Verifies that `FutureForkBlock = math.MaxInt64 = 9223372036854775807` in all network configs:
- Mainnet (ChainID 52014): line 63 of params/config.go
- Stagenet (ChainID 5201419): line 96
- Testnet (ChainID 5201420): line 128

Since no block number will reach MaxInt64, the fix never activates.

### Test 5: Gas Waiver Interaction

If the replayed priority key has `IsGasPriceWaiver: true`:
- Attacker sets GasTipCap=0, GasFeeCap=0 (required for waiver txs)
- Pool validation passes (waiver key + zero fees = valid)
- Execution skips base fee check
- `buyGas()` deducts 0 from attacker
- Block gas IS consumed (up to 30M per block)

Combined impact: unauthorized free execution via replayed priority authorization.

## Expected Results

```
Test 1: PriorityHash == Hash for londonSigner (CONFIRMED)
Test 2: Priority signature replay succeeds pre-fork (CONFIRMED)
Test 3: Priority signature replay blocked post-fork (CONFIRMED)
Test 4: FutureForkBlock = MaxInt64 on all networks (CONFIRMED)
Test 5: Gas waiver applicable to replayed tx (CONFIRMED)
All 9 tests passed.
```

## What This Demonstrates vs. What It Does Not

### Demonstrated:
- `londonSigner.PriorityHash(tx) == londonSigner.Hash(tx)` (no sender binding)
- Priority signature from one sender is valid on any other sender's tx with same body
- The fix exists (`futureForkSigner`) but is inactive (`FutureForkBlock = MaxInt64`)
- Combined with gas waiver, enables free execution from unauthorized account
- The repository's own test suite confirms the vulnerability

### NOT Demonstrated:
- No real transactions were submitted to any network
- No real private keys were used or compromised
- No actual priority signatures were extracted from the network
- This PoC does not demonstrate mempool monitoring (observation is assumed)

### Practical Limitations:
- Attacker must match all body fields exactly for the hash to collide
- Nonce matching requires the attacker to control their account's nonce
- Priority key revocation provides eventual mitigation
- The attack is limited to priority transaction privileges, not fund theft

## Safety Notes

- All testing uses synthetic data and mathematical computation
- No connection to any Electroneum network
- No real keys, signatures, or transactions involved
- The Go tests are the repository's own, not externally injected code
