# Bug Bounty Report: Priority-Tx Signature Not Bound to Sender on Any Shipped Network

## Title

Priority-Tx Signature Is Not Bound to the Sender on Any Shipped Network: Zero-Fee Replay Across Accounts

## CWE

CWE-345: Insufficient Verification of Data Authenticity

## Severity

**High (P2)**

CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N — **7.5**

## Affected Version

Electroneum Smart Chain (ETN-SC) — current `master` branch. All shipped networks: mainnet (ChainID 52014), stagenet (ChainID 5201419), testnet (ChainID 5201420).

## Known-Issue Disclosure

**Important**: The Electroneum team appears aware of this issue. The repository contains:
1. A fix (`futureForkSigner`) in `core/types/transaction_signing.go:362-429`
2. Comprehensive test coverage in `core/types/priority_sig_binding_test.go` (6 tests)
3. Comments explicitly stating "This documents the vulnerability"

However, the fix is **not activated on any network** — `FutureForkBlock = math.MaxInt64` in `params/config.go` for mainnet (line 63), stagenet (line 96), and testnet (line 128). The vulnerability remains live. This report documents the unmitigated risk and the impact of the indefinite delay in activating the fix.

## Summary

The priority transaction signing scheme on all shipped ETN-SC networks uses `londonSigner.PriorityHash(tx)`, which returns the same hash as `londonSigner.Hash(tx)` — a hash over the transaction body fields only, excluding the sender's ECDSA signature (V, R, S). This means the priority key's signature is not bound to any particular sender account.

An attacker who observes a valid priority transaction in the mempool or on-chain can extract the priority signature (PriorityV, PriorityR, PriorityS) and replay it onto a different transaction signed by their own account. The replayed transaction passes all validation — the priority signature recovers to the same authorized public key because it was computed over an identical body hash.

If the replayed priority key has `IsGasPriceWaiver: true`, the attacker's transaction executes with zero gas fees, enabling free block-capacity consumption from an unauthorized account.

## Root Cause

### The Vulnerable Code Path

**`core/types/transaction_signing.go:356-360`** — `londonSigner.PriorityHash`:
```go
func (s londonSigner) PriorityHash(tx *Transaction) common.Hash {
    return s.Hash(tx)
}
```

`Hash(tx)` includes only: ChainID, Nonce, GasTipCap, GasFeeCap, Gas, To, Value, Data, AccessList. It does **not** include the sender's V, R, S signature values.

**`core/types/transaction_signing.go:293-307`** — `londonSigner.PrioritySender`:
```go
func (s londonSigner) PrioritySender(tx *Transaction) (common.PublicKey, error) {
    // ...
    return recoverPublicKey(s.Hash(tx), V, R, S, true)
    //                      ^^^^^^^^^^
    //                      body-only hash — same for any sender
}
```

The priority public key is recovered against the body-only hash. Since `PriorityHash == Hash`, two transactions with identical body fields but different senders produce the same hash, so the same priority signature is valid on both.

### The Fix (Written But Not Activated)

**`core/types/transaction_signing.go:395-414`** — `futureForkSigner.PriorityHash`:
```go
func (s futureForkSigner) PriorityHash(tx *Transaction) common.Hash {
    V, R, S := tx.RawSignatureValues()
    return prefixedRlpHash(
        tx.Type(),
        []interface{}{
            s.chainId, tx.Nonce(), tx.GasTipCap(), tx.GasFeeCap(),
            tx.Gas(), tx.To(), tx.Value(), tx.Data(), tx.AccessList(),
            V, R, S,  // ← sender's signature included
        })
}
```

This binds the priority signature to a specific sender by including V, R, S. But `futureForkSigner` is only selected when `IsFutureFork(blockNumber)` returns true.

### Why the Fix Is Inactive

**`params/config.go`** — all networks:
```go
// Mainnet (line 63):
FutureForkBlock: big.NewInt(math.MaxInt64),  // 9223372036854775807

// Stagenet (line 96):
FutureForkBlock: big.NewInt(math.MaxInt64),

// Testnet (line 128):
FutureForkBlock: big.NewInt(math.MaxInt64),
```

`MakeSigner()` (`transaction_signing.go:48-65`) checks `config.IsFutureFork(blockNumber)` first. Since the fork block is `MaxInt64`, this always returns false, and `londonSigner` is selected on every network at every block height.

**`core/tx_pool.go:660-665`** — `prioritySigner()`:
```go
func (pool *TxPool) prioritySigner() types.Signer {
    if pool.futureFork {
        return types.NewFutureForkSigner(pool.chainconfig.ChainID)
    }
    return types.NewLondonSigner(pool.chainconfig.ChainID)
}
```

`pool.futureFork` is derived from the chain config and is always false on all networks.

## Attack Scenario

### Preconditions
1. The attacker can observe priority transactions (mempool monitoring or on-chain reading)
2. The observed priority key has `IsGasPriceWaiver: true`
3. The attacker can construct a transaction with identical body fields (ChainID, Nonce, GasTipCap=0, GasFeeCap=0, Gas, To, Value, Data, AccessList)

### Steps
1. **Observe**: Attacker monitors for a priority transaction from any sender. The transaction's priority signature (PriorityV, PriorityR, PriorityS) and body fields are visible.
2. **Construct**: Attacker creates a new `PriorityTx` with the same body fields.
3. **Sign**: Attacker signs the sender slot with their own private key (producing different V, R, S from the victim).
4. **Replay**: Attacker copies the victim's PriorityV, PriorityR, PriorityS into their transaction.
5. **Submit**: The transaction enters the pool. `PrioritySender()` recovers the authorized priority public key because `PriorityHash(attackerTx) == Hash(attackerTx) == Hash(victimTx) == PriorityHash(victimTx)`.
6. **Execute**: If the priority key has `IsGasPriceWaiver: true`, the attacker's transaction executes with zero gas fees.

### Practical Constraints
- The attacker must match ALL body fields exactly (ChainID, Nonce, gas params, To, Value, Data, AccessList) for the hash to match
- The attacker needs their own funded account (for the nonce) or can use a fresh account with nonce 0
- The attacker needs to observe at least one valid priority transaction with a gas waiver key
- Nonce reuse is constrained: the attacker's account must have a nonce matching the observed tx's nonce

### Nonce Window
The nonce constraint is significant but not prohibitive:
- A fresh attacker account has nonce 0 — if the observed tx uses nonce 0, replay is immediate
- The attacker can pre-increment their nonce to match any observed nonce by sending cheap transactions
- For waiver txs with GasTipCap=0 and GasFeeCap=0, the remaining fields are controllable

## Evidence

The repository's own test file (`core/types/priority_sig_binding_test.go`) contains authoritative proof:

**`TestPrioritySignatureReplay_PreFork` (line 14)**: Creates a victim's priority tx, extracts its priority signature, pastes it onto an attacker's tx with a different sender key, and verifies the replayed signature is valid with `londonSigner`.

**`TestPreForkSignerPriorityHashEqualsHash` (line 278)**: Explicitly verifies `PriorityHash(tx) == Hash(tx)` for `londonSigner`.

**`TestPrioritySignatureReplay_PostFork` (line 105)**: Confirms the same attack fails with `futureForkSigner`.

All 6 tests pass. The vulnerability is proven by the project's own test suite.

## Impact

### Confirmed:
- **Unauthorized priority access**: Any observer of a waiver-key priority transaction can grant themselves the same gas-free privilege
- **Zero-cost block capacity consumption**: Combined with the gas waiver bypass, an attacker can fill blocks at zero economic cost using someone else's priority authorization
- **Circumvents permissioning model**: The priority transactor system is designed to limit gas waivers to authorized entities; this breaks that guarantee

### Scenario Impact:
- **Fee displacement**: Attacker fills blocks with zero-fee transactions, displacing fee-paying transactions
- **Validator revenue loss**: Block space consumed without generating tips
- **Priority pool exhaustion**: Attacker can monopolize the 5,120-slot priority pool

### Bounded by:
- Block gas limit (30M gas) caps per-block throughput
- Nonce matching requirement adds friction
- Priority key revocation provides an eventual mitigation path
- The attacker cannot steal funds — only consume block capacity for free

### Eligible Outcome:
This maps to **(B) Gaming consensus** — the attacker manipulates the fee mechanism to gain unauthorized free execution, and **(E) Tricking exchanges about tx/block info** — transactions appear authorized by a priority entity when they are not.

## Reproduction

Run the existing Go test in the repository:
```bash
cd core/types/
go test -run TestPrioritySignatureReplay_PreFork -v
```

This test (written by the Electroneum team) demonstrates the full attack:
1. Victim creates and signs a priority tx
2. Attacker creates identical-body tx, signs with own key
3. Attacker pastes victim's priority signature
4. `PrioritySender()` with `londonSigner` accepts the replayed signature

Additionally, see `test_priority_sig_replay.py` for a Python logic demonstration.

## Remediation

### Immediate: Activate the existing fix

Schedule `FutureForkBlock` to a concrete block number on all networks:

```go
// params/config.go — mainnet
FutureForkBlock: big.NewInt(TARGET_BLOCK_NUMBER),

// Same for stagenet and testnet
```

The `futureForkSigner` code is already written, tested, and correct. It includes V, R, S in the priority hash, binding the priority signature to a specific sender. The fix requires only a configuration change and a coordinated hard fork.

### Additional Recommendations:
1. **Mempool privacy**: Consider not broadcasting raw priority transactions to all peers, reducing the observation window
2. **Priority signature expiry**: Add a timestamp or block-range field to priority signatures to limit replay windows
3. **Per-key rate limiting**: As noted in Finding 6, add per-priority-key gas budgets and pool quotas

## Disclosure

This finding was identified through static code analysis under the authorized Bugcrowd bug bounty program. No production systems were tested or affected. The analysis relies on code review, the repository's own test suite, and mathematical reasoning. No transactions were submitted to any Electroneum network.
