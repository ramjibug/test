# Priority-Tx Signature Replay — Code Path Analysis

## Root Cause

The `londonSigner.PriorityHash(tx)` method returns the same value as `londonSigner.Hash(tx)` — a hash over the transaction body fields only. The priority key's ECDSA signature is computed over this body-only hash, meaning it is not bound to any particular sender. Two transactions with identical body fields but different senders produce the same priority hash, so a priority signature from one is valid on the other.

The fix (`futureForkSigner`) includes the sender's V, R, S in the priority hash, but `FutureForkBlock = math.MaxInt64` on all networks prevents it from activating.

## Source References

### The Vulnerable Hash (londonSigner)

**`core/types/transaction_signing.go:335-360`**:
```go
func (s londonSigner) Hash(tx *Transaction) common.Hash {
    if tx.Type() != DynamicFeeTxType && tx.Type() != PriorityTxType {
        return s.eip2930Signer.Hash(tx)
    }
    return prefixedRlpHash(
        tx.Type(),
        []interface{}{
            s.chainId, tx.Nonce(), tx.GasTipCap(), tx.GasFeeCap(),
            tx.Gas(), tx.To(), tx.Value(), tx.Data(), tx.AccessList(),
        })
}

func (s londonSigner) PriorityHash(tx *Transaction) common.Hash {
    return s.Hash(tx)  // ← SAME as body hash
}
```

Fields in Hash/PriorityHash: `{ChainID, Nonce, GasTipCap, GasFeeCap, Gas, To, Value, Data, AccessList}`

Fields NOT in Hash/PriorityHash: `{V, R, S}` (sender's ECDSA signature)

### Priority Sender Recovery (londonSigner)

**`core/types/transaction_signing.go:293-307`**:
```go
func (s londonSigner) PrioritySender(tx *Transaction) (common.PublicKey, error) {
    switch inner := tx.inner.(type) {
    case *PriorityTx:
        V, R, S := inner.rawPrioritySignatureValues()
        V = new(big.Int).Add(V, big.NewInt(27))
        if tx.ChainId().Cmp(s.chainId) != 0 {
            return common.PublicKey{}, ErrInvalidChainId
        }
        return recoverPublicKey(s.Hash(tx), V, R, S, true)
        //                      ^^^^^^^^^^
        //                      body-only hash
    default:
        return common.PublicKey{}, ErrTxTypeNotSupported
    }
}
```

`recoverPublicKey(s.Hash(tx), ...)` uses the body-only hash. Since `Hash(tx)` is identical for two transactions with the same body fields regardless of sender, the same priority (PriorityV, PriorityR, PriorityS) values will recover the same public key on both.

### The Fix (futureForkSigner)

**`core/types/transaction_signing.go:395-414`**:
```go
func (s futureForkSigner) PriorityHash(tx *Transaction) common.Hash {
    if tx.Type() != PriorityTxType {
        return s.londonSigner.Hash(tx)
    }
    V, R, S := tx.RawSignatureValues()  // sender's signature
    return prefixedRlpHash(
        tx.Type(),
        []interface{}{
            s.chainId, tx.Nonce(), tx.GasTipCap(), tx.GasFeeCap(),
            tx.Gas(), tx.To(), tx.Value(), tx.Data(), tx.AccessList(),
            V, R, S,  // ← included in priority hash
        })
}
```

**`core/types/transaction_signing.go:417-429`** — recovery uses `s.PriorityHash(tx)` instead of `s.Hash(tx)`:
```go
func (s futureForkSigner) PrioritySender(tx *Transaction) (common.PublicKey, error) {
    // ...
    return recoverPublicKey(s.PriorityHash(tx), V, R, S, true)
}
```

### Fork Activation (Never)

**`params/config.go`**:
```go
// Line 63 — Mainnet (ChainID 52014):
FutureForkBlock: big.NewInt(math.MaxInt64),

// Line 96 — Stagenet (ChainID 5201419):
FutureForkBlock: big.NewInt(math.MaxInt64),

// Line 128 — Testnet (ChainID 5201420):
FutureForkBlock: big.NewInt(math.MaxInt64),
```

**`params/config.go:407-408`** — `IsFutureFork`:
```go
func (c *ChainConfig) IsFutureFork(num *big.Int) bool {
    return isForked(c.FutureForkBlock, num)
}
```

Since `math.MaxInt64 = 9223372036854775807`, no realistic block number triggers the fork.

### Signer Selection

**`core/types/transaction_signing.go:48-65`** — `MakeSigner`:
```go
func MakeSigner(config *params.ChainConfig, blockNum *big.Int) Signer {
    var signer Signer
    switch {
    case config.IsFutureFork(blockNum):
        signer = NewFutureForkSigner(config.ChainID)
    case config.ChainID != nil && config.LondonBlock != nil...:
        signer = NewLondonSigner(config.ChainID)
    // ...
    }
    return signer
}
```

Always falls through to `NewLondonSigner` on all networks.

**`core/tx_pool.go:660-665`** — pool signer:
```go
func (pool *TxPool) prioritySigner() types.Signer {
    if pool.futureFork {
        return types.NewFutureForkSigner(pool.chainconfig.ChainID)
    }
    return types.NewLondonSigner(pool.chainconfig.ChainID)
}
```

`pool.futureFork` is always false.

## Attack Flow

```
Attacker observes victimTx on-chain or in mempool:
  victimTx = {body fields..., V_victim, R_victim, S_victim, PV, PR, PS}

PriorityHash(victimTx) = Hash(body fields)   [londonSigner]

Attacker constructs:
  attackerTx = {same body fields..., V_attacker, R_attacker, S_attacker, PV, PR, PS}

PriorityHash(attackerTx) = Hash(same body fields)   [londonSigner]

Since body fields are identical:
  PriorityHash(attackerTx) == PriorityHash(victimTx)

Therefore:
  recoverPublicKey(PriorityHash(attackerTx), PV, PR, PS)
    == recoverPublicKey(PriorityHash(victimTx), PV, PR, PS)
    == authorized priority public key  ✓
```

## Nonce Matching Analysis

The attacker must match the victim's nonce. Analysis of practical scenarios:

| Scenario | Attacker Nonce | Victim Nonce | Match? |
|----------|---------------|-------------|--------|
| Fresh account | 0 | 0 | Yes (first tx) |
| Pre-incremented | N | N | Yes (send N cheap txs first) |
| Mismatched | M ≠ N | N | No (hash differs) |

The nonce constraint limits but does not prevent exploitation. The attacker controls their own nonce by choosing when to send preceding transactions.

## Gas Waiver Interaction

When the replayed priority key has `IsGasPriceWaiver: true`:

1. Pool validation (`tx_pool.go:721-728`): waiver key MUST have zero fees → attacker sets GasTipCap=0, GasFeeCap=0
2. Base fee check skipped (`state_transition.go:262`)
3. `buyGas()`: deducts `gas * 0 = 0` from attacker
4. Block gas pool decremented normally

Result: attacker executes transactions for free using someone else's priority authorization.

## Repository Awareness

The test file `core/types/priority_sig_binding_test.go` contains 6 tests:

| Test | Line | What It Proves |
|------|------|----------------|
| `TestPrioritySignatureReplay_PreFork` | 14 | Attack succeeds with londonSigner |
| `TestPrioritySignatureReplay_PostFork` | 105 | Attack fails with futureForkSigner |
| `TestFutureForkSigner_SignAndVerifyRoundtrip` | 178 | Fix works correctly |
| `TestFutureForkSigner_IncompatibleWithLondonSigner` | 219 | Cross-signer incompatibility |
| `TestPreForkSignerPriorityHashEqualsHash` | 278 | PriorityHash == Hash for londonSigner |
| `TestFutureForkSignerPriorityHashDiffersFromHash` | 304 | PriorityHash != Hash for futureForkSigner |

The team has characterized the vulnerability and built the fix. The open question is why `FutureForkBlock` remains at `MaxInt64` — this may be a scheduled hard fork awaiting coordination, or an indefinitely deferred fix.
