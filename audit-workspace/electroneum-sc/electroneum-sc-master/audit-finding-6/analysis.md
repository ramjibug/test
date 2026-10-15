# Finding 6: Gas Waiver DoS Vector — Code Path Analysis

## Root Cause

Priority transactors with `IsGasPriceWaiver: true` can submit transactions with zero gas price, bypassing all fee-related checks. If a priority key is compromised, the attacker gains free, unlimited execution within block gas limits — no economic cost to sustain the attack.

## Source References

### Gas Waiver Validation

**`core/state_transition.go:389-426`** — `validatePriorityGasFields()`:
```go
func validatePriorityGasFields(evm *vm.EVM, msg Message) (bool, error) {
    ps := msg.PrioritySender()
    if ps == (common.PublicKey{}) {
        return false, nil
    }
    transactor, found := evm.StateDB.GetPriorityTransactorByKey(ps)
    if !found {
        return false, fmt.Errorf("%w: Bad priority pubkey %v", errBadPriorityKey, ps)
    }
    feeCap := msg.GasFeeCap()
    tipCap := msg.GasTipCap()
    if transactor.IsGasPriceWaiver {
        if feeCap.Sign() != 0 || tipCap.Sign() != 0 {
            return true, fmt.Errorf("%w: waiver priority tx must have zero fee fields", errNoGasPriceWaiver, ps)
        }
        return true, nil   // ← gas price waiver granted
    }
    if feeCap.Sign() <= 0 {
        return false, fmt.Errorf("%w: non-waiver priority tx must have feeCap > 0", errNoGasPriceWaiver, ps)
    }
    return false, nil
}
```

Called from `preCheck()` at line 255. When it returns `hasGasPriceWaiver=true`, the base fee check at line 262 is skipped:
```go
if !hasGasPriceWaiver && st.gasFeeCap.Cmp(st.evm.Context.BaseFee) < 0 {
    return ... ErrFeeCapTooLow ...
}
```

### buyGas() with Zero Price

**`core/state_transition.go:196-216`** — `buyGas()`:
```go
mgval := new(big.Int).SetUint64(st.msg.Gas())
mgval = mgval.Mul(mgval, st.gasPrice)  // gas * 0 = 0 for waiver txs
// ...
st.gp.SubGas(st.msg.Gas())  // block gas IS still consumed
st.state.SubBalance(st.msg.From(), mgval)  // subtracts 0
```

Block gas pool is decremented (bounded by block gas limit), but the sender pays nothing.

### Transaction Pool Admission

**`core/tx_pool.go:669-768`** — `validateTx()`:
- Line 712: Priority signature must be valid
- Line 717: Priority key must exist in `currentPriorityTransactors`
- Line 721-728: Waiver key MUST submit zero fees; non-zero fees rejected
- Line 747: Waiver txs skip minimum gas price check
- Line 756: Balance check uses `tx.Cost() = gas*0 + value = value` — only value transfer checked
- Line 760-766: Intrinsic gas still enforced (≥21,000 for simple transfer)

### Priority Pool Limits

**`core/tx_pool.go:190-203`** — Default pool configuration:
```go
PrioritySlots: 4096 + 1024,  // 5120 executable priority tx slots
PriorityQueue: 1024,          // non-executable priority queue
AccountSlots:  16,             // per-account guaranteed slots
```

Pool overflow (`ErrPriorityTxPoolOverflow`) rejects new priority txs when full.

### Priority Transactor Configuration

**`common/types.go:443-451`**:
```go
type PriorityTransactor struct {
    IsGasPriceWaiver bool
    EntityName       string
}
type PriorityTransactorMap map[PublicKey]PriorityTransactor
```

Managed by an on-chain smart contract (hardcoded addresses in `params/config.go:75,143`). Only the contract owner/governance can add or remove priority transactors. The contract is queried via `GetPriorityTransactorsAt()` in `core/prioritytransactors.go` using EVM `StaticCall`.

### Key Revocation

**`core/tx_pool.go:1500-1509,1865-1874`**: When the priority transactor map updates (chain reorg or new block), transactions signed with revoked keys are immediately evicted from the mempool.

**`miner/worker.go:952-953` and `core/state_processor.go:162-163`**: Priority transactor cache refreshes mid-block after any tx targeting the priority contract address, so a governance tx revoking a key can take effect within the same block.

## What Is Bypassed vs. What Is Not

### Bypassed by gas waiver:
| Check | Location | Bypassed? |
|-------|----------|-----------|
| Base fee (`feeCap >= baseFee`) | state_transition.go:262 | Yes |
| Minimum gas price in pool | tx_pool.go:747 | Yes |
| Balance for gas cost (`gas * price`) | tx_pool.go:756 | Yes (cost=0) |
| Miner tip payment | state_transition.go:351-357 | Yes (tip=0) |

### NOT bypassed:
| Check | Location | Still enforced? |
|-------|----------|-----------------|
| Block gas limit | state_transition.go:208 (`gp.SubGas`) | Yes |
| Intrinsic gas (≥21,000) | tx_pool.go:760-766 | Yes |
| EVM opcode gas metering | Throughout EVM | Yes |
| Nonce ordering | tx_pool.go:751 | Yes |
| Priority key validation | tx_pool.go:712-719 | Yes |
| Priority pool slot limit (5,120+1,024) | tx_pool.go default config | Yes |
| Tx size limit (`txMaxSize`) | tx_pool.go:679 | Yes |
| Block gas limit per tx | tx_pool.go:688 | Yes |

## Attack Prerequisites

1. **Compromise a priority private key** with `IsGasPriceWaiver: true`. These keys are held by Electroneum or trusted entities in a permissioned model.
2. **Any sender account private key** (trivial to generate — the priority key authorizes separately from the ECDSA sender signature).

## Attack Capabilities

With a compromised waiver key, the attacker can:
1. Submit zero-fee transactions consuming up to full block gas limit every block
2. Fill the priority pool (5,120 + 1,024 = 6,144 slots)
3. Execute arbitrary contract calls and deploy contracts at zero cost
4. Displace legitimate priority transactions
5. Reduce miner/validator tip revenue to zero for priority-filled block space
6. Use multiple sender addresses (each with its own nonce sequence) all signed by the same priority key

## Mitigations and Counterevidence

### Existing controls:
1. **Block gas limit**: Caps throughput per block regardless of fee
2. **On-chain key revocation**: Contract owner can remove compromised key; mid-block refresh means it takes effect within the same block
3. **Separate pool partitioning**: Priority txs have their own pool; flooding it does not displace regular user transactions
4. **Priority key compromise is prerequisite**: Requires breaching a permissioned key management system

### Missing controls:
1. **No per-key rate limiting**: No limit on how many txs/block a single priority key can authorize
2. **No per-key pool quota**: One compromised key can fill the entire priority pool
3. **No per-key gas budget per block**: No cumulative gas limit per priority key
4. **No anomaly detection**: No built-in alerting for abnormal priority tx volume

## Severity Assessment

**Medium** — The vulnerability is real and bounded:
- Exploitation requires compromising a permissioned priority key (high prerequisite)
- Attack is economically free and sustainable indefinitely once key is compromised
- Impact is bounded by block gas limit, pool limits, and available key revocation
- No consensus failure — validators continue producing blocks; block capacity is consumed, not consensus integrity
- This is a resource-abuse vector, not a consensus-breaking vulnerability
