# Bug Bounty Report: Zero-Gas-Price DoS Vector via Compromised Priority Key

## Title

Compromised Gas-Waiver Priority Key Enables Free Block-Capacity Consumption Without Rate Limiting

## CWE

CWE-770: Allocation of Resources Without Limits or Throttling

## Severity

**Medium**

CVSS 3.1: AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L — **2.2** (base), elevated to **Medium** considering sustained economic impact and lack of per-key rate limiting.

## Affected Version

Electroneum Smart Chain (ETN-SC) — current `master` branch.

## Summary

Priority transactors with `IsGasPriceWaiver: true` can submit transactions with zero gas price that pass all validation layers — transaction pool admission, base fee checks, and execution-layer fee deduction. While block gas limits and pool slot limits provide absolute caps, there is no per-key rate limiting, per-key gas budget, or per-key pool quota. A compromised waiver key enables an attacker to consume block gas capacity indefinitely at zero economic cost.

This is a **resource-abuse vector**, not a consensus-breaking vulnerability. Block production and consensus continue normally. The practical impact is displacement of fee-paying transactions from block space and reduction of validator tip revenue.

## Root Cause

The gas waiver mechanism in `validatePriorityGasFields()` (`core/state_transition.go:389-426`) returns `hasGasPriceWaiver=true` for transactions signed with a waiver key, which:

1. **Skips the base fee check** (`state_transition.go:262`): `if !hasGasPriceWaiver && st.gasFeeCap.Cmp(st.evm.Context.BaseFee) < 0`
2. **Deducts zero from sender** (`state_transition.go:196-214`): `mgval = gas * gasPrice = gas * 0 = 0`
3. **Skips minimum gas price in pool** (`tx_pool.go:747`): `if !local && !isGasWaiver && tx.GasTipCapIntCmp(pool.gasPrice) < 0`

Block gas IS still consumed (`gp.SubGas(st.msg.Gas())` at `state_transition.go:208`), so each zero-fee transaction occupies real block space.

The missing control is **per-key rate limiting**: there is no mechanism to limit how many transactions per block, per epoch, or per time period a single priority key can authorize. The 5,120-slot priority pool limit is global across all keys — one compromised key can monopolize the entire priority pool.

## Technical Details

### Validation Path (Waiver Tx)

1. **Pool admission** (`tx_pool.go:708-744`): Priority signature verified → key found in `currentPriorityTransactors` → `IsGasPriceWaiver=true` → waiver consistency check passes (zero fees required) → underpriced check skipped → balance check passes (cost = 0 + value)
2. **Execution preCheck** (`state_transition.go:255-265`): `validatePriorityGasFields()` returns `hasGasPriceWaiver=true` → base fee check skipped
3. **buyGas** (`state_transition.go:196-216`): `gas * 0 = 0` deducted from sender; block gas pool decremented by `msg.Gas()`
4. **Execution**: Normal EVM gas metering; sender pays nothing for consumed gas

### Priority Transactor Configuration

Priority transactors are managed by an on-chain smart contract (`params/config.go:75,143`). Only the contract owner can add/remove entries. Each entry has:
- `PublicKey` (65-byte uncompressed secp256k1 key)
- `IsGasPriceWaiver` (boolean)
- `EntityName` (string)

### Capacity Impact

With a 30M block gas limit:
- ~1,428 simple zero-fee transfers per block (21,000 gas each)
- ~30 complex contract calls per block (1M gas each)
- Cost to attacker: 0 ETN per block, sustainable indefinitely

### Existing Mitigations

| Control | Effectiveness |
|---------|---------------|
| Block gas limit | Caps per-block throughput |
| Priority pool slots (5,120 + 1,024) | Caps mempool flooding |
| On-chain key revocation | Effective once detected; mid-block refresh available |
| Separate pool partitions | Regular txs not displaced from their pool |
| Nonce ordering | Limits per-account throughput (but attacker can use multiple accounts) |

### Missing Controls

| Gap | Impact |
|-----|--------|
| No per-key rate limit | One key can authorize unlimited txs |
| No per-key pool quota | One key can fill entire priority pool |
| No per-key gas budget | No cumulative gas cap per block per key |
| No anomaly detection | No alerting on abnormal volume |

## Reproduction Steps

1. Run `python3 test_gas_waiver_logic.py` — simulates validation logic confirming zero-fee acceptance
2. For full integration testing (requires Go build):
   - Configure a StateDB with a waiver priority transactor
   - Submit a PriorityTxType transaction with `gasFeeCap=0`, `gasTipCap=0`
   - Verify `validatePriorityGasFields()` returns `(true, nil)`
   - Verify `buyGas()` deducts 0 from sender but decrements block gas pool
   - Submit an identical tx without the waiver key and verify `ErrFeeCapTooLow`

## Evidence

The `test_gas_waiver_logic.py` test confirms (11/11 pass):
- Waiver txs accepted with zero fees through all validation layers
- Non-waiver txs correctly rejected with zero fees
- Block gas consumed despite zero fee payment
- Pool limits cap total priority tx count to 6,144
- Significant block capacity (~1,428 simple txs/block) consumable for free

## Impact

**What is demonstrated:**
- Free, sustained block-capacity consumption by a compromised waiver key
- Displacement of legitimate priority transactions from the priority pool
- Zero validator tip revenue for priority-filled block space

**What is NOT demonstrated:**
- No consensus failure — validators continue producing blocks
- No node crashes — gas metering and block limits remain intact
- No direct impact on regular (non-priority) transaction processing (separate pool)
- No ability for ordinary users to obtain waiver keys

**Realistic scenario:** An attacker who compromises a priority key with gas waiver can fill blocks with zero-fee transactions until the key is revoked. With responsive governance, the attack window is limited; without detection, it could persist.

## Remediation

### Primary Fix: Per-key rate limiting

Add per-priority-key limits in both the transaction pool and block builder:

```go
// In TxPool: track pending tx count per priority key
type priorityKeyStats struct {
    pendingCount uint64
    pendingGas   uint64
}

// Reject when a single key exceeds its quota
if stats.pendingCount >= maxTxsPerPriorityKey {
    return ErrPriorityKeyQuotaExceeded
}
```

### Secondary Fixes:
1. **Per-key gas budget per block**: Limit cumulative gas authorized by a single priority key within one block
2. **Anomaly detection**: Log and alert when priority tx volume from a single key exceeds thresholds
3. **Key expiry**: Add time-based validity windows for priority keys, requiring periodic renewal

## Disclosure

This finding was identified through static code analysis under the authorized Bugcrowd bug bounty program. No production systems were tested or affected. All analysis uses synthetic data and in-memory testing.
