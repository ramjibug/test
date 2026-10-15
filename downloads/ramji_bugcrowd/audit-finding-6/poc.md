# Finding 6: Gas Waiver DoS — Proof of Concept

## Overview

This PoC demonstrates that priority transactions with `IsGasPriceWaiver: true` bypass all fee checks while still consuming block gas capacity. The test uses the existing ETN-SC test framework with synthetic accounts.

## Prerequisites

- Go 1.19+ installed
- ETN-SC source code checked out
- No network connections required — all tests are local/in-memory

## Test Approach

The PoC uses Go's testing framework to:
1. Set up an in-memory blockchain with a priority transactor map containing a waiver key
2. Submit transactions with zero gas price using the waiver key
3. Verify they are accepted through validation
4. Submit identical transactions without the waiver and verify they are rejected
5. Verify block gas is consumed despite zero fees

## Setup

The test creates a synthetic priority transactor with `IsGasPriceWaiver: true` in the StateDB, then exercises the validation path.

### Test 1: validatePriorityGasFields accepts zero-fee waiver tx

```go
// Setup: StateDB with a waiver transactor
statedb.SetPriorityTransactors(common.PriorityTransactorMap{
    testPubKey: {IsGasPriceWaiver: true, EntityName: "test-waiver"},
})

// Create a priority tx message with zero fee fields
msg := types.NewMessage(
    from, &to, nonce, value,
    gasLimit,
    big.NewInt(0), // gasPrice = 0
    big.NewInt(0), // gasFeeCap = 0
    big.NewInt(0), // gasTipCap = 0
    nil, nil, false,
    priorityPubKey, // waiver key
)

// Validate
hasWaiver, err := validatePriorityGasFields(evm, msg)
// Expected: hasWaiver=true, err=nil
```

### Test 2: validatePriorityGasFields rejects zero-fee non-waiver tx

```go
// Setup: StateDB with a NON-waiver transactor
statedb.SetPriorityTransactors(common.PriorityTransactorMap{
    testPubKey: {IsGasPriceWaiver: false, EntityName: "test-no-waiver"},
})

// Same zero-fee message
hasWaiver, err := validatePriorityGasFields(evm, msg)
// Expected: hasWaiver=false, err=errNoGasPriceWaiver
```

### Test 3: buyGas deducts zero from sender balance

```go
// With gasPrice=0, buyGas computes:
// mgval = gas * gasPrice = 21000 * 0 = 0
// st.state.SubBalance(from, 0) -- no deduction

// But block gas IS consumed:
// st.gp.SubGas(21000) -- 21000 gas removed from block gas pool
```

### Test 4: Pool admission accepts waiver tx with zero fees

```go
// tx_pool.validateTx path:
// Line 721: isGasWaiver = transactor.IsGasPriceWaiver → true
// Line 726: tx.HasZeroFee() → true (matches waiver requirement)
// Line 747: !isGasWaiver is false → skip underpriced check
// Line 756: tx.Cost() = 0 + 0 = 0 → balance check passes (any balance ≥ 0)
// Result: tx accepted into priority pool
```

### Test 5: Block capacity consumption

```go
// Block gas limit: 30,000,000
// Simple transfer intrinsic gas: 21,000
// Max zero-fee simple txs per block: 30,000,000 / 21,000 ≈ 1,428
// Contract call with 1M gas: 30,000,000 / 1,000,000 = 30 per block

// Each zero-fee tx consumes real block gas, displacing fee-paying txs
```

## Running the Python Logic Test

```bash
cd audit-finding-6/
python3 test_gas_waiver_logic.py
```

This test simulates the validation logic without requiring a full Go build.

## Expected vs. Actual Results

| Scenario | Expected | Actual |
|----------|----------|--------|
| Waiver key + zero fees | Accepted | **Accepted** |
| Waiver key + non-zero fees | Rejected | **Rejected** |
| Non-waiver key + zero fees | Rejected | **Rejected** |
| Non-waiver key + positive fees | Accepted | **Accepted** |
| Regular tx + zero fees | Rejected (ErrFeeCapTooLow) | **Rejected** |
| Waiver tx consumes block gas | Yes (gp.SubGas) | **Yes** |
| Waiver tx deducts sender ETN | No (gas*0=0) | **No** |
| Pool limits apply to waiver txs | Yes (5120+1024) | **Yes** |
| Per-key rate limit | Should exist | **Does not exist** |

## What This Demonstrates vs. What It Does Not

### Demonstrated:
- Zero-gas-price transactions ARE accepted through all validation layers when signed with a waiver key
- The sender pays zero ETN for gas while consuming real block gas capacity
- Pool limits provide a cap on mempool flooding (6,144 total priority slots)

### NOT demonstrated:
- This PoC does NOT demonstrate network-wide denial of service
- This PoC does NOT demonstrate consensus failure
- Block production continues normally — blocks are just filled with zero-fee txs instead of fee-paying ones
- Regular (non-priority) transactions are in a separate pool partition and are not directly displaced from the mempool

### NOT claimed:
- We do NOT claim this enables unbounded flooding (pool limits exist)
- We do NOT claim this crashes nodes (gas metering is intact)
- We do NOT claim ordinary users can obtain waiver keys (requires smart contract governance)

## Safety Notes

- All testing uses synthetic accounts and in-memory state
- No network connections to any Electroneum network
- No real keys, funds, or transactions involved
