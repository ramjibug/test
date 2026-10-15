# Finding 8: Biased `random32_unbiased()` — Proof of Concept

## Overview

This PoC demonstrates that the rejection-sampling loop in `random32_unbiased()` never rejects, causing `sc_reduce32` to operate on the full `[0, 2^256)` range with a provable 16/15 multiplicative bias.

## Prerequisites

- Python 3.6+
- No network connections required
- No real keys or signatures involved

## Test Approach

The PoC takes three approaches:
1. **Logical proof**: Demonstrates the boolean condition is always false
2. **Mathematical derivation**: Computes the exact bias from first principles
3. **Statistical simulation**: Generates random values through the buggy path and measures distribution

## Running the Tests

```bash
cd audit-finding-8/
python3 test_random32_bias.py
```

## Test Details

### Test 1: Boolean Logic Proof

The while condition `!sc_isnonzero(bytes) && !less32(bytes, limit)` evaluates to:
- `!sc_isnonzero(bytes)` = `true` when bytes is all-zeros
- `!less32(bytes, limit)` = `true` when bytes ≥ 15*l

Combined: `(bytes == 0) AND (bytes >= 15*l)` — impossible for any nonzero limit.

The test evaluates this for all relevant value classes and confirms the condition is never true.

### Test 2: Mathematical Bias Calculation

```
l = 2^252 + 27742317777372353535851937790883648493
2^256 = 16 * 2^252 = 16*l - 16*δ  (where δ = 27742317777372353535851937790883648493)
2^256 = 15*l + (l - 16*δ)

Quotient: 15
Remainder: l - 16*δ
```

After `sc_reduce32` on uniform `[0, 2^256)`:
- Residues in `[0, l-16*δ)`: each has 16 pre-images → probability 16/2^256
- Residues in `[l-16*δ, l)`: each has 15 pre-images → probability 15/2^256
- Multiplicative bias: 16/15 ≈ 1.0667 (6.67%)

### Test 3: Correct Behavior Comparison

With `||` (the fix), the input range is `[1, 15*l)`:
- `15*l - 1` total values
- Each residue in `[1, l)` has exactly 15 pre-images
- Residue 0 has 14 pre-images (0 is excluded)
- Bias: ~1/(15*l) ≈ negligible

### Test 4: Statistical Simulation

Simulates `sc_reduce32(random_256bit)` for a small modulus to make the bias visible. Uses a toy modulus `l_toy = 11` with 256 → 11 to demonstrate the 16/15 ratio is observable in finite samples.

### Test 5: Caller Enumeration

Lists all callers of `random32_unbiased()` and `random_scalar()` with their security relevance.

## Expected Results

```
Test 1: Boolean condition is ALWAYS FALSE (loop never rejects)
Test 2: Bias ratio = 16/15 = 1.0667 (6.67%)
Test 3: Correct (||) version: bias ratio ≈ 1.0 (negligible)
Test 4: Statistical test shows over-representation of low residues
Test 5: 13 security-critical callers identified
```

## What This Demonstrates vs. What It Does Not

### Demonstrated:
- The rejection loop is provably non-functional (always executes once)
- The mathematical bias is exactly 16/15 for low residue classes
- Every random scalar in the codebase flows through this biased path
- The upstream Monero code uses `||` (correct), Electroneum uses `&&` (buggy)

### NOT demonstrated:
- This PoC does NOT recover any real private key
- This PoC does NOT demonstrate a practical lattice attack
- The bias magnitude (~6.67% on ~2^{-123} fraction of outputs) is below published nonce-bias attack thresholds
- We do NOT claim immediate key recovery is feasible

### Honest assessment:
The bug is **mathematically proven and real**. The security impact is that a fundamental cryptographic invariant (uniform random scalars) is violated. Whether the specific bias profile is practically exploitable with known techniques is a separate question — the bias is significantly smaller than those exploited in Minerva/TPM-FAIL attacks, but the violation of uniformity is unconditional.

## Safety Notes

- All testing uses synthetic data and mathematical computation
- No real keys, signatures, or transactions involved
- No connection to any Electroneum network
