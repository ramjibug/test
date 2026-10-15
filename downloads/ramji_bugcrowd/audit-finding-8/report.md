# Bug Bounty Report: Disabled Rejection Sampling Produces Biased Cryptographic Scalars

## Title

Logic Error in `random32_unbiased()` Disables Rejection Sampling, Producing Biased Scalars for All Key Generation and Signatures

## CWE

CWE-330: Use of Insufficiently Random Values

## Severity

**High**

CVSS 3.1: AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N — **8.7**

## Affected Version

Electroneum legacy daemon (CryptoNote-based chain) — current `master` branch.

## Summary

The `random32_unbiased()` function in `src/crypto/crypto.cpp:110-120` contains a boolean logic error (`&&` instead of `||`) that makes its rejection-sampling loop never reject any sample. The function is the sole source of random scalars for all cryptographic operations — key generation, signature nonces, ring signature parameters, and RingCT masks. Instead of producing uniform scalars over `[0, l)` (the ed25519 group order), it produces scalars with a provable 16/15 multiplicative bias between residue classes.

Upstream Monero uses `||` (correct) in the equivalent function. The comment "should be good about 15/16 of the time" in the Electroneum code describes the correct `||` behavior, confirming this is a regression.

## Root Cause

**`src/crypto/crypto.cpp:118`**:
```cpp
} while (!sc_isnonzero(bytes) && !less32(bytes, limit));
```

This evaluates to `(bytes == 0) AND (bytes >= 15*l)`, which is a logical impossibility — zero is always less than `15*l`. The loop always executes exactly once.

**Correct code** (matching upstream Monero):
```cpp
} while (!sc_isnonzero(bytes) || !less32(bytes, limit));
```

With `||`, the loop retries when `bytes == 0` OR `bytes >= 15*l`, correctly rejecting ~1/16 of samples.

## Technical Details

### The Intended Algorithm

1. Generate random 32 bytes (256 bits)
2. **Reject** if the value is zero or ≥ `15*l` (where `l` is the ed25519 group order)
3. Reduce modulo `l` using `sc_reduce32()`
4. Return a uniform scalar in `[0, l)`

The rejection step (2) ensures the input to `sc_reduce32` is in `[1, 15*l)`, where every residue class modulo `l` has exactly 15 pre-images, producing a uniform distribution.

### What Actually Happens

The rejection step never triggers. `sc_reduce32` operates on the full `[0, 2^256)` range.

### Mathematical Bias

```
l = 2^252 + 27742317777372353535851937790883648493
2^256 = 15*l + (l - 16*δ),  where δ = 27742317777372353535851937790883648493
```

| Residue class | Pre-images in [0, 2^256) | Relative probability |
|---------------|--------------------------|---------------------|
| [0, l-16δ) | 16 each | 16/2^256 |
| [l-16δ, l) | 15 each | 15/2^256 |

**Multiplicative bias: 16/15 ≈ 6.67%** between the most-probable and least-probable output values.

### Affected Callers (Complete List)

| Function | File:Line | Usage | Impact |
|----------|-----------|-------|--------|
| `generate_keys()` | crypto.cpp:147 | Wallet keypair | All wallet secret keys are biased |
| `generate_signature()` | crypto.cpp:284 | Schnorr nonce `k` | Biased nonces weaken signatures |
| `generate_tx_proof()` | crypto.cpp:360 | Tx proof nonce | Biased proofs |
| `generate_input_signature()` | crypto.cpp:535 | Input sig nonce | Biased nonces |
| `generate_ring_signature()` | crypto.cpp:644,657,658 | Ring sig nonce + decoys | Weakens anonymity |
| `rct::skGen()` | rctOps.cpp:254 | RingCT secret keys | All RingCT masks biased |
| `genBorromean()` | rctSigs.cpp:116,119,130 | Borromean ring sig | Biased ring sigs |
| `proveRange()` | rctSigs.cpp:346 | Range proof mask | Biased range proofs |
| `genRct()/genRctSimple()` | rctSigs.cpp:873 | Pseudo-output mask | Biased RingCT |
| Ledger device | device_ledger.cpp:2310-2311 | Hardware wallet ring sig | Hw wallet affected |

### Existing Test Is Insufficient

`tests/unit_tests/random.cpp:37-47` tests that `sc_reduce32` is idempotent on the output. This test passes with the bug because `sc_reduce32` always produces values in `[0, l)` regardless of input distribution. The test does not check uniformity.

## Reproduction Steps

1. Run `python3 test_random32_bias.py`
2. The test:
   - Proves the boolean condition is always false (8 test values, all return "no reject")
   - Derives the exact bias: 2^256 = 15*l + (l - 16δ), confirming 16/15 ratio
   - Simulates with a toy modulus to show observable over-representation
   - Enumerates all 13 security-critical callers

## Evidence

The `test_random32_bias.py` test confirms:
- The loop condition `(bytes == 0) AND (bytes >= 15*l)` is never true for any input
- The correct `||` version rejects zero and values ≥ 15*l (4 of 8 test values)
- The bias ratio is exactly 16/15 = 1.0667 (6.67%)
- Statistical simulation with toy modulus shows measurable over-representation of low residues
- 13 callers span all cryptographic operations in the codebase

## Impact

### Confirmed:
- **Violated cryptographic invariant**: The fundamental assumption of uniform random scalars, on which all ed25519/CryptoNote security proofs depend, does not hold
- **Every secret key generated on the legacy chain is biased**: Spend keys, view keys, and all ephemeral signing keys
- **Every signature nonce is biased**: Schnorr signatures, ring signatures, and RingCT all use biased nonces

### Theoretical escalation:
- **Biased nonces enable lattice attacks**: Published work (Minerva, TPM-FAIL, Howgrave-Graham/Smart) demonstrates secret key recovery from biased ECDSA/Schnorr nonces
- **Practical constraint**: The 6.67% bias affects ~2^129 residue classes out of ~2^252, a fraction of ~2^{-123}. This is below the bias levels exploited in published attacks (which typically require multiple bits of bias per signature). Practical exploitation would require further cryptanalytic advances.

### Not claimed:
- We do NOT claim immediate key recovery from the observed bias
- We do NOT claim that any specific wallet has been compromised
- The bias profile differs from published nonce-bias attacks in magnitude

## Remediation

**One-character fix** — change `&&` to `||` on `src/crypto/crypto.cpp:118`:

```diff
- } while (!sc_isnonzero(bytes) && !less32(bytes, limit));
+ } while (!sc_isnonzero(bytes) || !less32(bytes, limit));
```

This restores the intended rejection-sampling behavior, matching upstream Monero.

**Additional recommendation**: Add a distribution test to the test suite that verifies the output of `random32_unbiased()` is uniform (e.g., chi-squared test over buckets, or verify that `sc_reduce32` is NOT applied to values ≥ `15*l`).

## Disclosure

This finding was identified through static code analysis under the authorized Bugcrowd bug bounty program. No production systems were tested or affected. All analysis uses mathematical derivation and synthetic data.
