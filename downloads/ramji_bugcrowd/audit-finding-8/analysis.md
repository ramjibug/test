# Finding 8: Biased Scalar Generation in `random32_unbiased()` — Code Path Analysis

## Root Cause

The rejection-sampling loop in `random32_unbiased()` uses `&&` (AND) instead of `||` (OR), creating a logically impossible rejection condition. The loop always executes exactly once, never rejecting any sample. As a result, `sc_reduce32` operates on the full `[0, 2^256)` range instead of a uniform sample from `[0, 15*l)`, producing a biased distribution modulo the ed25519 group order `l`.

## Source References

### The Bug

**`src/crypto/crypto.cpp:110-120`**:
```cpp
void random32_unbiased(unsigned char *bytes)
{
    // l = 2^252 + 27742317777372353535851937790883648493.
    // it fits 15 in 32 bytes
    static const unsigned char limit[32] = { 0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29,
        0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0 };
    do
    {
        generate_random_bytes_thread_safe(32, bytes);
    } while (!sc_isnonzero(bytes) && !less32(bytes, limit));
    //        ^^^^^^^^^^^^^^^^        ^^^^^^^^^^^^^^^^^^^^^^
    //        "bytes == 0"     AND    "bytes >= 15*l"
    // This condition is ALWAYS FALSE — zero is always < 15*l
    sc_reduce32(bytes);
}
```

### Helper Functions

**`sc_isnonzero()`** (`src/crypto/crypto-ops.c:3727-3732`):
```cpp
int sc_isnonzero(const unsigned char *s) {
    return (((int) (s[0] | s[1] | ... | s[31]) - 1) >> 8) + 1;
}
```
Returns 1 when nonzero, 0 when all-zeros. The name is accurate.

**`less32()`** (`src/crypto/crypto.cpp:98-108`):
```cpp
static inline bool less32(const unsigned char *k0, const unsigned char *k1) {
    for (int n = 31; n >= 0; --n) {
        if (k0[n] < k1[n]) return true;
        if (k0[n] > k1[n]) return false;
    }
    return false;
}
```
Returns `true` when `k0 < k1` (little-endian comparison from most-significant byte down).

**`sc_reduce32()`** (`src/crypto/crypto-ops.c:2334-2447`):
Standard Barrett reduction of a 256-bit value modulo the ed25519 group order `l`.

### The `limit` Constant

`limit = 15 * l` stored in little-endian. The comment confirms: "it fits 15 in 32 bytes." Since `l ≈ 2^252`, `15*l ≈ 15 * 2^252 ≈ 2^255.9`, which fits in 32 bytes (MSB = 0xF0).

## Boolean Logic Analysis

Substituting return value semantics into the while condition:

```
!sc_isnonzero(bytes)  →  true when bytes == 0, false when bytes != 0
!less32(bytes, limit) →  true when bytes >= limit, false when bytes < limit
```

The combined condition is:
```
(bytes == 0) AND (bytes >= 15*l)
```

**This is a logical contradiction.** Zero is always less than `15*l` (a huge positive number). The condition is always `false`, so the `do-while` loop executes exactly once and never rejects any sample.

### What was intended (correct version):
```cpp
} while (!sc_isnonzero(bytes) || !less32(bytes, limit));
```

Using `||` (OR), the loop retries when `bytes == 0` OR `bytes >= 15*l`. This would reject ~1/16 of samples (those in `[15*l, 2^256)`), as the comment "should be good about 15/16 of the time" confirms.

**This is a De Morgan's law error**: the developer likely reasoned "accept if (nonzero AND less-than-limit)" but incorrectly negated to get the retry condition.

## Mathematical Bias Derivation

Since rejection never occurs, `sc_reduce32` operates on the full `[0, 2^256)` range.

### Division of 2^256 by l:

```
l = 2^252 + δ,  where δ = 27742317777372353535851937790883648493

2^256 = 16 * 2^252 = 16 * (l - δ) = 16*l - 16*δ

Therefore: 2^256 mod l = l - 16*δ  (since 2^256 = 15*l + (l - 16*δ))
```

The quotient is `q = 15`, remainder `r = l - 16*δ`.

### Residue class distribution:

For the `sc_reduce32(x)` mapping from `[0, 2^256)` → `[0, l)`:

| Residue class | Count of pre-images | Probability |
|---------------|---------------------|-------------|
| `[0, l - 16*δ)` | **16** | 16/2^256 |
| `[l - 16*δ, l)` | **15** | 15/2^256 |

- **Over-represented classes**: `l - 16*δ ≈ l` (the vast majority of residues)
- **Under-represented classes**: `16*δ ≈ 16 * 2^125 = 2^129` residue values near the top of the scalar range
- **Multiplicative bias**: 16/15 ≈ **6.67%** between most-probable and least-probable outputs

### Correct behavior (with `||`):

The input range would be `[1, 15*l)`, which has exactly `15*l - 1` values. After `sc_reduce32`:
- Each residue in `[0, l)` would have exactly 15 pre-images (ignoring the missing 0)
- Bias would be negligible (~1/15*l per residue)

## Caller Analysis — Security Impact

`random32_unbiased()` is the **sole source of random scalars** for the entire cryptographic layer.

### Direct callers:
| Function | Location | Usage | Security Impact |
|----------|----------|-------|-----------------|
| `random_scalar()` | crypto.cpp:122 | Thin wrapper | All callers below |
| `rct::skGen()` | rctOps.cpp:254 | RingCT key gen | All RingCT callers below |

### `random_scalar()` callers:
| Function | Location | Usage | Impact |
|----------|----------|-------|--------|
| `generate_keys()` | crypto.cpp:147 | Wallet key generation | **Every wallet's spend/view keys are biased** |
| `generate_signature()` | crypto.cpp:284 | Schnorr signature nonce `k` | **Biased nonces → potential key recovery** |
| `generate_tx_proof()` | crypto.cpp:360 | Tx proof nonce `k` | Biased proof nonces |
| `generate_input_signature()` | crypto.cpp:535 | Input signature nonce | Biased nonces |
| `generate_ring_signature()` | crypto.cpp:644,657,658 | Ring sig nonce `k`, decoys `w_i`/`q_i` | **Biased ring signatures weaken anonymity** |

### `rct::skGen()` callers:
| Function | Location | Usage |
|----------|----------|-------|
| `genBorromean()` | rctSigs.cpp:116,119,130 | Borromean ring sig generation |
| `proveRange()` | rctSigs.cpp:346 | Range proof mask generation |
| `genRct()/genRctSimple()` | rctSigs.cpp:873 | Pseudo-output mask generation |

## Exploitability Assessment

### Biased nonces (most dangerous path):

The 16/15 multiplicative bias affects values in `[l-16*δ, l)` — approximately `2^129` residue classes near the top of the scalar range. For signature nonces, this means:

1. **Known bias structure**: An attacker knows which residue classes are under-represented
2. **Lattice attacks**: Biased ECDSA/Schnorr nonces are the basis for well-known lattice attacks (Howgrave-Graham/Smart, Bleichenbacher, Minerva, TPM-FAIL). These attacks recover secret keys from signatures with biased nonces.
3. **Practical constraint**: The bias here is ~6.67% multiplicative, affecting a `2^129/2^252 ≈ 2^{-123}` fraction of the output space. This is significantly weaker than the biases exploited in Minerva (~1 bit leaked per signature). Practical exploitation would require an astronomical number of observed signatures.

### Biased keys (secondary path):

Wallet secret keys are not uniformly distributed over `[0, l)`. The statistical advantage for brute-force key search is negligible (~6.67% for a small fraction of the key space).

### Counterevidence and mitigations:

1. **Bias magnitude is small in practice**: The 16/15 ratio affects only ~0.00000...% of the scalar range (2^129 out of 2^252 residues). For any single scalar, the probability of landing in the biased region is ~2^{-123}.
2. **No existing exploit for this exact bias profile**: Published nonce-bias attacks target much larger biases (multiple bits per signature). The ~6.67% multiplicative bias on a ~2^{-123} fraction of outputs is orders of magnitude below published attack thresholds.
3. **Ring signature structure**: CryptoNote ring signatures involve multiple scalars; the bias affects each independently, but the composite bias in the ring structure has not been analyzed for this specific profile.

### Existing tests:

**`tests/unit_tests/random.cpp:37-47`**: Tests that output is already reduced (sc_reduce32 is idempotent). This test **passes with the bug** — it checks format, not distribution. It does NOT detect the bias.

## Upstream Comparison

Upstream Monero uses `||` (OR) in the equivalent rejection loop. The Electroneum code uses `&&` (AND). The comment "should be good about 15/16 of the time" is inherited from upstream and describes the correct `||` behavior, further confirming this is an error.

## Severity Assessment

**High** — The bug is mathematically confirmed: rejection sampling is completely disabled, producing biased scalars. The function is used for every security-critical random scalar in the codebase (secret keys, signature nonces, ring signature parameters, RingCT masks). While the practical exploitability via known lattice attacks is limited by the specific bias profile, the fundamental cryptographic invariant (uniform random scalars) that all security proofs depend on is violated. The severity is High because:

1. The defect is in a foundational cryptographic primitive
2. Every secret key and signature nonce in the system is affected
3. The bias is mathematically provable and structurally exploitable in principle
4. Upstream Monero has the correct code, confirming this is a regression
