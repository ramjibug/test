# CANDIDATE 1: Detailed Analysis

## RatedSwapPool Missing Rate Validity Check on add_liquidity

### Vulnerability Classification
- **Type**: Logic error / Missing validation
- **Location**: `rated_swap/mod.rs` lines 210-247 (`calc_add_liquidity_with_rates`)
- **Severity**: Medium (potentially High under extreme conditions)
- **Exploitable by unprivileged attacker**: Yes
- **Affected pool types**: All RatedSwapPools (stNEAR, LiNEAR, NEARX, SFRAX)

### Root Cause

`calc_add_liquidity_with_rates` (rated_swap/mod.rs:210) only calls
`assert_rates_valid()` when `shares_total_supply == 0` (bootstrap case, line 224).
For subsequent deposits (the else branch at line 236), no rate validity check occurs.

The rates used for the invariant computation come from `self.get_rates()` (line 94),
which reads from the global `RATES` static cache and returns whatever was last stored,
regardless of freshness.

### Inconsistency Map

| Operation                    | Code Location          | Calls assert_rates_valid()? |
|------------------------------|------------------------|-----------------------------|
| swap (internal_get_return)   | mod.rs:515             | YES                         |
| add_liquidity (bootstrap)    | mod.rs:224             | YES                         |
| add_liquidity (subsequent)   | mod.rs:236-246         | **NO**                      |
| remove_liquidity_by_tokens   | mod.rs:432             | YES                         |
| remove_liquidity_by_shares   | mod.rs:336             | NO (but proportional, no rates used) |

### Mathematical Proof of Value Extraction

Given a 2-token pool with tokens A (non-rated) and B (rated):
- Pool state: [a, b] in c_amounts
- Cached rate for B: r_stale
- True rate for B: r_true > r_stale (appreciation)

**With StableSwap invariant at high A:**
For large A, D ≈ sum(rated_balances)

**Step 1: Compute D with stale rate**
- rated_balances_stale = [a, b * r_stale]
- D_0_stale ≈ a + b * r_stale

**Step 2: Attacker deposits amount `x` of token A**
- new_balances = [a + x, b]
- rated_new_stale = [a + x, b * r_stale]
- D_1_stale ≈ (a + x) + b * r_stale

**Step 3: Shares minted (ignoring fees for clarity)**
- shares_stale = supply * (D_1_stale - D_0_stale) / D_0_stale
- shares_stale = supply * x / (a + b * r_stale)

**Step 4: Fair shares (with true rate)**
- D_0_true ≈ a + b * r_true
- shares_true = supply * x / (a + b * r_true)

**Step 5: Excess**
Since r_true > r_stale:
  (a + b * r_stale) < (a + b * r_true)
  Therefore: x / (a + b * r_stale) > x / (a + b * r_true)
  Therefore: shares_stale > shares_true

The attacker receives MORE shares than fair value.

**Excess ratio:**
  excess_ratio = shares_stale / shares_true - 1
               = (a + b * r_true) / (a + b * r_stale) - 1
               = b * (r_true - r_stale) / (a + b * r_stale)

For a balanced pool (a ≈ b * r_stale), and rate deviation δ = (r_true - r_stale) / r_stale:
  excess_ratio ≈ δ / 2

So a 5% rate deviation yields ~2.5% excess shares.
A 10% rate deviation yields ~5% excess shares.

### Attack Cycle

1. Wait for rate to go stale (or for external rate to diverge from cached)
2. Deposit non-rated token via `add_stable_liquidity()` — succeeds without rate check
3. Receive excess LP shares (shares_stale > shares_true)
4. Call `remove_liquidity()` (proportional) — succeeds without rate check
5. Receive proportional tokens including rated token
6. Net profit = excess_ratio * deposit_amount

### Extraction Value

The attacker's proportional withdrawal gives them:
- Token A out: shares_stale / total_supply * pool_a
- Token B out: shares_stale / total_supply * pool_b

Net profit (in token A equivalent):
  profit = x * excess_ratio (approximately)

For a pool with $10M TVL and 5% rate deviation:
  profit ≈ deposit_amount * 2.5%

The attack is repeatable and scales with deposit size (up to pool reserves).

### Rate Deviation Scenarios

1. **Normal appreciation** (~10% APY staking tokens):
   - Daily deviation: ~0.027%
   - Excess per tx: ~0.013%
   - Economically insignificant for single transactions
   - But: accumulates over many transactions over 24h window

2. **Oracle outage / delayed update**:
   - Deviation: 1-5%
   - Excess per tx: 0.5-2.5%
   - Significant for large deposits

3. **Depeg event / slash**:
   - Deviation: 5-50%+
   - Excess per tx: 2.5-25%+
   - Critical impact, large-scale extraction

4. **Rate expired (>24h since last update)**:
   - Swaps blocked (assert_rates_valid fails)
   - add_liquidity still works
   - remove_by_shares still works
   - Pool becomes one-directional: only deposits and proportional withdrawals
   - Worst scenario: attacker is the ONLY one who can enter/exit

### Affected Pools

All pools created via `add_rated_swap_pool` that include any token with
a registered rate provider (STNEAR, LINEAR, NEARX, SFRAX).

Rate expiry window: 24 hours for all rate types.

### Entry Points

1. `Contract::add_stable_liquidity()` (lib.rs:432) → `Pool::add_stable_liquidity()` → `RatedSwapPool::add_liquidity()`
2. `HotZap` via `ft_on_transfer()` (token_receiver.rs:208-217) → `pool.add_stable_liquidity()` → same path

Both entry points reach the vulnerable `calc_add_liquidity_with_rates` without rate validation.

### Verification Status

- [x] Source code analysis complete
- [x] Mathematical proof of excess shares
- [x] All four rate types confirmed to have same 24h expiry
- [x] Both entry points (direct + HotZap) confirmed vulnerable
- [x] Attack cycle (add + proportional remove) confirmed to bypass all rate checks
- [x] PoC test structure written (poc/test_stale_rate_exploit.rs)
- [ ] **BLOCKED**: Needs deployed wasm to test against deployed bytes
- [ ] **BLOCKED**: Needs RPC access to verify pool configurations and current rate states
- [ ] **BLOCKED**: Needs on-chain TVL data to estimate USD impact

### Suggested Fix

Add `self.assert_rates_valid()` at the start of `add_liquidity()` (mod.rs:271),
before calling `calc_add_liquidity_with_rates()`:

```rust
pub fn add_liquidity(...) -> Balance {
    let n_coins = self.token_account_ids.len();
    assert_eq!(amounts.len(), n_coins, "{}", ERR64_TOKENS_COUNT_ILLEGAL);
    
    self.assert_rates_valid();  // <-- ADD THIS LINE
    
    let (new_shares, fee_part) = self.calc_add_liquidity_with_rates(amounts, &self.get_rates(), fees);
    // ...
}
```

Or alternatively, move the `assert_rates_valid()` call in `calc_add_liquidity_with_rates`
outside the bootstrap-only branch:

```rust
fn calc_add_liquidity_with_rates(...) -> (Balance, Balance) {
    self.assert_rates_valid();  // <-- MOVE HERE (before the if/else)
    let invariant = self.get_invariant_with_rates(rates);
    let c_amounts = self.amounts_to_c_amounts(amounts);
    if self.shares_total_supply == 0 {
        // bootstrap case...
    } else {
        // subsequent case...
    }
}
```
