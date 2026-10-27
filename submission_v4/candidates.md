# Rhea Finance Audit - Vulnerability Candidates

## Source: ref-exchange (v2.ref-finance.near)
## Repo: DevOfCredit/ref-contracts at b444323 (ref-exchange/src/)
## Date: 2026-10-27
## Status: Source-only analysis (deployed wasm NOT yet verified)

---

## CANDIDATE 1 — RatedSwapPool: Missing Rate Validity Check on add_liquidity

**Severity estimate**: Medium (potentially High under extreme rate deviation)
**Confidence**: Medium-high (math verified from source, needs deployed wasm confirmation)
**Exploitable by unprivileged attacker**: Yes

### Description

`RatedSwapPool::add_liquidity` (rated_swap/mod.rs:271) does NOT call
`assert_rates_valid()` for subsequent (non-bootstrap) deposits. In contrast,
every other rate-dependent operation enforces freshness:

| Operation                   | File:Line                     | Checks rates? |
|-----------------------------|-------------------------------|---------------|
| swap (via internal_get_return) | rated_swap/mod.rs:515       | YES           |
| remove_liquidity_by_tokens  | rated_swap/mod.rs:432         | YES           |
| add_liquidity (bootstrap)   | rated_swap/mod.rs:224         | YES           |
| **add_liquidity (subsequent)** | **rated_swap/mod.rs:283**  | **NO**        |
| **remove_liquidity_by_shares** | **rated_swap/mod.rs:336**  | **NO** (N/A — proportional) |

The `add_liquidity` path calls `calc_add_liquidity_with_rates(amounts,
&self.get_rates(), fees)` at line 283, which fetches the cached rates from
the global static `RATES` and uses them in the invariant computation — but
never validates whether those rates are still fresh (i.e., `are_actual()`).

Rate expiry window: **24 hours** (stnear_rate.rs:10 `EXPIRE_TS = 24 * 3600 * 10^9`).

### Root Cause

`calc_add_liquidity_with_rates` (rated_swap/mod.rs:210) only calls
`self.assert_rates_valid()` for the bootstrap case (`shares_total_supply == 0`,
line 224). For subsequent adds (the else branch at line 236), no rate
validation occurs.

### Attack Scenario

Concrete example (high-A approximation for clarity):

1. Pool contains [1000 USDT, 1000 stNEAR], stNEAR rate stale at 1.0,
   actual market rate = 1.05 (5% appreciation since last oracle update).
   Total LP shares = S.

2. **Swaps are blocked** — `assert_rates_valid()` fails on the stale rate.

3. Attacker deposits 100 USDT via `add_liquidity` — succeeds because
   add_liquidity does NOT check rate validity.

4. With stale rate (1.0): D_0 = D([1000, 1000]) ≈ 2000.
   After deposit: D_1 = D([1100, 1000]) ≈ 2100.
   shares_stale ≈ S × 100/2000 = **5.0%** of S.

5. With correct rate (1.05): D_0 = D([1000, 1050]) ≈ 2050.
   After deposit: D_1 = D([1100, 1050]) ≈ 2150.
   shares_correct ≈ S × 100/2050 = **4.878%** of S.

6. Attacker got ~2.5% more shares than fair value.

7. Attacker calls `remove_liquidity_by_shares` (also has no rate check) to
   withdraw proportionally:
   - Gets back USDT + stNEAR proportional to their excess shares.
   - Net profit ≈ 2.38% of deposit for a 5% rate deviation.

8. Alternatively, attacker waits for oracle to update (rate refreshes),
   then can swap or remove_by_tokens at correct rates.

### Estimated Impact

- Profit = f(rate_deviation, deposit_size, pool_size)
- For liquid staking tokens (stNEAR, LiNEAR) that only appreciate, the
  stale rate always UNDERVALUES the token vs. reality. This means depositing
  the NON-rated token (e.g., USDT/USDC) at stale rates yields excess shares.
- Extreme scenario: during a rapid rate change (depeg event, slash) or
  prolonged oracle outage (>24h), deviation could be 5-20%+, yielding
  significant extraction from LPs.
- Under normal conditions (24h natural appreciation ~0.027%/day for ~10%
  APY staking tokens), the profit per transaction is tiny (~0.013%).
- Under stress conditions (depegs, exploits of rate providers), impact
  could be significant.
- Pool size on NEAR mainnet is unknown without RPC access.

### Verification Steps (BLOCKED — need deployed wasm)

1. Fetch deployed wasm for v2.ref-finance.near
2. Verify code_hash matches expected
3. Build sandbox test:
   a. Deploy deployed wasm to sandbox
   b. Create a RatedSwapPool with a rated token
   c. Set rate, let it go stale (advance block_timestamp by >24h)
   d. Verify swap fails (assert_rates_valid blocks it)
   e. Verify add_liquidity succeeds with stale rate
   f. Compare shares received vs. fair-rate shares
   g. Remove_by_shares and measure net extraction
4. Negative control: verify that with fresh rate, no excess shares

### Additional Findings (Deepened Analysis)

- **All four rate types affected**: STNEAR, LINEAR, NEARX, SFRAX all have
  identical 24h expiry windows (`EXPIRE_TS = 24 * 3600 * 10^9` ns).
- **HotZap entry point also vulnerable**: `ft_on_transfer` HotZap flow at
  `token_receiver.rs:208-217` routes to `pool.add_stable_liquidity()` →
  `RatedSwapPool::add_liquidity()` — same vulnerable path, no rate check.
- **`update_token_rate` is callable by anyone** (`lib.rs:563`), so the
  attacker controls timing: they can choose NOT to update the rate.
- **Proportional withdrawal uses no rates at all**: `remove_liquidity_by_shares`
  simply divides `c_amounts[i] * shares / shares_total_supply` — no rate
  dependency, no rate check. The exit path is always open.
- **View function `predict_add_rated_liquidity` accepts custom rates** 
  (`mod.rs:249`), enabling on-chain proof of share differential without
  actually depositing.

### Code References

- `rated_swap/mod.rs:271-299` — add_liquidity (no rate check)
- `rated_swap/mod.rs:210-247` — calc_add_liquidity_with_rates (only checks bootstrap)
- `rated_swap/mod.rs:107-110` — assert_rates_valid
- `rated_swap/mod.rs:515` — internal_get_return (checks rates)
- `rated_swap/mod.rs:432` — remove_liquidity_by_tokens (checks rates)
- `rated_swap/rate.rs:214-232` — is_global_rate_valid
- `rated_swap/stnear_rate.rs:10` — EXPIRE_TS = 24h
- `token_receiver.rs:208-217` — HotZap add_stable_liquidity path
- `lib.rs:563` — update_token_rate (anyone callable)

---

## CANDIDATE 2 — Shadow Record Inconsistency on Liquidation Callback Failure

**Severity estimate**: Low
**Confidence**: Low (cross-contract edge case, requires specific conditions)
**Exploitable by unprivileged attacker**: No (requires admin/burrowland coordination)

### Description

In `shadow_actions.rs`, the `on_burrow_liquidation` function (callable only
by `burrowland_id`) decreases the liquidated user's `shadow_in_farm` record
and makes a cross-contract call to boost_farm to remove the farming shadow.
If this callback fails, `callback_on_burrow_liquidation` only logs the
failure — it does NOT revert the `shadow_in_farm` decrease.

### Root Cause

`callback_on_burrow_liquidation` (shadow_actions.rs, ~line 270+):
On cross-contract failure, only `env::log("...")` is called. The shadow
record was already updated before the cross-contract call.

### Attack Scenario

Not directly exploitable by unprivileged attacker. Requires:
1. Burrowland initiates a liquidation of a user who has farming shadow
2. The `on_remove_shadow` call to boost_farm fails (gas, contract state, etc.)
3. Result: ref-exchange thinks the user has less farming shadow than
   boost_farm does
4. The user could potentially claim farming rewards on shares that
   ref-exchange no longer tracks

### Estimated Impact

Low. The shadow record discrepancy is a bookkeeping issue between two
admin-controlled contracts. It cannot be triggered by an unprivileged user,
and the damage is bounded by the liquidated position size.

### Verification Steps

Would require both ref-exchange AND boost-farm wasm for sandbox testing,
plus a mock burrowland contract. boost-farm repo is private (clone failed).

---

## CANDIDATE 3 — SimplePool Admin Fee LP Share Rounding Accumulation

**Severity estimate**: Very Low (informational)
**Confidence**: Medium
**Exploitable by unprivileged attacker**: Negligible profit

### Description

In `simple_pool.rs`, the `update_pool_and_distribute_fee` function computes
admin fee shares as:

```
new_invariant = integer_sqrt(new_amounts[0] * new_amounts[1])
admin_shares = (new_invariant - prev_invariant) * shares_total
              / (prev_invariant * FEE_DIVISOR / admin_fee_bps)
```

This uses integer division throughout. Over many small swaps, the cumulative
rounding loss benefits non-admin LPs at the expense of admin fee collection.
The per-swap rounding error is at most 1 unit of the share denomination.

### Impact

At the scale of ref-finance pools (~10^24 unit shares), 1 unit of rounding
per swap is 10^-24 NEAR equivalent — completely negligible.

---

## CANDIDATE 4 — First-Depositor Share Inflation (StableSwap/RatedSwap)

**Severity estimate**: Not Applicable on NEAR
**Confidence**: High (ruled out by NEAR architecture)

### Description

The Ethereum-style "first depositor" or "inflation attack" on vault-like
contracts does not apply to NEAR/NEP-141 because:
1. NEP-141 tokens cannot be directly transferred to a contract's storage
   without going through `ft_transfer_call`/`ft_on_transfer`.
2. The pool's internal `c_amounts` only increase via `add_liquidity`, not
   via direct token receipt.
3. There is no equivalent of Ethereum's `SELFDESTRUCT` or raw ETH transfer
   that bypasses the contract's accounting.

### Conclusion

Ruled out. Not a valid vulnerability on NEAR.

---

## CANDIDATES EVALUATED AND RULED OUT

| Hypothesis | Module | Reason Ruled Out |
|------------|--------|------------------|
| HotZap token_cache accounting mismatch | token_receiver.rs | SimplePool mutates amounts, but mutated amounts = actual consumption; subtraction from token_cache is correct |
| SwapByOutput backward chain double-spend | lib.rs | finalize_prev_swap_chain correctly withdraws from account; action chain validation prevents abuse |
| execute_actions_in_va virtual account leak | lib.rs | Virtual account is ephemeral; cleared after actions; panics on insufficient balance |
| StableSwap Newton's method convergence | stable_swap/math.rs | 256 iterations with ±1 convergence; checked_div returns None on division by zero |
| mft_resolve_transfer double refund | multi_fungible_token.rs | Refund amount = min(unused, receiver_balance); cannot exceed what receiver holds |
| storage_unregister with non-empty tokens | storage_impl.rs | Explicitly asserts tokens.is_empty() AND legacy_tokens.is_empty() AND shadow_records.is_empty() |
| DEGEN-1 price freshness | degen_swap/ | EXCLUDED per user rules (DEGEN-1 is CLOSED) |

---

## NEXT STEPS (ALL BLOCKED ON NETWORK ACCESS)

1. **Fetch deployed wasm** for v2.ref-finance.near — verify code_hash
2. **Build sandbox harness** with near-workspaces and deployed wasm
3. **Test CANDIDATE 1** with concrete rate parameters against deployed bytes
4. **Fetch boost-farm wasm** for boostfarm.ref-labs.near (if accessible)
5. **On-chain parameter verification**: pool configurations, fee levels,
   actual rate values for stNEAR/LiNEAR/NEARX/SFRAX pools

### Blocker

`rpc.mainnet.near.org` is denied by the cloud environment's egress proxy.
User action needed: add `rpc.mainnet.near.org` to environment's allowed
domains (Cloud environment menu → Edit → Network access → Allowed domains).
