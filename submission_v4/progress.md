# Rhea Finance Audit - Progress Log

## Status: Source analysis COMPLETE — BLOCKED on network access for verification

### Completed Work

#### Source Code Analysis (COMPLETE)
All ref-exchange source modules read and analyzed:
- `lib.rs` — Main contract, execute_actions, swap chains, virtual accounts
- `pool.rs` — Pool enum dispatch (Simple, StableSwap, RatedSwap, Degen)
- `simple_pool.rs` — Constant-product AMM (xy=k)
- `stable_swap/mod.rs` — StableSwapPool implementation
- `stable_swap/math.rs` — StableSwap invariant math (U256)
- `rated_swap/mod.rs` — RatedSwapPool implementation (**PRIMARY FINDING**)
- `rated_swap/math.rs` — RatedSwap invariant math (U384)
- `rated_swap/rate.rs` — Global rate cache, rate providers
- `rated_swap/stnear_rate.rs` — StnearRate with 24h expiry
- `token_receiver.rs` — ft_on_transfer, HotZap flow
- `account_deposit.rs` — Account management, shadow records
- `multi_fungible_token.rs` — MFT protocol, mft_resolve_transfer
- `shadow_actions.rs` — Farming/burrow shadow integration
- `storage_impl.rs` — Storage management
- `action.rs` — SwapAction, AddLiquidityAction types
- `owner.rs` — Admin functions, guardians
- `admin_fee.rs` — Admin fee configuration
- `oracle.rs` — Price oracle integration
- `views.rs` — View functions
- `errors.rs` — Error codes
- `utils.rs` — FEE_DIVISOR, integer_sqrt, U256/U384
- `client_echo_limit.rs` — Client echo whitelist
- `donation.rs` — Donation pool
- `degen_swap/mod.rs` — EXCLUDED per DEGEN-1 CLOSED rule

#### Vulnerability Candidates (WRITTEN)
`submission_v4/candidates.md` contains:
- **CANDIDATE 1 (Medium/High)**: RatedSwapPool missing `assert_rates_valid()` on `add_liquidity` for non-bootstrap deposits. Mathematical analysis shows ~2.5% excess shares per 5% rate deviation. Full attack cycle: add_liquidity(stale) → remove_by_shares(proportional) = value extraction.
- **CANDIDATE 2 (Low)**: Shadow record inconsistency on liquidation callback failure
- **CANDIDATE 3 (Very Low)**: SimplePool admin fee rounding
- **CANDIDATE 4 (N/A)**: First-depositor ruled out on NEAR
- 7 hypotheses evaluated and ruled out with reasons

#### Hypotheses Ruled Out
- HotZap token_cache accounting → correct after mutation
- SwapByOutput backward chain → finalize_prev_swap_chain prevents abuse
- Virtual account leak → ephemeral, cleared after actions
- StableSwap Newton convergence → 256 iterations, checked_div
- mft_resolve_transfer double refund → min(unused, balance)
- storage_unregister with tokens → asserts emptiness
- DEGEN-1 price freshness → EXCLUDED per rules

### Phase 1: Delta Analysis — BLOCKED
- **BLOCKER**: `rpc.mainnet.near.org` blocked by egress proxy (403 Forbidden)
- Cannot fetch deployed wasm for v2.ref-finance.near or boostfarm.ref-labs.near
- Cannot make read-only view calls for on-chain parameters
- boost-farm repo (ref-finance/boost-farm) is private, clone failed

### What REQUIRES RPC access to proceed:
1. Fetch deployed wasm (CRITICAL — all confirmation gates require deployed bytes)
2. Verify code_hash matches expected `25eNFdfK76NUEZn4cDgq1xQYKjxKCuzgXmPB3SHBRW4Y`
3. View calls for on-chain parameters (reserves, fees, pool configs, rate values)
4. Delta analysis between deployed and source wasm
5. Sandbox testing of CANDIDATE 1 against deployed bytes

### Action needed from user:
Add `rpc.mainnet.near.org` to the environment's allowed domains list.
Settings path: Cloud environment menu → Edit → Network access → Allowed domains.
