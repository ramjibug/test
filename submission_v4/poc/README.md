# CANDIDATE 1 PoC: RatedSwapPool Stale Rate add_liquidity

## Status: BLOCKED on deployed wasm

This test proves that `RatedSwapPool::add_liquidity` accepts stale rates,
allowing an attacker to receive excess LP shares compared to fair value.

## Prerequisites

1. Deployed wasm for `v2.ref-finance.near` (fetch via NEAR RPC)
2. Place at `poc/wasm/ref_exchange.wasm`
3. Source-built wasm for `test-rated-token` and `test-token`
4. `near-workspaces` crate

## How to run

```bash
cd /root/RHEA_HACKENPROOF_HUNT/submission_v4/poc
cargo test -- --nocapture
```

## What it proves

1. After bootstrap: swap FAILS with stale rate (assert_rates_valid blocks it)
2. After bootstrap: add_liquidity SUCCEEDS with stale rate (no rate check)
3. Shares received with stale rate > shares that would be received with fresh rate
4. Attacker can extract value via add_stale → remove_proportional cycle

## Negative control

With fresh rates, shares match expected fair value (no excess).
