# On-Chain Verification Plan for CANDIDATE 1

## Status: BLOCKED on RPC access (rpc.mainnet.near.org)

## Step 1: Verify Deployed Code Matches Source

```bash
# Fetch deployed wasm
near-cli-rs contract download-wasm v2.ref-finance.near --output deployed.wasm

# Expected code_hash: 25eNFdfK76NUEZn4cDgq1xQYKjxKCuzgXmPB3SHBRW4Y
# Verify with: sha256 of wasm, base58-encoded
```

## Step 2: Check Current Rate States

```bash
# View call: list all rated token info
near-cli-rs contract call-function \
  --account-id v2.ref-finance.near \
  --function-name list_rated_tokens \
  --args '{}' \
  --network mainnet

# Returns: { token_id: { rate_type, rate_price, last_update_ts, is_valid, extra_info } }
# Look for: is_valid = false (expired rates)
# Look for: last_update_ts older than 24 hours
```

## Step 3: Enumerate Rated Pools

```bash
# Get pool count
near-cli-rs contract call-function \
  --account-id v2.ref-finance.near \
  --function-name get_number_of_pools \
  --args '{}' \
  --network mainnet

# List pools and find RatedSwap types
# get_pools returns PoolInfo which includes pool_kind
near-cli-rs contract call-function \
  --account-id v2.ref-finance.near \
  --function-name get_pools \
  --args '{"from_index": 0, "limit": 100}' \
  --network mainnet
```

## Step 4: Prove Share Differential with View Calls

For each rated pool found in Step 3:

```bash
# Get pool info (current reserves, shares supply)
near-cli-rs contract call-function \
  --account-id v2.ref-finance.near \
  --function-name get_pool \
  --args '{"pool_id": <POOL_ID>}' \
  --network mainnet

# Get current cached rates
# (from list_rated_tokens output above)

# Get true rates from external contracts
# For stNEAR: call meta-pool.near -> get_st_near_price()
# For LiNEAR: call linear-protocol.near -> ft_price()
# For NEARX: call v2-nearx.stader-labs.near -> get_nearx_price()
# For SFRAX: requires Pyth oracle or price oracle

# Predict shares with CACHED rate (what attacker would get)
near-cli-rs contract call-function \
  --account-id v2.ref-finance.near \
  --function-name predict_add_rated_liquidity \
  --args '{"pool_id": <POOL_ID>, "amounts": [<DEPOSIT>, "0"]}' \
  --network mainnet

# Predict shares with TRUE rate (what fair value would be)
near-cli-rs contract call-function \
  --account-id v2.ref-finance.near \
  --function-name predict_add_rated_liquidity \
  --args '{"pool_id": <POOL_ID>, "amounts": [<DEPOSIT>, "0"], "rates": [<TRUE_RATE_A>, <TRUE_RATE_B>]}' \
  --network mainnet

# Compare: shares_cached > shares_true proves the vulnerability
```

## Step 5: Sandbox Test with Deployed Wasm

```rust
// Using near-workspaces
let worker = near_workspaces::sandbox().await?;

// Deploy the DEPLOYED wasm (not source-built)
let contract = worker.dev_deploy(&deployed_wasm_bytes).await?;

// Initialize pool
// ... (see poc/test_stale_rate_exploit.rs for structure)

// Use worker.fast_forward() to advance time past 24h expiry
worker.fast_forward(86400 / 1).await?; // advance ~24h worth of blocks

// Verify swap fails (assert_rates_valid blocks it)
// Verify add_liquidity succeeds (no rate check)
// Compare shares to prove excess
```

## Step 6: Estimate USD Impact

Using on-chain data from Steps 2-3:
- Pool TVL from reserves + current token prices
- Rate deviation = (true_rate - cached_rate) / cached_rate
- Excess ratio ≈ deviation / 2 (for balanced pool)
- Max extractable = TVL * excess_ratio * (attacker_deposit / pool_size)

## Required RPC Endpoints

All are READ-ONLY view calls:
1. `rpc.mainnet.near.org` (primary, BLOCKED)
2. Alternative: `near-mainnet.api.pagoda.co` (may also be blocked)
3. Alternative: `archival-rpc.mainnet.near.org`

## User Action Required

Add `rpc.mainnet.near.org` to the environment's allowed domains.
Path: Cloud environment menu → Edit → Network access → Allowed domains.
