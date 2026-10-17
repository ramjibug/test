# Bitcoin Cash CashAddr short-payload abort (wallet-core) — working notes, v2

One line: a Bitcoin Cash CashAddr payload of 0–7 symbols underflows `len() - CHECKSUM_LEN` at
`tw_bitcoincash/src/cash_address/unchecked.rs:116`; with `panic = "abort"` and overflow checks off the
process aborts (SIGABRT, exit 134). Availability only; no memory corruption. Product-level reachability
is NOT yet established — the report says so until rows 2–7 of its Reachability table are filled.

## Layout
- `bch-cashaddr-dos-report.md` — report body (draft; every ⟨…⟩ needs a result or must be deleted)
- `evidence/poc/` — PoC v2: modes `parser`, `is_valid`, `with_string`, `with_string_unchecked`, `replay` (explicit coin = BitcoinCash)
- `evidence/repro/` — `capture_env.sh`, `run_matrix.sh`, `capi_probe_test.cpp` (public C API check)
- `evidence/fix/` — `unchecked.rs.patch` (applies cleanly to the file at the commit in VERSION.txt), `short_input.rs` (regression test)
- `evidence/fuzzing/` — fuzz harness + 2-byte artifact
- `evidence/logs/` — 01, 02, 04 (local paths scrubbed, nothing else changed); 00, 05, 06 are yours to generate
- `evidence/source/` — verbatim excerpts at the commit in VERSION.txt

## Run order (needs a wallet-core checkout at the commit in `evidence/source/VERSION.txt`)
1. `evidence/repro/capture_env.sh <wallet-core> > evidence/logs/00-environment.log`
2. Set `<WALLET_CORE>` in `evidence/poc/Cargo.toml`. The Rust here is uncompiled: if a name does not resolve
   (e.g. the `CoinType::BitcoinCash` variant, `AnyAddress::with_string_unchecked`), fix it to match the commit.
3. `evidence/repro/run_matrix.sh` → `logs/05-matrix.log`, `logs/05-matrix-table.md`. Look at:
   - the 8-symbol rows (a second panic at `unchecked.rs:126` `payload_data[0]` is likely but unverified),
   - the `with_string_unchecked` rows (likely the path behind `TWAnyAddressCreateWithString` — check `src/interface/TWAnyAddress.cpp`),
   - the `replay` line (`coins.len()`, `idx`, `coin`).
4. Public C API: add `evidence/repro/capi_probe_test.cpp` to wallet-core `tests/`, build Release, run the loop in its header, save output as `logs/06-capi.log`.
5. Apply `evidence/fix/unchecked.rs.patch` + `short_input.rs`: the test must pass with the patch and fail without; re-run the fuzzer with the patch applied.
6. Optional, highest value: reproduce in the Trust Wallet app on your own device (screen recording + device crash log).
7. Fill the ⟨…⟩ in the report; delete rows you did not run.

## Before submitting
- Live brief: scope, automated-testing rule, DoS carve-out, AI-assistance disclosure if required.
- Earliest affected release (`git log --diff-filter=A --follow -- rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs`, then `git tag --contains <sha>`) and whether the shipping apps include it.
- Other coins routed to the Bitcoin Cash entry (e.g. eCash).
- Leads, unverified: call sites of `partly_checked` (no checksum check when the address has no prefix).
- Existing logs 01/02 have blank `BUILD_EXIT=` / `RUN_EXIT=` captures; the 05 logs replace them.

## Changes from v1
- Dropped the `checksum.rs:30` claim: the 8 phantom checksum bytes are appended first, so it cannot underflow (and the function is `calc_and_append_checksum`).
- Dropped the Solana targets and negative log from the bundle (still in your own copy).
- Release-profile wording: `panic = "abort"` comes from wallet-core's profile; overflow checks off is Cargo's release default.
- CWE reduced to CWE-191 (add CWE-129 only if the 8-symbol site is confirmed).
- No public-C-API or app claims until tested; the Reachability table separates tested from untested.
- Added: explicit-coin PoC, artifact replay, length matrix, second-site fix, regression test.
