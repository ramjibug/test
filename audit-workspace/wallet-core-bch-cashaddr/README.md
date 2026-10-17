# BCH CashAddr Denial-of-Service — Evidence Package

## What is proven

| Layer | Status | Detail |
|---|---|---|
| Rust parser (`CashAddress::from_str_with_hrp`) | **PROVEN** | Process abort (exit 134) reproduced for payloads 0-8 decoded symbols |
| Rust API (`AnyAddress::is_valid`, `with_string`, `from_str_unchecked`) | **PROVEN** | All four entry points crash identically |
| Exported Rust C-ABI — BitcoinCash (`tw_any_address_is_valid`, `tw_any_address_create_with_string`, coin id 145) | **PROVEN** | Both functions crash for payloads 0-8 decoded symbols; exhaustive 0-12 coverage |
| Exported Rust C-ABI — eCash (`tw_any_address_is_valid`, `tw_any_address_create_with_string`, coin id 899) | **PROVEN** | Both functions crash for payloads 0-8 decoded symbols; exhaustive 0-12 coverage |
| Public C++ API — BitcoinCash (`TWAnyAddressIsValid`, `TWAnyAddressCreateWithString`) | **REFUTED** | Dispatches through separate C++ CashAddr parser (`cash_decode`), not the Rust parser |
| Public C++ API — eCash (`TWAnyAddressIsValid`, `TWAnyAddressCreateWithString`) | **REFUTED** | Dispatches through `ECashAddress::isValid` → C++ `cash_decode`; independently traced, does not reach Rust parser |
| Trust Wallet iOS/Android application | **UNVERIFIED** | No execution evidence; C++ API uses separate implementation for both BCH and eCash |
| Remote attacker delivery | **UNVERIFIED** | No demonstrated path to the Rust parser |
| Patch correctness | **PROVEN** | All 36 Rust API + 36 C-ABI previously-aborting cases + fuzz replay return normally after patch; all existing unit tests pass |

## Target

- Repository: `https://github.com/trustwallet/wallet-core/`
- Commit: `adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9` (master, 2026-10-14)
- File: `rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs` lines 116 and 126

## Reproduction

1. Clone wallet-core at the target commit:
   ```bash
   git clone https://github.com/trustwallet/wallet-core.git
   cd wallet-core
   git checkout adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9
   ```

2. Edit `evidence/poc/Cargo.toml` — replace `<WALLET_CORE>` with the absolute path to the checkout.

3. Build and run:
   ```bash
   cd evidence/poc
   cargo build --release
   ./target/release/bch_repro parser ""       # exit 134
   ./target/release/cabi_probe                # C-ABI table
   ```

4. To verify the patch:
   ```bash
   cd /path/to/wallet-core
   git apply /path/to/evidence/fix/unchecked.rs.patch
   # Rebuild the PoC against patched code, re-run — all inputs return exit 0
   ```

## File manifest

| Path | Contents |
|---|---|
| `REPORT.md` | Final submission report |
| `README.md` | This file |
| `evidence/poc/main.rs` | Rust API PoC binary (4 modes + fuzz replay) |
| `evidence/poc/cabi_probe.rs` | Exhaustive C-ABI probe: both coins (BCH id=145, eCash id=899), payloads 0-12, valid and prefixed controls; 60 test cases |
| `evidence/poc/Cargo.toml` | Build configuration (edit `<WALLET_CORE>` path) |
| `evidence/fix/unchecked.rs.patch` | Minimal patch fixing both panic sites |
| `evidence/fix/short_input.rs` | Regression test |
| `evidence/source/unchecked.rs` | Snapshot of vulnerable source at target commit |
| `evidence/source/tw_any_address_ffi.rs` | Snapshot of FFI layer (no catch_unwind) |
| `evidence/source/VERSION.txt` | Target commit hash |
| `evidence/fuzzing/anyaddress.rs` | Fuzz harness that discovered the bug |
| `evidence/fuzzing/anyaddress-fuzz-Cargo.toml` | Fuzz harness Cargo.toml |
| `evidence/fuzzing/crash-0b94ee47...` | 2-byte crash artifact (selects eCash, empty address) |
| `evidence/logs/00-environment.log` | Build environment capture |
| `evidence/logs/01-anyaddress-fuzz-crash.log` | Original fuzzer crash log |
| `evidence/logs/02-production-profile-reproducer.log` | Original production-profile crash log |
| `evidence/logs/04-crash-backtrace.txt` | Symbolized panic backtrace |
| `evidence/logs/05-matrix.log` | Unpatched full test matrix (raw) |
| `evidence/logs/05-matrix-table.md` | Unpatched full test matrix (table) |
| `evidence/logs/06-patched-matrix.log` | Patched full test matrix (raw) |
| `evidence/logs/06-patched-matrix-table.md` | Patched full test matrix (table) |
| `evidence/capi_probe_test.cpp` | Unexecuted C++ test template for the public C++ API (targets the `TWAnyAddressIsValid`/`TWAnyAddressCreateWithString` path, which was REFUTED by source analysis as not reaching the vulnerable Rust parser) |
| `evidence/logs/07-cabi-probe.log` | Unpatched exhaustive C-ABI probe results (both BCH and eCash, payloads 0-12) |
| `evidence/logs/08-cabi-probe-patched.log` | Patched exhaustive C-ABI probe results (all 60 cases return normally) |
| `scripts/run_matrix.sh` | Test matrix runner (requires binary path edit) |
| `scripts/capture_env.sh` | Environment capture script |
