# Process termination in Rust Bitcoin Cash CashAddr parsing due to missing payload-length validation

## Platform fields (submission form, not body)

- **Title:** Process termination in Rust Bitcoin Cash CashAddr parsing due to missing payload-length validation
- **Affected asset:** `https://github.com/trustwallet/wallet-core/` — `rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs:116` and `:126`
- **Version:** commit `adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9` (master, 2026-10-14). Earliest affected release: `4.6.7` (file introduced at `dfda5af9acd` on 2026-05-04)
- **CWE:** CWE-191 (Integer Underflow), CWE-129 (Improper Validation of Array Index)
- **Suggested severity:** Low — CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L` = 3.3, scored only on what is demonstrated (see Impact and severity)

---

## Summary

`UncheckedCashAddress::from_str` in the Bitcoin Cash CashAddr parser has two panic sites reachable from any CashAddr payload shorter than nine decoded symbols:

1. **Line 116:** Subtracts `CHECKSUM_LEN` (8) from the decoded payload length without a bounds check. For payloads of 0–7 symbols the subtraction wraps (overflow checks are off in the release profile), and the resulting slice operation panics at Rust's always-on bounds check.
2. **Line 126:** Indexes `payload_data[0]` without checking that `payload_data` is non-empty. For a payload of exactly 8 symbols the subtraction produces 0, `payload_u5` is empty, `convert_bits` returns an empty vector, and the index panics.

In the release configuration — `panic = "abort"` (explicitly configured in the wallet-core release profile) with overflow checks off (Cargo's default for release builds) — both panics terminate the process with SIGABRT (exit 134). The expected behavior is an `Err(AddressError::InvalidInput)` return.

**Demonstrated impact:** process termination only. No memory corruption, information disclosure, or code execution was observed; Rust's bounds check prevents out-of-bounds memory access.

**API reachability:** Crashes were reproduced by execution through:
- Four Rust API entry points: `CashAddress::from_str_with_hrp`, `AnyAddress::is_valid`, `AnyAddress::with_string`, and `CashAddress::from_str_unchecked`.
- Two exported Rust C-ABI functions: `tw_any_address_is_valid` and `tw_any_address_create_with_string`, called via their `extern "C"` interface with proper `TWString` creation.

**Public C++ API reachability (REFUTED):** Source-code tracing shows that the public C++ functions `TWAnyAddressIsValid` and `TWAnyAddressCreateWithString` for BitcoinCash dispatch through a **separate C++ CashAddr implementation** (`Bitcoin::Entry::validateAddress` → `BitcoinCashAddress::isValid` → `CashAddress::isValid` → `cash_decode`), not the vulnerable Rust parser. The Rust C-ABI functions are reached only via `RustCoinEntry`, which BitcoinCash does not use at this commit. See the Reachability section for the full trace.

## Root cause

`rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs` at the target commit:

```rust
// Line 112-116:
let payload_with_checksum =
    cash_base32::decode(&address_parts.payload).map_err(|_| AddressError::InvalidInput)?;

// Get the payload without the checksum.
let payload_u5 = &payload_with_checksum[..payload_with_checksum.len() - CHECKSUM_LEN]; // line 116

// Line 118-126:
let payload_data = {
    let from = 5;
    let to = 8;
    let pad = false;
    bech32::convert_bits(payload_u5, from, to, pad)
        .map_err(|_| AddressError::InvalidInput)?
};

let version_byte = payload_data[0]; // line 126
```

`cash_base32::decode` succeeds on short payloads and returns one 5-bit symbol per input character (e.g., length 0 for `""`, 1 for `"q"`, 7 for `"qqqqqqq"`, 8 for `"qqqqqqqq"`). Nothing prevents `len() - CHECKSUM_LEN` from underflowing.

**Site 1 (CWE-191):** Without overflow checks, the subtraction wraps to approximately `usize::MAX`, and the slice bounds check panics. Observed for payloads of 0–7 decoded symbols.

**Site 2 (CWE-129):** For exactly 8 decoded symbols, the subtraction produces 0, so `payload_u5` is `&[]`, `convert_bits` returns `vec![]`, and `payload_data[0]` panics on an empty slice. This site triggers in every build profile (debug and release alike) because it is a straightforward index-out-of-bounds.

The release profile at this commit:

```toml
[profile.release]
strip = true
codegen-units = 1
panic = "abort"
```

No explicit `overflow-checks` setting; Cargo's release default is `false`.

## Reproduction

**Environment:**
- Commit: `adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9`
- rustc: 1.97.0 (2d8144b78 2026-07-07)
- cargo: 1.97.0 (c980f4866 2026-06-30)
- Host: Linux 6.18.44-fc-v139 x86_64
- Full environment capture: `evidence/logs/00-environment.log`

**Build and run (Rust API PoC):**

```bash
cd evidence/poc
# Edit Cargo.toml: replace <WALLET_CORE> with the path to a wallet-core checkout at the target commit.
cargo build --release
./target/release/bch_repro parser ""          # exit 134
./target/release/bch_repro is_valid ""        # exit 134
./target/release/bch_repro with_string ""     # exit 134
./target/release/bch_repro with_string_unchecked ""  # exit 134
./target/release/bch_repro parser "qqqqqqqq"  # exit 134 (second panic site)
```

**Build and run (C-ABI probe):**

```bash
cd evidence/poc
cargo build --release --bin cabi_probe
./target/release/cabi_probe    # runs each input in a subprocess; reports exit codes
```

The `cabi_probe` binary calls the exported `extern "C"` functions `tw_any_address_is_valid` and `tw_any_address_create_with_string` with `TWString`-wrapped inputs, exactly as a C/C++ consumer would through the linker.

**Rust API matrix results (unpatched):**

| Input | Decoded symbols | Panic location | Exit | Panic message |
|---|---|---|---|---|
| `""` | 0 | `unchecked.rs:116` | 134 | `range end index 18446744073709551608 out of range for slice of length 0` |
| `"q"` | 1 | `unchecked.rs:116` | 134 | `range end index 18446744073709551609 out of range for slice of length 1` |
| `"qqqqqqq"` | 7 | `unchecked.rs:116` | 134 | `range end index 18446744073709551615 out of range for slice of length 7` |
| `"qqqqqqqq"` | 8 | `unchecked.rs:126` | 134 | `index out of bounds: the len is 0 but the index is 0` |
| `"qqqqqqqqq"` | 9 | — | 0 | returned normally (error) |
| valid addr | 42 | — | 0 | returned normally (`is_ok = true`) |

**Full test matrix:** All four Rust API modes (parser, is_valid, with_string, with_string_unchecked) were tested with decoded payload lengths 0 through 12, plus valid and prefixed controls. Complete results in `evidence/logs/05-matrix-table.md`.

**Matrix counts:**
- 61 total cases: 4 modes × 13 payload lengths (0-12) + 4 modes × 2 valid controls + 1 fuzz replay
- 36 aborting matrix cases: 4 modes × 9 short inputs (payloads 0-8)
- 1 aborting fuzz-artifact replay
- 24 normal-return cases: 4 modes × 4 longer payloads (9-12) + 4 modes × 2 valid controls

**C-ABI probe results (unpatched):**

| FFI function | Input | Decoded symbols | Exit | Result |
|---|---|---|---|---|
| `tw_any_address_is_valid` | `""` | 0 | 134 | **abort (SIGABRT)** |
| `tw_any_address_create_with_string` | `""` | 0 | 134 | **abort (SIGABRT)** |
| `tw_any_address_is_valid` | `"q"` | 1 | 134 | **abort (SIGABRT)** |
| `tw_any_address_create_with_string` | `"q"` | 1 | 134 | **abort (SIGABRT)** |
| `tw_any_address_is_valid` | `"qqqqqqq"` | 7 | 134 | **abort (SIGABRT)** |
| `tw_any_address_create_with_string` | `"qqqqqqq"` | 7 | 134 | **abort (SIGABRT)** |
| `tw_any_address_is_valid` | `"qqqqqqqq"` | 8 | 134 | **abort (SIGABRT)** |
| `tw_any_address_create_with_string` | `"qqqqqqqq"` | 8 | 134 | **abort (SIGABRT)** |
| `tw_any_address_is_valid` | `"qqqqqqqqq"` | 9 | 0 | returned normally |
| `tw_any_address_create_with_string` | `"qqqqqqqqq"` | 9 | 0 | returned normally |
| `tw_any_address_is_valid` | valid addr | 42 | 0 | returned normally |
| `tw_any_address_create_with_string` | valid addr | 42 | 0 | returned normally |

Full C-ABI log: `evidence/logs/07-cabi-probe.log`

**Fuzz artifact replay:** The 2-byte artifact `[0x59, 0x32]` selects coin index 121 (eCash) from 168 registered coins and supplies an empty address string. eCash routes through the same `BitcoinCashEntry`, confirming the vulnerability also affects eCash address parsing. See `evidence/logs/05-matrix.log`.

## Reachability

| # | Layer | Call | Status | Exit | Evidence |
|---|---|---|---|---|---|
| 1 | Rust parser | `CashAddress::from_str_with_hrp("", "bitcoincash")` | **PROVEN** — crash reproduced | 134 | `evidence/logs/05-matrix.log` |
| 2 | Rust API | `AnyAddress::is_valid(CoinType::BitcoinCash, "", None)` | **PROVEN** — crash reproduced | 134 | `evidence/logs/05-matrix.log` |
| 3 | Rust API | `AnyAddress::with_string(CoinType::BitcoinCash, "", None)` | **PROVEN** — crash reproduced | 134 | `evidence/logs/05-matrix.log` |
| 4 | Rust API (unchecked) | `CashAddress::from_str_unchecked("")` | **PROVEN** — crash reproduced | 134 | `evidence/logs/05-matrix.log` |
| 5 | Exported Rust C-ABI | `tw_any_address_is_valid(TWString(""), 145)` | **PROVEN** — crash reproduced | 134 | `evidence/logs/07-cabi-probe.log` |
| 6 | Exported Rust C-ABI | `tw_any_address_create_with_string(TWString(""), 145)` | **PROVEN** — crash reproduced | 134 | `evidence/logs/07-cabi-probe.log` |
| 7 | Public C++ API | `TWAnyAddressIsValid`, `TWAnyAddressCreateWithString` for BitcoinCash | **REFUTED** — separate C++ CashAddr implementation; does not reach Rust parser | — | Source trace below |
| 8 | Trust Wallet iOS/Android | Application-level address validation | **UNVERIFIED** — no execution evidence; C++ API path mitigates for BCH | — | — |
| 9 | Remote attacker delivery | Attacker-controlled input reaching the Rust parser | **UNVERIFIED** — no demonstrated delivery path | — | — |

### Public C++ API call-path trace (row 7)

The C++ public API for BitcoinCash dispatches through a **separate C++ CashAddr parser**, not the vulnerable Rust code. The complete call chain at the target commit:

```
TWAnyAddressIsValid(string, TWCoinTypeBitcoinCash)
  → TW::validateAddress(coin, address)              [src/Coin.cpp:221, wrapped in try/catch]
    → coinDispatcher(TWCoinTypeBitcoinCash)          [src/Coin.cpp:197 → BitcoinCashDP]
      → BitcoinCash::Entry::validateAddress(...)     [src/BitcoinCash/Entry.h:17 — inherits Bitcoin::Entry]
        → Bitcoin::Entry::validateAddress(...)        [src/Bitcoin/Entry.cpp:34-35]
          → BitcoinCashAddress::isValid(address)     [src/Bitcoin/CashAddress.h:61]
            → CashAddress::isValid(hrp, string)      [src/Bitcoin/CashAddress.cpp:52-62]
              → cash_decode(...)                      [C implementation, NOT Rust]
```

Key evidence:
- `BitcoinCash::Entry` inherits from `Bitcoin::Entry` (`src/BitcoinCash/Entry.h:17`), NOT from `Rust::RustCoinEntry`.
- `Bitcoin::Entry::validateAddress` calls `BitcoinCashAddress::isValid` for `TWCoinTypeBitcoinCash` (`src/Bitcoin/Entry.cpp:35`), which uses the C++ `cash_decode` function.
- `Rust::RustCoinEntry::validateAddress` (`src/rust/RustCoinEntry.cpp:17`) calls `Rust::tw_any_address_is_valid`, but BitcoinCash does not use this entry.
- A TODO comment in `src/BitcoinCash/Entry.h:16` reads: "TODO inherit Rust::RustCoinEntry directly when `Bitcoin.proto` is deprecated." This confirms the migration to Rust has not happened for BitcoinCash at this commit.

## Impact and severity

**Demonstrated:** A standalone Rust binary built with the wallet-core release profile (`panic = "abort"`, overflow checks off) terminates (SIGABRT, exit 134) when the Bitcoin Cash or eCash address parser receives a CashAddr payload shorter than nine decoded symbols. The crash is reproduced through four Rust API entry points (rows 1–4) and two exported Rust C-ABI functions (rows 5–6).

**Not demonstrated, not claimed:** Remote delivery, persistence across process restarts, memory corruption, information disclosure, code execution, or any effect beyond terminating the process that calls the parser. The public C++ API (`TWAnyAddressIsValid`, `TWAnyAddressCreateWithString`) for BitcoinCash uses a separate C++ CashAddr parser and does not reach the vulnerable Rust code (row 7, REFUTED). Application-level Trust Wallet reachability has not been established.

**Scoring:** `AV:L` because the demonstrated trigger is a local library call via the exported Rust C-ABI; `UI:R` because a crafted string must be processed by the victim's application; `A:L` because a single process termination is shown. The score applies to the Rust library and its exported C-ABI layer. The public C++ API for BitcoinCash is not affected at this commit.

**Note on eligibility:** Before submitting, verify that the bounty program accepts availability findings at this severity level and that `wallet-core` Rust code (specifically the exported C-ABI layer) is in scope.

## Remediation

Suggested fix (applies cleanly to `unchecked.rs` at the target commit):

```diff
--- a/rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs
+++ b/rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs
@@ -113,7 +113,12 @@
             cash_base32::decode(&address_parts.payload).map_err(|_| AddressError::InvalidInput)?;
 
         // Get the payload without the checksum.
-        let payload_u5 = &payload_with_checksum[..payload_with_checksum.len() - CHECKSUM_LEN];
+        // The decoded data must be at least `CHECKSUM_LEN` symbols long.
+        let payload_len = payload_with_checksum
+            .len()
+            .checked_sub(CHECKSUM_LEN)
+            .ok_or(AddressError::InvalidInput)?;
+        let payload_u5 = &payload_with_checksum[..payload_len];
 
         let payload_data = {
             let from = 5;
@@ -123,7 +128,7 @@
                 .map_err(|_| AddressError::InvalidInput)?
         };
 
-        let version_byte = payload_data[0];
+        let version_byte = *payload_data.first().ok_or(AddressError::InvalidInput)?;
         let ty = get_address_type(version_byte)?;
         let key_hash =
             H160::try_from(&payload_data[1..]).map_err(|_| AddressError::InvalidInput)?;
```

**Patch verification:** Applied to the target commit, rebuilt, and retested:
- All 36 previously-aborting Rust API matrix cases now return normally (exit 0).
- The fuzz-artifact replay also returns normally.
- Both C-ABI functions (`tw_any_address_is_valid`, `tw_any_address_create_with_string`) return normally for all previously-crashing inputs.
- All 3 existing `tw_bitcoincash` unit tests continue to pass.
- All valid addresses and longer payloads continue to parse correctly.
Full patched results in `evidence/logs/06-patched-matrix-table.md` and `evidence/logs/08-cabi-probe-patched.log`.

Regression test (`evidence/fix/short_input.rs`):

```rust
use tw_bitcoincash::cash_address::CashAddress;

#[test]
fn short_payloads_return_error_instead_of_panicking() {
    for input in ["", "q", "qqqqqqq", "qqqqqqqq", "bitcoincash:", "bitcoincash:q"] {
        assert!(
            CashAddress::from_str_with_hrp(input, "bitcoincash".to_string()).is_err(),
            "expected an error for input {input:?}"
        );
    }
}
```

**Optional hardening:** Because the release profile aborts on panic, any reachable panic in the Rust parsers terminates the host process. Containing panics at the FFI boundary (e.g., wrapping exported `extern "C"` functions in `catch_unwind`, which requires an unwinding panic strategy for the library) would turn this entire class of defect into ordinary error returns.

## Discovery

Found by fuzzing the universal address parser with `cargo fuzz` (`evidence/fuzzing/anyaddress.rs`): the first two bytes of the fuzz input select a coin via `u16::from_le_bytes([b0, b1]) as usize % CoinType::iter().count()`, and the rest is the address string. The saved artifact `[0x59, 0x32]` (2 bytes, empty address) selects coin index 121 from 168 coins, which is `eCash` at this commit. eCash routes through `BitcoinCashEntry`, reaching the same vulnerable parser. The explicit-coin runs in this report (using `CoinType::BitcoinCash` directly) are the authoritative reproduction, independent of the coin-registry order.

## Additional notes

- **Other affected coins:** eCash uses the same `BitcoinCashEntry` and is confirmed reachable via the fuzz artifact replay.
- **`checksum.rs` is not affected:** An earlier analysis suggested `checksum.rs:30` had a similar underflow; this was incorrect — `calc_and_append_checksum` appends 8 phantom checksum bytes before the subtraction, so it cannot underflow.
- **Signing path:** The Bitcoin Cash signer (`BitcoinSigner`) receives pre-parsed UTXO data, not raw address strings from user input. No evidence was found that the signing path reaches the vulnerable parser from attacker-controlled input.
- **Public C++ API — separate implementation:** The C++ functions `TWAnyAddressIsValid` and `TWAnyAddressCreateWithString` for BitcoinCash dispatch through `Bitcoin::Entry::validateAddress`, which uses a C++ CashAddr parser (`cash_decode`) entirely separate from the Rust `UncheckedCashAddress::from_str`. The vulnerable Rust code is reached only through `Rust::RustCoinEntry::validateAddress`, which BitcoinCash does not use. A source-level TODO (`src/BitcoinCash/Entry.h:16`) notes that migration to `RustCoinEntry` is planned but incomplete. **If and when this migration occurs, the vulnerable Rust parser would become reachable from the public C++ API**, making this fix important regardless of current C++ API reachability.
- **No catch_unwind in codebase:** Zero occurrences of `catch_unwind` were found in the entire wallet-core Rust codebase. Any panic in any Rust parser reachable from the C-ABI will terminate the host process under the `panic = "abort"` profile. The C++ `try/catch` in `TW::validateAddress` (Coin.cpp:225) cannot catch a Rust abort.
- **Future risk:** Coins currently using `RustCoinEntry` (Solana, Cosmos, Ethereum, Polkadot, Binance, and others) already route their `validateAddress` calls through the Rust C-ABI. If any of those coins' address parsers contain similar unchecked arithmetic, they would be similarly vulnerable. The `checked_sub` / `.first()` pattern in the suggested fix should be adopted as a codebase convention.
