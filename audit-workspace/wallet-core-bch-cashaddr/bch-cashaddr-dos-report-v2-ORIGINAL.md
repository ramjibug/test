> **DRAFT — before submitting:** replace every ⟨…⟩ using the logs in `evidence/logs/`, delete table rows you did not run, and delete this note. Every claim below is limited to what a listed log shows.

# Report body

## Platform fields (submission form, not body)

- **Title:** Process termination in Rust Bitcoin Cash CashAddr parsing due to missing payload-length validation
- **Affected asset:** `https://github.com/trustwallet/wallet-core/` — `rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs:116`
- **Version:** commit `adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9` (master, 2026-10-14). Earliest affected release: ⟨first tag containing the Rust `unchecked.rs`⟩
- **CWE:** CWE-191 (Integer Underflow)
- **Suggested severity:** Low — CVSS 3.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L` = 3.3, scored only on what is demonstrated (see Impact and severity)

---

## Summary

`UncheckedCashAddress::from_str` subtracts `CHECKSUM_LEN` (8) from the decoded payload length before checking that the payload has at least eight symbols. For an empty or 1–7-symbol payload the slice bound is invalid. In the tested release configuration — `panic = "abort"` with overflow checks off (the Cargo release default) — the subtraction wraps, the slice bounds check panics, and the process terminates with SIGABRT. The expected behavior is an invalid-address result.

The demonstrated impact is process termination only. No memory corruption, information disclosure or code execution was observed; the bounds check prevents out-of-bounds access.

**Entry points shown to reach the parser:** see *Reachability*.

**Product-level impact:** ⟨the in-scope consumer and attacker-controlled input path you demonstrated — or keep this sentence: "Product-level reachability (public C API, Trust Wallet apps) has not been established; this report covers the library-level defect."⟩

## Root cause

`rust/chains/tw_bitcoincash/src/cash_address/unchecked.rs`:

```rust
let payload_with_checksum =
    cash_base32::decode(&address_parts.payload).map_err(|_| AddressError::InvalidInput)?;

// Get the payload without the checksum.
let payload_u5 = &payload_with_checksum[..payload_with_checksum.len() - CHECKSUM_LEN]; // line 116
```

`cash_base32::decode` succeeds on an empty or short payload and returns one 5-bit symbol per input character (observed: slice length 0 for `""`, 1 for `"q"`, 7 for `"qqqqqqq"`), so nothing prevents `len() - CHECKSUM_LEN` from underflowing. Without overflow checks the result wraps to ≈ `usize::MAX`, and the following slice fails Rust's always-on bounds check.

⟨If the 8-symbol rows in `logs/05-matrix-table.md` also abort, add: "A payload of exactly 8 symbols passes the subtraction but leaves `payload_u5` empty; `payload_data[0]` (line 126) then panics with an index-out-of-bounds in every build profile, so the length check must require more than `CHECKSUM_LEN` symbols (see Remediation)." — and add CWE-129 to the CWE field.⟩

## Reproduction

Environment (commit, `rustc -Vv`, the `[profile.release]` block, host): `evidence/logs/00-environment.log`.

```
cd evidence/poc                      # set <WALLET_CORE> in Cargo.toml first
cargo build --release
./target/release/bch_repro parser ""
./target/release/bch_repro is_valid ""
./target/release/bch_repro with_string ""
./target/release/bch_repro with_string_unchecked ""
./target/release/bch_repro replay ../fuzzing/crash-0b94ee470ea1beccfb38b3709e5550b664db9c1e
../repro/run_matrix.sh               # every mode x payload length 0-12 + controls -> logs/05-matrix*
```

Observed in `parser` mode, release profile (`logs/02-production-profile-reproducer.log`):

| Input | Payload symbols | Result |
|---|---|---|
| `""` | 0 | panic at `unchecked.rs:116:48`: `range end index 18446744073709551608 out of range for slice of length 0`; exit 134 (SIGABRT) |
| `q` | 1 | `range end index 18446744073709551609 out of range for slice of length 1`; exit 134 |
| `qqqqqqq` | 7 | `range end index 18446744073709551615 out of range for slice of length 7`; exit 134 |
| `qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` (valid) | 42 | returns cleanly, `is_ok = true`; exit 0 |

All modes, payload lengths 0–12 and controls: ⟨paste `logs/05-matrix-table.md`⟩

## Reachability

| # | Layer | Call | Result | Evidence |
|---|---|---|---|---|
| 1 | Rust parser | `CashAddress::from_str_with_hrp("", "bitcoincash")`, release, `panic = "abort"` | abort, exit 134 | `logs/02` |
| 2 | Rust API | `AnyAddress::is_valid` (fuzz artifact; entry `tw_bitcoincash::BitcoinCashEntry`) | panic at `unchecked.rs:116` via `any_address.rs:26` (fuzz build, overflow checks on). Release-profile run with `CoinType::BitcoinCash`: ⟨`logs/05`⟩ | `logs/04`, ⟨`logs/05`⟩ |
| 3 | Rust API | `AnyAddress::with_string(CoinType::BitcoinCash, …)` | ⟨`logs/05`⟩ | ⟨`logs/05`⟩ |
| 4 | Rust API | `AnyAddress::with_string_unchecked(CoinType::BitcoinCash, …)` (behind `tw_any_address_create_with_string_unchecked`) | ⟨`logs/05`⟩ | ⟨`logs/05`⟩ |
| 5 | Exported Rust C-ABI | `tw_any_address_is_valid`, `tw_any_address_create_with_string`, `tw_any_address_create_with_string_unchecked` | The string is passed through with no length check and no panic containment (no `catch_unwind` in the file). Not executed. | `source/tw_any_address_ffi.rs` |
| 6 | Public C API | `TWAnyAddressIsValid`, `TWAnyAddressCreateWithString` with `TWCoinTypeBitcoinCash` | ⟨`logs/06-capi.log`: aborts / returns normally⟩ | `repro/capi_probe_test.cpp` |
| 7 | Application | ⟨Trust Wallet iOS/Android build, input path, interaction required⟩ | ⟨…⟩ | ⟨recording + device crash log⟩ |

Rows without a result were not tested and are not claimed.

## Impact and severity

**Demonstrated:** a standalone Rust binary built with `panic = "abort"` and overflow checks off terminates (SIGABRT) when the Bitcoin Cash parser receives a payload shorter than eight symbols (row 1) ⟨and through rows 2–4 and 6, as logged⟩.

**Not demonstrated, not claimed:** remote delivery, persistence across restarts, or any effect beyond terminating the process that calls the parser. ⟨If row 7 was demonstrated, replace this with the exact scenario and the interaction required.⟩

**Scoring:** `AV:L` because the demonstrated trigger is a local call; `UI:R` because a crafted string has to be processed by the victim's application; `A:L` because a single recoverable process termination is shown. If product-level reachability is demonstrated, the vector will be recalculated from the attack vector, interaction and persistence actually shown; no re-scoring is claimed here.

## Remediation

Suggested fix (applies cleanly to `unchecked.rs` at the commit above):

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

Regression test (`rust/chains/tw_bitcoincash/tests/short_input.rs`):

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

The `first()` change also covers an empty `payload_data` at line 126. Optional hardening: because the release profile aborts on panic, any reachable panic in the Rust parsers terminates the host process; containing panics at the FFI boundary (which needs an unwinding panic strategy) would turn this whole class into ordinary errors, in addition to fixing individual sites.

## Discovery (supporting)

Found by fuzzing the universal address parser with `cargo fuzz` (`evidence/fuzzing/anyaddress.rs`): the first two input bytes select a coin, `idx = u16::from_le_bytes([b0, b1]) as usize % CoinType::iter().count()`, and the rest is the address string. The saved artifact `59 32` plus an empty address gives `0x3259 = 12889`; `replay` mode prints the resulting index and coin: ⟨`coins.len()`, `idx`, `coin` from `logs/05-matrix.log`⟩. That mapping depends on the coin registry at this commit, so the explicit-coin runs above are the authoritative reproduction.
