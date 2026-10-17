// Place at: rust/chains/tw_bitcoincash/tests/short_input.rs
//
// Before the fix this panics (debug/test profile: "attempt to subtract with overflow" at
// unchecked.rs:116); after the fix every input below returns an error.

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
