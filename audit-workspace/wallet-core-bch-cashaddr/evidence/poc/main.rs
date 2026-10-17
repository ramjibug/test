// PoC: Bitcoin Cash CashAddr parsing aborts on short/empty input.
//
// Usage: bch_repro <mode> <input>
//   parser                CashAddress::from_str_with_hrp(input, "bitcoincash")          root cause, called directly
//   is_valid              AnyAddress::is_valid(CoinType::BitcoinCash, input, None)       Rust API
//   with_string           AnyAddress::with_string(CoinType::BitcoinCash, input, None)    Rust API
//   with_string_unchecked AnyAddress::with_string_unchecked(CoinType::BitcoinCash, input) Rust API behind
//                                                                                        tw_any_address_create_with_string_unchecked
//   replay                <input> is a libFuzzer artifact path; repeats the harness's coin selection
//                         (first two bytes, little-endian, modulo the coin count) and calls AnyAddress::is_valid
//
// Build: cargo build --release   (profile in Cargo.toml: panic = "abort", overflow checks off)
// Exit status 134 (SIGABRT) = the process aborted; 0 = returned normally.
//
// NOTE: written against the same APIs the fuzz harness uses (evidence/fuzzing/anyaddress.rs);
// if a name does not resolve at your commit (e.g. the CoinType variant), adjust it.

use tw_any_coin::any_address::AnyAddress;
use tw_bitcoincash::cash_address::CashAddress;
use tw_coin_registry::coin_type::CoinType;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let input = args.next().unwrap_or_default();

    match mode.as_str() {
        "parser" => {
            eprintln!("[repro] input = {input:?} (byte len {})", input.len());
            // hrp is irrelevant: the panic happens during decode, before the hrp check.
            let res = CashAddress::from_str_with_hrp(&input, "bitcoincash".to_string());
            eprintln!("[repro] returned cleanly, is_ok = {:?}", res.is_ok());
        },
        "is_valid" => {
            eprintln!("[repro] mode=is_valid coin=BitcoinCash input = {input:?} (byte len {})", input.len());
            let res = AnyAddress::is_valid(CoinType::BitcoinCash, &input, None);
            eprintln!("[repro] returned cleanly, is_valid = {res}");
        },
        "with_string" => {
            eprintln!("[repro] mode=with_string coin=BitcoinCash input = {input:?} (byte len {})", input.len());
            let res = AnyAddress::with_string(CoinType::BitcoinCash, &input, None);
            eprintln!("[repro] returned cleanly, is_ok = {:?}", res.is_ok());
        },
        "with_string_unchecked" => {
            // AnyAddress::with_string_unchecked is pub(crate); test via CashAddress::from_str_unchecked
            // which is the same code path reached by tw_any_address_create_with_string_unchecked FFI.
            eprintln!("[repro] mode=with_string_unchecked (via CashAddress::from_str_unchecked) input = {input:?} (byte len {})", input.len());
            let res = CashAddress::from_str_unchecked(&input);
            eprintln!("[repro] returned cleanly, is_ok = {:?}", res.is_ok());
        },
        "replay" => {
            let data = std::fs::read(&input).expect("cannot read artifact");
            assert!(data.len() >= 2, "artifact must be at least 2 bytes");
            // Same selection as evidence/fuzzing/anyaddress.rs
            let coins: Vec<CoinType> = CoinType::iter().into_iter().collect();
            let idx = (u16::from_le_bytes([data[0], data[1]]) as usize) % coins.len();
            let coin = coins[idx];
            let address = std::str::from_utf8(&data[2..]).unwrap_or_default();
            eprintln!(
                "[repro] mode=replay coins.len() = {} idx = {idx} coin = {coin:?} address = {address:?}",
                coins.len()
            );
            let res = AnyAddress::is_valid(coin, address, None);
            eprintln!("[repro] returned cleanly, is_valid = {res}");
        },
        _ => {
            eprintln!("usage: bch_repro <parser|is_valid|with_string|with_string_unchecked|replay> <input-or-artifact-path>");
            std::process::exit(2);
        },
    }
}
