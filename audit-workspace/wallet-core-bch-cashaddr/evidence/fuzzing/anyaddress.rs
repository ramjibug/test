// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tw_any_coin::any_address::AnyAddress;
use tw_coin_registry::coin_type::CoinType;

// Universal address-parser fuzzer. First 2 bytes select a coin; the rest is the
// candidate address string. Exercises validate_address / normalize_address /
// address_to_data across every Rust-migrated chain, reachable via the public
// TWAnyAddressIsValid / TWAnyAddressCreateWithString FFI.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let coins: Vec<CoinType> = CoinType::iter().into_iter().collect();
    let idx = (u16::from_le_bytes([data[0], data[1]]) as usize) % coins.len();
    let coin = coins[idx];

    if let Ok(s) = std::str::from_utf8(&data[2..]) {
        let _ = AnyAddress::is_valid(coin, s, None);
        if let Ok(addr) = AnyAddress::with_string(coin, s, None) {
            let _ = addr.get_data();
        }
    }
});
