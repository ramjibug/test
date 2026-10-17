// Public C API reachability check (the "uppercase" functions an app actually calls).
//
// Install: copy into wallet-core/tests/ (e.g. tests/chains/BitcoinCash/CApiShortInputTests.cpp),
//          re-run cmake so the file is picked up, and build in Release so the Rust crates use the
//          release profile (check the build output for `cargo build --release`).
// Run each input in its own process; an abort kills the whole test binary:
//
//   for s in "" q qqqqqqq qqqqqqqq; do
//     BCH_INPUT="$s" ./build/tests/tests --gtest_filter='BitcoinCashShortInput.*'
//     echo "input=[$s] exit=$?"
//   done
//
// exit 134 (SIGABRT) on an input  => the public C API reaches the vulnerable Rust parser.
// Normal pass/fail output      => it does not abort; report that result as-is.
//
// Adjust includes/helpers (STRING, WRAPS) to match the neighbouring tests at your commit.

#include "TestUtilities.h"

#include <TrustWalletCore/TWAnyAddress.h>
#include <TrustWalletCore/TWCoinType.h>

#include <gtest/gtest.h>

#include <cstdlib>

TEST(BitcoinCashShortInput, TWAnyAddressIsValid) {
    const char* input = std::getenv("BCH_INPUT");
    ASSERT_NE(input, nullptr) << "set BCH_INPUT (it may be empty)";
    auto string = STRING(input);
    // After the fix this returns false; before it, the process aborts if the C API reaches the Rust parser.
    EXPECT_FALSE(TWAnyAddressIsValid(string.get(), TWCoinTypeBitcoinCash));
}

TEST(BitcoinCashShortInput, TWAnyAddressCreateWithString) {
    const char* input = std::getenv("BCH_INPUT");
    ASSERT_NE(input, nullptr) << "set BCH_INPUT (it may be empty)";
    auto string = STRING(input);
    auto* address = TWAnyAddressCreateWithString(string.get(), TWCoinTypeBitcoinCash);
    EXPECT_EQ(address, nullptr);
    if (address != nullptr) {
        TWAnyAddressDelete(address);
    }
}
