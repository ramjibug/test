// C-ABI probe: exercises the exported `extern "C"` FFI functions that a C/C++
// consumer (including the public TWAnyAddress* API) calls.
//
// This binary calls the same `#[no_mangle] pub unsafe extern "C" fn` entry
// points that a C linker would resolve.  It does NOT call the safe Rust API;
// it goes through the FFI boundary exactly as a C caller does.
//
// Each crash-triggering input is run in a forked child so the parent can
// report the exit status without itself terminating.
//
// Build:  cargo build --release --bin cabi_probe
// Run:    ./target/release/cabi_probe
//
// If the release profile uses panic = "abort" and no catch_unwind wraps the
// FFI functions, exit code 134 (SIGABRT) proves the C-ABI boundary crashes.

use std::ffi::CString;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

// Re-export the FFI functions we are testing.
// These are the actual `extern "C"` symbols exported by the Rust library.
use tw_memory::ffi::tw_string::{tw_string_create_with_utf8_bytes, tw_string_delete, TWString};
use tw_any_coin::ffi::tw_any_address::{
    tw_any_address_is_valid,
    tw_any_address_create_with_string,
};

const BCH_COIN_ID: u32 = 145; // CoinType::BitcoinCash

fn run_in_child(mode: &str, input: &str) -> (i32, String) {
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(&exe)
        .args(["--child", mode, input])
        .output()
        .expect("failed to spawn child");

    let code = output
        .status
        .code()
        .unwrap_or_else(|| {
            // killed by signal
            output.status.signal().map(|s| 128 + s).unwrap_or(1)
        });
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stderr)
}

fn child_is_valid(input: &str) {
    let cstr = CString::new(input).expect("CString::new");
    unsafe {
        let tw_str = tw_string_create_with_utf8_bytes(cstr.as_ptr());
        assert!(!tw_str.is_null(), "tw_string_create_with_utf8_bytes returned null");
        let result = tw_any_address_is_valid(tw_str, BCH_COIN_ID);
        tw_string_delete(tw_str as *mut TWString);
        eprintln!("[cabi] tw_any_address_is_valid returned: {result}");
    }
}

fn child_create_with_string(input: &str) {
    let cstr = CString::new(input).expect("CString::new");
    unsafe {
        let tw_str = tw_string_create_with_utf8_bytes(cstr.as_ptr());
        assert!(!tw_str.is_null(), "tw_string_create_with_utf8_bytes returned null");
        let addr = tw_any_address_create_with_string(tw_str, BCH_COIN_ID);
        tw_string_delete(tw_str as *mut TWString);
        if addr.is_null() {
            eprintln!("[cabi] tw_any_address_create_with_string returned: null (expected for invalid)");
        } else {
            eprintln!("[cabi] tw_any_address_create_with_string returned: non-null");
            // Would delete here, but we're testing the crash path
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Child mode: execute a single FFI call (may abort)
    if args.len() >= 4 && args[1] == "--child" {
        let mode = &args[2];
        let input = &args[3];
        match mode.as_str() {
            "is_valid" => child_is_valid(input),
            "create_with_string" => child_create_with_string(input),
            _ => {
                eprintln!("unknown child mode: {mode}");
                std::process::exit(2);
            }
        }
        return;
    }
    // Handle empty-input child case (args[3] would be missing)
    if args.len() == 3 && args[1] == "--child" {
        let mode = &args[2];
        match mode.as_str() {
            "is_valid" => child_is_valid(""),
            "create_with_string" => child_create_with_string(""),
            _ => {
                eprintln!("unknown child mode: {mode}");
                std::process::exit(2);
            }
        }
        return;
    }

    // Parent mode: run each test case in a subprocess and report
    println!("=== C-ABI FFI Probe: tw_any_address_is_valid / tw_any_address_create_with_string ===");
    println!("Target: commit adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9");
    println!("Coin:   BitcoinCash (id=145)");
    println!("Profile: panic=\"abort\", overflow-checks=false");
    println!();

    let test_inputs: Vec<(&str, &str)> = vec![
        ("(empty)", ""),
        ("q", "q"),
        ("qqqqqqq", "qqqqqqq"),
        ("qqqqqqqq", "qqqqqqqq"),
        ("qqqqqqqqq", "qqqqqqqqq"),
        ("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
         "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    ];

    println!("| FFI function | input | decoded symbols | exit | result |");
    println!("|---|---|---|---|---|");

    for (label, input) in &test_inputs {
        let decoded_len = if *input == "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a" {
            "42 (valid)".to_string()
        } else {
            format!("{}", input.len())
        };

        // Test tw_any_address_is_valid
        let (code, _stderr) = run_in_child("is_valid", input);
        let result = match code {
            0 => "returned normally",
            134 => "**abort (SIGABRT)**",
            _ => "other",
        };
        println!("| `tw_any_address_is_valid` | `{label}` | {decoded_len} | {code} | {result} |");

        // Test tw_any_address_create_with_string
        let (code, _stderr) = run_in_child("create_with_string", input);
        let result = match code {
            0 => "returned normally",
            134 => "**abort (SIGABRT)**",
            _ => "other",
        };
        println!("| `tw_any_address_create_with_string` | `{label}` | {decoded_len} | {code} | {result} |");
    }

    println!();
    println!("Exit 134 = SIGABRT (process termination via panic-abort)");
    println!("Exit 0   = function returned normally");
}
