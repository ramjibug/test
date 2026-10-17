// C-ABI probe: exercises the exported `extern "C"` FFI functions
// (`tw_any_address_is_valid`, `tw_any_address_create_with_string`)
// through the same `#[no_mangle] pub unsafe extern "C" fn` symbols
// a C linker would resolve.
//
// Each potentially aborting input runs in an isolated subprocess so the
// parent can report exit codes without itself terminating.
//
// Coverage: every decoded payload length 0-12, valid address, prefixed
// address, for both BitcoinCash (id=145) and eCash (id=899).
//
// Build:  cargo build --release --bin cabi_probe
// Run:    ./target/release/cabi_probe

use std::ffi::CString;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use tw_memory::ffi::tw_string::{tw_string_create_with_utf8_bytes, tw_string_delete, TWString};
use tw_any_coin::ffi::tw_any_address::{
    tw_any_address_is_valid,
    tw_any_address_create_with_string,
};

fn run_in_child(mode: &str, coin_id: u32, input: &str) -> (i32, String) {
    let exe = std::env::current_exe().unwrap();
    let output = Command::new(&exe)
        .args(["--child", mode, &coin_id.to_string(), input])
        .output()
        .expect("failed to spawn child");

    let code = output
        .status
        .code()
        .unwrap_or_else(|| {
            output.status.signal().map(|s| 128 + s).unwrap_or(1)
        });
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stderr)
}

fn child_is_valid(coin_id: u32, input: &str) {
    let cstr = CString::new(input).expect("CString::new");
    unsafe {
        let tw_str = tw_string_create_with_utf8_bytes(cstr.as_ptr());
        assert!(!tw_str.is_null());
        let result = tw_any_address_is_valid(tw_str, coin_id);
        tw_string_delete(tw_str as *mut TWString);
        eprintln!("[cabi] tw_any_address_is_valid(coin={coin_id}) returned: {result}");
    }
}

fn child_create_with_string(coin_id: u32, input: &str) {
    let cstr = CString::new(input).expect("CString::new");
    unsafe {
        let tw_str = tw_string_create_with_utf8_bytes(cstr.as_ptr());
        assert!(!tw_str.is_null());
        let addr = tw_any_address_create_with_string(tw_str, coin_id);
        tw_string_delete(tw_str as *mut TWString);
        if addr.is_null() {
            eprintln!("[cabi] tw_any_address_create_with_string(coin={coin_id}) returned: null");
        } else {
            eprintln!("[cabi] tw_any_address_create_with_string(coin={coin_id}) returned: non-null");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Child mode: --child <mode> <coin_id> [input]
    if args.len() >= 4 && args[1] == "--child" {
        let mode = &args[2];
        let coin_id: u32 = args[3].parse().expect("coin_id");
        let input = if args.len() >= 5 { &args[4] } else { "" };
        match mode.as_str() {
            "is_valid" => child_is_valid(coin_id, input),
            "create_with_string" => child_create_with_string(coin_id, input),
            _ => {
                eprintln!("unknown child mode: {mode}");
                std::process::exit(2);
            }
        }
        return;
    }

    println!("=== C-ABI FFI Probe (exhaustive): tw_any_address_is_valid / tw_any_address_create_with_string ===");
    println!("Target: commit adf80f8bac989e18a4ef1922e2b9eaeb4bf804a9");
    println!("Profile: panic=\"abort\", overflow-checks=false");
    println!();

    struct CoinTest {
        name: &'static str,
        id: u32,
        valid_addr: &'static str,
        prefixed_addr: &'static str,
    }

    let coins = [
        CoinTest {
            name: "BitcoinCash",
            id: 145,
            valid_addr: "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            prefixed_addr: "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
        },
        CoinTest {
            name: "eCash",
            id: 899,
            valid_addr: "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            prefixed_addr: "ecash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
        },
    ];

    let q = "qqqqqqqqqqqq"; // 12 q's

    for coin in &coins {
        println!("## {} (id={})", coin.name, coin.id);
        println!();
        println!("| FFI function | input | decoded symbols | exit | result |");
        println!("|---|---|---|---|---|");

        // Payload lengths 0 through 12
        for len in 0..=12u32 {
            let input = &q[..len as usize];
            let label = if len == 0 { "(empty)".to_string() } else { input.to_string() };

            for func in ["is_valid", "create_with_string"] {
                let (code, _) = run_in_child(func, coin.id, input);
                let result = match code {
                    0 => "returned normally",
                    134 => "**abort (SIGABRT)**",
                    _ => "other",
                };
                let func_name = if func == "is_valid" {
                    "tw_any_address_is_valid"
                } else {
                    "tw_any_address_create_with_string"
                };
                println!("| `{func_name}` | `{label}` | {len} | {code} | {result} |");
            }
        }

        // Valid address (no prefix)
        for func in ["is_valid", "create_with_string"] {
            let (code, _) = run_in_child(func, coin.id, coin.valid_addr);
            let result = match code {
                0 => "returned normally",
                134 => "**abort (SIGABRT)**",
                _ => "other",
            };
            let func_name = if func == "is_valid" {
                "tw_any_address_is_valid"
            } else {
                "tw_any_address_create_with_string"
            };
            println!("| `{func_name}` | `{0}` | 42 (valid) | {code} | {result} |", coin.valid_addr);
        }

        // Prefixed address
        for func in ["is_valid", "create_with_string"] {
            let (code, _) = run_in_child(func, coin.id, coin.prefixed_addr);
            let result = match code {
                0 => "returned normally",
                134 => "**abort (SIGABRT)**",
                _ => "other",
            };
            let func_name = if func == "is_valid" {
                "tw_any_address_is_valid"
            } else {
                "tw_any_address_create_with_string"
            };
            println!("| `{func_name}` | `{0}` | prefixed | {code} | {result} |", coin.prefixed_addr);
        }

        println!();
    }

    println!("Exit 134 = SIGABRT (process termination via panic-abort)");
    println!("Exit 0   = function returned normally");
}
