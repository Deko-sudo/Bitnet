//! Fuzz target for KDBX vault deserialization.
//!
//! Run with:
//!   rustup run nightly cargo fuzz run kdbx_deserialize -- -max_total_time=60
//!
//! Prerequisites:
//!   rustup toolchain install nightly
//!   cargo install cargo-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Write fuzz input to a temporary file and attempt vault load.
    // Must not panic on any input.
    let path = "fuzz_temp_vault.bitnet";
    if std::fs::write(path, data).is_err() {
        return;
    }
    // Try with a dummy password. Decryption will almost certainly fail,
    // but we are testing that the deserializer does not panic or crash.
    let _ = bitnet_kdbx::load_vault(path, b"fuzz_password_12345");
    let _ = std::fs::remove_file(path);
});