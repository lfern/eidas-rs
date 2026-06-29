//! Generates a CAdES B-B signature over "hello world" and writes it to `cades_bb_test.p7s`.
//!
//! Run with: `cargo run --example dump_cades_bb`
//! Then upload `cades_bb_test.p7s` to <https://dss.nowina.lu/validation>.

use ades::{cades, signer::SoftSigner};
use std::fs;

fn main() {
    let signer = SoftSigner::generate(2048).expect("key generation failed");
    let data = b"hello world";
    let signed = cades::sign(data, &signer).expect("CAdES B-B signing failed");
    fs::write("cades_bb_test.p7s", &signed).expect("failed to write output file");
    println!("Written {} bytes to cades_bb_test.p7s", signed.len());
}
