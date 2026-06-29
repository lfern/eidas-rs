use ades::{pades, signer::SoftSigner};
use std::fs;

fn main() {
    let pdf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures/sample.pdf".to_owned());

    let pdf = fs::read(&pdf_path).unwrap_or_else(|e| {
        eprintln!("cannot read {pdf_path}: {e}");
        std::process::exit(1);
    });

    let signer = SoftSigner::generate(2048).expect("key generation failed");
    let signed = pades::sign(&pdf, &signer).expect("PAdES B-B signing failed");

    let out = "pades_bb_test.pdf";
    fs::write(out, &signed).expect("failed to write output file");
    println!("Written {} bytes to {out}", signed.len());
    println!("Validate: cargo run -p dss-client -- --no-trust pades {out}");
}
