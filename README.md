# eidas-rs

Rust workspace with libraries for the eIDAS 2.0 ecosystem.

> **Status: Work in Progress — M1 (CAdES B-B) in development**

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| [`ades`](crates/ades/) | AdES digital signatures (CAdES, PAdES) | M0 ✅ |

## Milestones

- **M1**: CAdES B-B — validated by EU DSS
- **M2**: PAdES B-B — validated by EU DSS
- **M3**: Long-term validation (T, LT, LTA levels)
- **M4**: PKCS#11 backend (DNIe, HSM)
- **M5**: XAdES

## Validation

Correctness criterion: the generated signature is accepted by the EU DSS validator:
https://dss.nowina.lu/validation

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
