# eidas-rs — CLAUDE.md

## Contexto del proyecto

Workspace Rust con librerías para el ecosistema eIDAS 2.0.
Primer crate: `ades` — firma AdES (CAdES B-B, PAdES B-B).
Objetivo: publicable en crates.io, production-ready, validado por DSS de la CE.

## Comandos esenciales

```bash
cargo build                    # compilar
cargo test                     # ejecutar tests (los de integración están #[ignore] hasta M1)
cargo test -- --ignored        # ejecutar tests de integración
cargo clippy -- -D warnings    # lint estricto — cero errores tolerados
cargo fmt                      # formatear (equivalente a Pint en PHP)
cargo fmt --check              # verificar formato sin modificar (para CI)
cargo doc --no-deps --open     # generar y abrir documentación
```

## Arquitectura — decisiones tomadas, NO cambiar sin consultar

- Trait `Signer` con `sign_digest(&self, digest: &[u8])` — **nunca** `sign` con datos completos
  - La clave privada nunca sale del dispositivo: compatible con DNIe, HSM, WebCrypto
- Features para compilación selectiva: `soft` (tests), `pkcs11` (DNIe/HSM), `wasm` (navegador)
- Errores con `thiserror` — **nunca** `anyhow` en código de librería
- Sin `unwrap()` ni `expect()` fuera de `#[cfg(test)]` y binarios
- Workspace mono-repo: un `Cargo.toml` raíz, crates en `/crates/`
- Sin OpenSSL — Rust puro siempre que sea posible
- RustCrypto como base criptográfica
- `#![forbid(unsafe_code)]` en todos los crates

## Patrones obligatorios

- Toda función y tipo público tiene doc comment con ejemplo de uso
- `#[must_use]` en tipos `Result` y builders
- Errores son enums exhaustivos con `thiserror`, nunca strings ad-hoc (`Err("algo falló".to_string())` → prohibido)
- Tests de integración en `crates/*/tests/`, tests unitarios en `#[cfg(test)]` dentro del módulo
- Cada cambio debe pasar: `cargo fmt --check` + `cargo clippy -- -D warnings` + `cargo test`

## Estilo de código — compatibilidad RustCrypto

- `rustfmt` con `rustfmt.toml` en la raíz — ejecutar tras cada cambio
- `#![deny(clippy::all)]` y `#![deny(missing_docs)]` en todos los `lib.rs`
- Sin `unwrap()` / `expect()` fuera de `#[cfg(test)]`
- Sin `unsafe` salvo necesidad documentada con justificación explícita
- **Compatibilidad con `DigestSigner` de RustCrypto**: el trait `Signer` usa `sign_digest` análogo a `DigestSigner<D, S>` de RustCrypto. Al implementar backends futuros, usar los traits de `signature` crate cuando sea posible.
- **Traits vs Structs — regla práctica**:
  - Trait **solo** para `Signer` — múltiples backends reales e intercambiables (soft, pkcs11, wasm, remote)
  - `CAdES`, `PAdES`, `TspClient`, `OcspClient` → structs concretas, una sola implementación
  - `DigestAlgorithm` → enum, no trait
  - No diseñar para extensibilidad imaginaria — YAGNI
  - Si en el futuro se extrae TSP/OCSP para proponer a RustCrypto, entonces sí diseñar con traits desde el principio
- Errores con tipos específicos — nunca `String` como tipo de error
- `no_std` **no es un objetivo**. AdES no se ejecuta en microcontroladores, y PAdES requiere std para el manejo de PDF. Si un módulo de criptografía pura usa `core::` de forma natural, bien — pero no es un requisito.

## Dependencias — política

- RustCrypto como base: `rsa`, `p256`, `sha2`, `x509-cert`, `cms`, `der`, `spki`
- Si RustCrypto no cubre algo: implementar en este crate primero, PR a RustCrypto después
- Sin dependencias innecesarias — justificar cada nueva dep en el PR
- Sin OpenSSL (`openssl`, `openssl-sys`) — usar `rustls` si hace falta TLS

## Criterio de corrección

**Una firma es correcta cuando DSS de la CE la acepta.**
Validador: https://dss.nowina.lu/validation
Si DSS lo acepta → correcto. Si no → no importa lo que diga nuestro propio verificador.

## Milestone actual

**M5: XAdES B-B ✅ (en progreso)**
- `src/xades/mod.rs`, `src/xades/sign.rs` — XAdES B-B enveloping, exc-C14N
- Feature: `xades = ["dep:base64ct"]`
- DSS valida como `XAdES-BASELINE-B / TOTAL_PASSED`
- Validar: `cargo run -p dss-client -- --no-trust sign-xades-bb`
- Tests: `cargo test --features "cades,pades,soft,tsp,ocsp,xades" --test xades_bb`

**M4: Backend PKCS#11 (DNIe/HSM) ✅**
- `src/pkcs11/signer.rs` — RSA + ECDSA, `CKA_KEY_TYPE` detection, lifetime correcto
- `src/cms.rs` — `signature_algorithm_id()` derivando OID del certificado
- `tests/pkcs11_signer.rs` — tests con SoftHSM2 (RSA B-B, ECDSA B-B, RSA B-T)
- Features: `pkcs11 = ["dep:cryptoki"]`
- Ejecutar: `cargo test --features "pkcs11,tsp" --test pkcs11_signer -- --ignored`

**M3: Niveles T, LT (TSP/OCSP) ✅**
- `src/tsp/client.rs` — RFC 3161 TSP client (FreeTSA); `tests/tsp_client.rs` pasa
- `src/ocsp/client.rs` — RFC 6960 OCSP client; `tests/ocsp_client.rs` pasa
- `src/levels.rs` — `add_signature_timestamp` / `add_revocation_values` via decode→modify→encode CMS
- `src/cades/sign_t.rs` — `sign_t` (B-T), `sign_lt` (B-LT); `tests/cades_bt.rs` pasa
- `src/pades/sign_t.rs` — `pades::sign_t`, `pades::sign_lt`; `examples/dump_pades_bt.rs`
- DSS valida CAdES B-T como `CAdES-BASELINE-T / TOTAL_PASSED`
- Features: `tsp = ["dep:ureq"]`, `ocsp = ["dep:x509-ocsp", "dep:ureq"]`
- Validar CAdES: `cargo run -p dss-client -- --no-trust cades cades_bt_test.p7s`

**Siguiente: M5b — XAdES B-T, XAdES-LT**

## Roadmap

| Milestone | Descripción | Estado |
|-----------|-------------|--------|
| M0 | Workspace + stubs compilando | ✅ |
| M1 | CAdES B-B validado por DSS | ✅ |
| M2 | PAdES B-B validado por DSS | ✅ |
| M3 | Niveles T, LT (TSP/OCSP) | ✅ |
| M4 | Backend PKCS#11 (DNIe/HSM) | ✅ |
| M5 | XAdES | 🔄 (B-B ✅) |

## Lo que NO hacer ahora

- No implementar verificación completa
- No implementar verificación completa (M3)
- No publicar en crates.io hasta que DSS valide las firmas (después de M2)
- No usar nightly features
- No usar `unsafe` salvo que sea absolutamente necesario y documentado con justificación

## Licencia

MIT OR Apache-2.0 (dual) — estándar del ecosistema Rust.
