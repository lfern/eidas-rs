//! Valida firmas AdES contra el servicio REST del validador DSS de la Comisión Europea.
//!
//! # Uso
//!
//! ```text
//! # CAdES detached (firma .p7s + documento original)
//! dss-client cades firma.p7s original.txt
//!
//! # Con política que ignora cadena de confianza (para certificados de test)
//! dss-client --no-trust cades firma.p7s original.txt
//!
//! # PAdES (PDF firmado)
//! dss-client pades documento_firmado.pdf
//!
//! # Generar CAdES B-B en memoria y validar contra DSS
//! dss-client --no-trust sign-cades-bb [original.txt]
//!
//! # Generar PAdES B-B en memoria y validar contra DSS
//! dss-client --no-trust sign-pades-bb documento.pdf
//!
//! # Generar CAdES B-T en memoria y validar contra DSS
//! dss-client --no-trust sign-cades-t [original.txt]
//!
//! # Generar PAdES B-T en memoria y validar contra DSS
//! dss-client --no-trust sign-pades-t documento.pdf
//! ```
//!
//! Sale con código 0 si DSS responde TOTAL_PASSED, con código 1 en cualquier otro caso.

use ades::{cades, pades, signer::SoftSigner, tsp::TspClient};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::{env, fs, path::Path, process};

const FREETSA_URL: &str = ades::tsp::client::FREETSA_URL;

const DSS_BASE_URL: &str =
    "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest";

/// Política DSS con requisitos de cadena de confianza desactivados.
/// Útil para validar firmas con certificados autofirmados o de test.
const NO_TRUST_POLICY_XML: &[u8] = include_bytes!("no_trust_policy.xml");

// ---------------------------------------------------------------------------
// Tipos de resultado
// ---------------------------------------------------------------------------

struct ValidationResult {
    indication: String,
    sub_indication: Option<String>,
    sig_format: Option<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Cliente DSS
// ---------------------------------------------------------------------------

struct DssClient {
    base_url: String,
    no_trust: bool,
}

impl DssClient {
    fn new(base_url: &str, no_trust: bool) -> Self {
        Self {
            base_url: base_url.to_owned(),
            no_trust,
        }
    }

    fn policy_field(&self) -> Value {
        if self.no_trust {
            serde_json::json!({
                "bytes": STANDARD.encode(NO_TRUST_POLICY_XML),
                "name": "no-trust-policy.xml"
            })
        } else {
            Value::Null
        }
    }

    /// Valida una firma CAdES.
    ///
    /// `original` es necesario solo para firmas detached (sin contenido embebido).
    fn validate_cades(
        &self,
        sig: &[u8],
        sig_name: &str,
        original: Option<(&[u8], &str)>,
    ) -> Result<ValidationResult, String> {
        let mut body = serde_json::json!({
            "signedDocument": remote_document(sig, sig_name),
            "policy": self.policy_field(),
            "tokenExtractionStrategy": "NONE"
        });

        if let Some((orig_bytes, orig_name)) = original {
            body["originalDocuments"] = serde_json::json!([remote_document(orig_bytes, orig_name)]);
        }

        self.post_validate(body)
    }

    /// Valida una firma PAdES (PDF con firma embebida).
    fn validate_pades(&self, sig: &[u8], sig_name: &str) -> Result<ValidationResult, String> {
        let body = serde_json::json!({
            "signedDocument": remote_document(sig, sig_name),
            "policy": self.policy_field(),
            "tokenExtractionStrategy": "NONE"
        });

        self.post_validate(body)
    }

    fn post_validate(&self, body: Value) -> Result<ValidationResult, String> {
        let url = format!("{}/validation/validateSignature", self.base_url);

        let response: Value = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| format!("HTTP error: {e}"))?
            .into_json()
            .map_err(|e| format!("JSON parse error: {e}"))?;

        parse_simple_report(&response)
    }
}

// ---------------------------------------------------------------------------
// Helpers de construcción / parsing
// ---------------------------------------------------------------------------

fn remote_document(bytes: &[u8], name: &str) -> Value {
    serde_json::json!({
        "bytes": STANDARD.encode(bytes),
        "name": name,
        "digestAlgorithm": null
    })
}

fn parse_simple_report(response: &Value) -> Result<ValidationResult, String> {
    // La respuesta del DSS REST usa PascalCase:
    //   { "SimpleReport": { "signatureOrTimestampOrEvidenceRecord": [ { "Signature": { ... } } ] } }
    let sigs = response
        .pointer("/SimpleReport/signatureOrTimestampOrEvidenceRecord")
        .and_then(|v| v.as_array())
        .ok_or("respuesta inesperada: falta SimpleReport.signatureOrTimestampOrEvidenceRecord")?;

    if sigs.is_empty() {
        return Err("DSS no encontró ninguna firma en el documento".to_owned());
    }

    let sig = sigs
        .iter()
        .find_map(|e| e.get("Signature"))
        .ok_or("no Signature entry found in SimpleReport")?;

    let indication = str_field(sig, "Indication").unwrap_or("UNKNOWN");
    let sub_indication = str_field(sig, "SubIndication").map(ToOwned::to_owned);
    let sig_format = str_field(sig, "SignatureFormat").map(ToOwned::to_owned);

    let errors = nested_string_array(sig, "AdESValidationDetails", "Error");
    let warnings = nested_string_array(sig, "AdESValidationDetails", "Warning");

    Ok(ValidationResult {
        indication: indication.to_owned(),
        sub_indication,
        sig_format,
        errors,
        warnings,
    })
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(|f| f.as_str())
        .filter(|s| !s.is_empty())
}

/// Extrae un array `[{ "value": "..." }]` anidado bajo `parent_key -> child_key`.
fn nested_string_array(v: &Value, parent_key: &str, child_key: &str) -> Vec<String> {
    v.get(parent_key)
        .and_then(|p| p.get(child_key))
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    e.get("value")
                        .and_then(|s| s.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn print_result(result: &ValidationResult) {
    if let Some(fmt) = &result.sig_format {
        println!("Formato:       {fmt}");
    }
    println!("Indicación:    {}", result.indication);
    if let Some(sub) = &result.sub_indication {
        println!("Sub-indicación: {sub}");
    }
    for e in &result.errors {
        println!("ERROR:   {e}");
    }
    for w in &result.warnings {
        println!("WARNING: {w}");
    }
}

fn usage(prog: &str) {
    eprintln!("Uso:");
    eprintln!("  {prog} [--no-trust] cades <firma.p7s> [original.txt]");
    eprintln!("  {prog} [--no-trust] pades <documento.pdf>");
    eprintln!("  {prog} [--no-trust] sign-cades-bb [original.txt]");
    eprintln!("  {prog} [--no-trust] sign-pades-bb <documento.pdf>");
    eprintln!("  {prog} [--no-trust] sign-cades-t [original.txt]");
    eprintln!("  {prog} [--no-trust] sign-pades-t <documento.pdf>");
    eprintln!();
    eprintln!("  --no-trust  ignora cadena de confianza (para certs de test/autofirmados)");
    eprintln!();
    eprintln!("Los subcomandos sign-* generan la firma en memoria con SoftSigner + FreeTSA");
    eprintln!("y la envían directamente a DSS para validación.");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args[0].as_str();

    // Parse --no-trust flag (can appear anywhere before the subcommand)
    let no_trust = args.iter().any(|a| a == "--no-trust");
    let positional: Vec<&str> = args[1..]
        .iter()
        .filter(|a| a.as_str() != "--no-trust")
        .map(|a| a.as_str())
        .collect();

    if positional.is_empty() {
        usage(prog);
        process::exit(1);
    }

    if no_trust {
        eprintln!("[aviso] usando política sin validación de cadena de confianza");
    }

    let client = DssClient::new(DSS_BASE_URL, no_trust);

    let result = match positional[0] {
        "cades" => {
            let sig = fs::read(positional[1]).unwrap_or_else(|e| {
                eprintln!("No se puede leer {}: {e}", positional[1]);
                process::exit(1);
            });
            let sig_name = Path::new(positional[1])
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();

            let original = positional.get(2).map(|p| {
                let bytes = fs::read(p).unwrap_or_else(|e| {
                    eprintln!("No se puede leer {p}: {e}");
                    process::exit(1);
                });
                let name = Path::new(p)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                (bytes, name)
            });

            client.validate_cades(
                &sig,
                sig_name,
                original.as_ref().map(|(b, n)| (b.as_slice(), n.as_str())),
            )
        }
        "pades" => {
            let sig = fs::read(positional[1]).unwrap_or_else(|e| {
                eprintln!("No se puede leer {}: {e}", positional[1]);
                process::exit(1);
            });
            let sig_name = Path::new(positional[1])
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            client.validate_pades(&sig, sig_name)
        }
        "sign-cades-bb" => {
            let data: Vec<u8> = match positional.get(1) {
                Some(path) => fs::read(path).unwrap_or_else(|e| {
                    eprintln!("No se puede leer {path}: {e}");
                    process::exit(1);
                }),
                None => b"hello world cades-bb".to_vec(),
            };

            eprintln!("[sign-cades-bb] generando clave RSA 2048…");
            let signer = SoftSigner::generate(2048).unwrap_or_else(|e| {
                eprintln!("Error generando clave: {e}");
                process::exit(1);
            });

            eprintln!("[sign-cades-bb] firmando…");
            let signed = cades::sign(&data, &signer).unwrap_or_else(|e| {
                eprintln!("Error firmando: {e}");
                process::exit(1);
            });
            eprintln!("[sign-cades-bb] {} bytes — enviando a DSS…", signed.len());

            client.validate_cades(&signed, "signed.p7s", Some((&data, "original.bin")))
        }
        "sign-pades-bb" => {
            if positional.len() < 2 {
                eprintln!("sign-pades-bb requiere un fichero PDF");
                usage(prog);
                process::exit(1);
            }
            let pdf = fs::read(positional[1]).unwrap_or_else(|e| {
                eprintln!("No se puede leer {}: {e}", positional[1]);
                process::exit(1);
            });

            eprintln!("[sign-pades-bb] generando clave RSA 2048…");
            let signer = SoftSigner::generate(2048).unwrap_or_else(|e| {
                eprintln!("Error generando clave: {e}");
                process::exit(1);
            });

            eprintln!("[sign-pades-bb] firmando…");
            let signed = pades::sign(&pdf, &signer).unwrap_or_else(|e| {
                eprintln!("Error firmando: {e}");
                process::exit(1);
            });
            eprintln!("[sign-pades-bb] {} bytes — enviando a DSS…", signed.len());

            client.validate_pades(&signed, "signed.pdf")
        }
        "sign-cades-t" => {
            let data: Vec<u8> = match positional.get(1) {
                Some(path) => fs::read(path).unwrap_or_else(|e| {
                    eprintln!("No se puede leer {path}: {e}");
                    process::exit(1);
                }),
                None => b"hello world cades-t".to_vec(),
            };

            eprintln!("[sign-cades-t] generando clave RSA 2048…");
            let signer = SoftSigner::generate(2048).unwrap_or_else(|e| {
                eprintln!("Error generando clave: {e}");
                process::exit(1);
            });
            let tsa = TspClient::new(FREETSA_URL);

            eprintln!("[sign-cades-t] firmando + timestamp FreeTSA…");
            let signed = cades::sign_t(&data, &signer, &tsa).unwrap_or_else(|e| {
                eprintln!("Error firmando: {e}");
                process::exit(1);
            });
            eprintln!("[sign-cades-t] {} bytes — enviando a DSS…", signed.len());

            client.validate_cades(&signed, "signed.p7s", Some((&data, "original.bin")))
        }
        "sign-pades-t" => {
            if positional.len() < 2 {
                eprintln!("sign-pades-t requiere un fichero PDF");
                usage(prog);
                process::exit(1);
            }
            let pdf = fs::read(positional[1]).unwrap_or_else(|e| {
                eprintln!("No se puede leer {}: {e}", positional[1]);
                process::exit(1);
            });

            eprintln!("[sign-pades-t] generando clave RSA 2048…");
            let signer = SoftSigner::generate(2048).unwrap_or_else(|e| {
                eprintln!("Error generando clave: {e}");
                process::exit(1);
            });
            let tsa = TspClient::new(FREETSA_URL);

            eprintln!("[sign-pades-t] firmando + timestamp FreeTSA…");
            let signed = pades::sign_t(&pdf, &signer, &tsa).unwrap_or_else(|e| {
                eprintln!("Error firmando: {e}");
                process::exit(1);
            });
            eprintln!("[sign-pades-t] {} bytes — enviando a DSS…", signed.len());

            client.validate_pades(&signed, "signed.pdf")
        }
        cmd => {
            eprintln!("Comando desconocido: '{cmd}'");
            usage(prog);
            process::exit(1);
        }
    };

    match result {
        Ok(r) => {
            print_result(&r);
            if r.indication == "TOTAL_PASSED" || r.indication == "PASSED" {
                println!("\nOK — DSS validó la firma correctamente.");
            } else {
                eprintln!("\nFALL — DSS rechazó la firma.");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
