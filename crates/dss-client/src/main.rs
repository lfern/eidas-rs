//! Valida firmas AdES contra el servicio REST del validador DSS de la Comisión Europea.
//!
//! # Uso
//!
//! ```text
//! # CAdES detached (firma .p7s + documento original)
//! dss-client cades firma.p7s original.txt
//!
//! # CAdES attached (firma .p7s sin documento aparte)
//! dss-client cades firma.p7s
//!
//! # PAdES (PDF firmado)
//! dss-client pades documento_firmado.pdf
//! ```
//!
//! Sale con código 0 si DSS responde TOTAL_PASSED, con código 1 en cualquier otro caso.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::{env, fs, path::Path, process};

const DSS_BASE_URL: &str =
    "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest";

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
}

impl DssClient {
    fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_owned(),
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
            "policy": null,
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
            "policy": null,
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
    //   { "SimpleReport": { "signatureOrTimestampOrEvidenceRecord": [ { "Indication": "...", ... } ] } }
    let sigs = response
        .pointer("/SimpleReport/signatureOrTimestampOrEvidenceRecord")
        .and_then(|v| v.as_array())
        .ok_or("respuesta inesperada: falta SimpleReport.signatureOrTimestampOrEvidenceRecord")?;

    if sigs.is_empty() {
        return Err("DSS no encontró ninguna firma en el documento".to_owned());
    }

    // Each element is { "Signature": { ... } } or { "Timestamp": { ... } }
    // We look for the first Signature entry.
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

/// Extracts a `[{ "value": "..." }]` array nested under `parent_key -> child_key`.
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
    eprintln!("  {prog} cades <firma.p7s> [original.txt]   — CAdES detached o attached");
    eprintln!("  {prog} pades <documento.pdf>               — PAdES");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args[0].as_str();

    if args.len() < 3 {
        usage(prog);
        process::exit(1);
    }

    let client = DssClient::new(DSS_BASE_URL);

    let result = match args[1].as_str() {
        "cades" => {
            let sig = fs::read(&args[2]).unwrap_or_else(|e| {
                eprintln!("No se puede leer {}: {e}", args[2]);
                process::exit(1);
            });
            let sig_name = Path::new(&args[2]).file_name().unwrap().to_str().unwrap();

            let original = args.get(3).map(|p| {
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
            let sig = fs::read(&args[2]).unwrap_or_else(|e| {
                eprintln!("No se puede leer {}: {e}", args[2]);
                process::exit(1);
            });
            let sig_name = Path::new(&args[2]).file_name().unwrap().to_str().unwrap();
            client.validate_pades(&sig, sig_name)
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
