// DuckDB loadable extension: ASN.1 BER/CER/DER inspection, in SQL — structural
// decode to JSON, an openssl-asn1parse-style dump, OID name resolution,
// well-formedness triage, node-path extraction, and canonical re-encoding.
//
// Thin quack-rs binding over `asn1_core` (verbatim from Query-farm's vgi-asn1
// asn1-core crate, MIT — a panic-free generic TLV codec + OID registry + JSON /
// dump renderers; only `serde_json`, `base64`, `sha2`; no I/O, no network, no
// Arrow). Only the Arrow IPC transport was replaced with direct C-API vector
// I/O.
//
// Function surface (v1 — scalars, no file/glob source, no MAP return):
//
//   asn1_to_json(payload)              -> VARCHAR  nested JSON projection (or {error,kind})
//   asn1_dump(payload, fmt)            -> VARCHAR  openssl/dumpasn1-style tree (fmt in {'openssl','dumpasn1'})
//   asn1_is_valid(payload, rules)      -> BOOLEAN  well-formed under der/cer/ber rules
//   asn1_well_formed(payload)          -> STRUCT(ok, error, kind)  BER triage
//   asn1_at_path(payload, path)        -> VARCHAR  JSON value at a node path ('$.0.2'), NULL if unparseable
//   asn1_oid_name(dotted)              -> VARCHAR  '1.2.840.113549.1.1.11' -> 'sha256WithRSAEncryption'
//   asn1_oid(name)                     -> VARCHAR  inverse of asn1_oid_name
//   asn1_to_der(payload)               -> BLOB     re-encoded canonical DER
//
// `payload` is a BLOB of DER/BER bytes. Decoding is total on arbitrary input:
// a malformed blob yields NULL (at_path/to_der) or a parse-error rendering
// (to_json/dump) — never a SQL error. The OID helpers take a VARCHAR (a dotted
// OID or a registry name) and return NULL for an unknown entry.

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::ScalarFunctionBuilder;
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{VectorReader, VectorWriter};

use asn1_core::dump::{dump, DumpFormat};
use asn1_core::reencode;
use asn1_core::tlv::{parse, Rules};
use asn1_core::{decode_json, oid, tlvlist, validate};

/// Read a BLOB cell into bytes; None when the row is NULL/invalid.
unsafe fn payload_bytes(value: &VectorReader, row: usize) -> Option<Vec<u8>> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_blob(row).to_vec())
}

/// Read a VARCHAR cell as a String; None when NULL/invalid.
unsafe fn cell_str(value: &VectorReader, row: usize) -> Option<String> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_str(row).to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// asn1_to_json(payload) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(to_json_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let row_count = payload.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match payload_bytes(&payload, row) {
                Some(bytes) => {
                    let json = decode_json(&bytes).to_string();
                    writer.write_varchar(row, &json);
                }
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_dump(payload, fmt) -> VARCHAR
// fmt in {'openssl' (default), 'dumpasn1'}; a NULL fmt column defaults to openssl.
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(dump_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let fmt = VectorReader::new(input, 1);
        let row_count = payload.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            let Some(bytes) = payload_bytes(&payload, row) else {
                writer.set_null(row);
                continue;
            };
            let style = cell_str(&fmt, row)
                .map(|s| DumpFormat::parse(&s))
                .unwrap_or(DumpFormat::Openssl);
            let text = match parse(&bytes) {
                Ok(t) => dump(&t, style),
                Err(e) => format!("<parse error: {} at offset {}>", e.kind.as_str(), e.offset),
            };
            writer.write_varchar(row, &text);
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_is_valid(payload, rules) -> BOOLEAN
// rules in {'der', 'cer', 'ber'}; a NULL rules column defaults to 'der'.
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(is_valid_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let rules = VectorReader::new(input, 1);
        let row_count = payload.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match payload_bytes(&payload, row) {
                Some(bytes) => {
                    let rule = cell_str(&rules, row)
                        .map(|s| Rules::parse(&s))
                        .unwrap_or(Rules::Der);
                    writer.write_bool(row, validate::is_valid(&bytes, rule));
                }
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_well_formed(payload) -> STRUCT(ok, error, kind)
// ─────────────────────────────────────────────────────────────────────────────

const WELL_FORMED_FIELDS: &[(&str, TypeId)] = &[
    ("ok", TypeId::Boolean),
    ("error", TypeId::Varchar),
    ("kind", TypeId::Varchar),
];

quack_rs::scalar_callback!(well_formed_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let row_count = payload.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, WELL_FORMED_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&payload, row) {
                Some(bytes) => {
                    let wf = validate::well_formed(&bytes);
                    sw.write_bool(row, 0, wf.ok);
                    sw.write_varchar(row, 1, &wf.error);
                    sw.write_varchar(row, 2, &wf.kind);
                }
                None => {
                    sw.set_null(row, 0);
                    sw.set_null(row, 1);
                    sw.set_null(row, 2);
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_at_path(payload, path) -> VARCHAR
// The JSON value at `path` (e.g. '$.0.2'); NULL when the blob won't parse or
// the path column is NULL.
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(at_path_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let path = VectorReader::new(input, 1);
        let row_count = payload.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match (payload_bytes(&payload, row), cell_str(&path, row)) {
                (Some(bytes), Some(p)) => match parse(&bytes) {
                    Ok(t) => {
                        let v = tlvlist::at_path(&t, &p);
                        writer.write_varchar(row, &v.to_string());
                    }
                    Err(_) => writer.set_null(row),
                },
                _ => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_oid_name(dotted) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(oid_name_fn, |_info, input, output| {
    unsafe {
        let value = VectorReader::new(input, 0);
        let row_count = value.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match cell_str(&value, row).and_then(|s| oid::name_for(s.trim()).map(|n| n.to_string())) {
                Some(n) => writer.write_varchar(row, &n),
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_oid(name) -> VARCHAR  (inverse of asn1_oid_name)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(oid_fn, |_info, input, output| {
    unsafe {
        let value = VectorReader::new(input, 0);
        let row_count = value.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match cell_str(&value, row).and_then(|s| oid::oid_for(s.trim()).map(|d| d.to_string())) {
                Some(d) => writer.write_varchar(row, &d),
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// asn1_to_der(payload) -> BLOB
// Canonical DER re-encoding; NULL when the blob won't parse.
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(to_der_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let row_count = payload.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match payload_bytes(&payload, row).and_then(|bytes| parse(&bytes).ok()) {
                Some(t) => {
                    let der = reencode::to_der(&t);
                    writer.write_blob(row, &der);
                }
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_to_json")
            .param(TypeId::Blob)
            .returns(TypeId::Varchar)
            .function(to_json_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_dump")
            .param(TypeId::Blob)
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(dump_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_is_valid")
            .param(TypeId::Blob)
            .param(TypeId::Varchar)
            .returns(TypeId::Boolean)
            .function(is_valid_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_well_formed")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(WELL_FORMED_FIELDS))
            .function(well_formed_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_at_path")
            .param(TypeId::Blob)
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(at_path_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_oid_name")
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(oid_name_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_oid")
            .param(TypeId::Varchar)
            .returns(TypeId::Varchar)
            .function(oid_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("asn1_to_der")
            .param(TypeId::Blob)
            .returns(TypeId::Blob)
            .function(to_der_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(asn1_init_c_api, |con| register_all(con));
