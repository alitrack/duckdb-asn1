//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (8 scalars).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped to
//! `target/release/asn1.duckdb_extension`).
//!
//! Bundled test DuckDB is v1.1.0: BLOBs are built with `from_hex('<hex>')`
//! (v1.1.0 does not interpret `x'HEX'` literals), and struct-field reads via
//! `-> 'field'` yield JSON, so numeric/bool assertions CAST them.

use quack_rs::testing::InMemoryDb;

const SEQ_INT: &str = "3003020105"; // SEQUENCE { INTEGER 5 }

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/asn1.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display())).expect("load extension");
    d
}

#[test]
fn to_json() {
    let d = db();
    let v: String = d
        .query_one(&format!("SELECT asn1_to_json(from_hex('{SEQ_INT}'))"))
        .unwrap();
    assert_eq!(v, "[5]");
}

#[test]
fn dump() {
    let d = db();
    let o: String = d
        .query_one(&format!("SELECT asn1_dump(from_hex('{SEQ_INT}'), 'openssl')"))
        .unwrap();
    assert!(o.contains("SEQUENCE"), "openssl dump:\n{o}");
    assert!(o.contains("INTEGER:5"), "openssl dump:\n{o}");
    let g: String = d
        .query_one(&format!("SELECT asn1_dump(from_hex('{SEQ_INT}'), 'dumpasn1')"))
        .unwrap();
    assert!(g.contains("SEQUENCE"), "dumpasn1 dump:\n{g}");
}

#[test]
fn is_valid() {
    let d = db();
    let ok: bool = d
        .query_one(&format!("SELECT asn1_is_valid(from_hex('{SEQ_INT}'), 'der')"))
        .unwrap();
    assert!(ok);
    // Truncated (declared length 5, only 1 byte present) is not well-formed.
    let bad: bool = d
        .query_one("SELECT asn1_is_valid(from_hex('30050201'), 'der')")
        .unwrap();
    assert!(!bad);
}

#[test]
fn well_formed() {
    let d = db();
    let ok: i32 = d
        .query_one(&format!(
            "SELECT CAST(asn1_well_formed(from_hex('{SEQ_INT}')) -> 'ok' AS INTEGER)"
        ))
        .unwrap();
    assert_eq!(ok, 1);
    // Malformed -> ok=0 with a set kind.
    let bad: i32 = d
        .query_one("SELECT CAST(asn1_well_formed(from_hex('30050201')) -> 'ok' AS INTEGER)")
        .unwrap();
    assert_eq!(bad, 0);
    let kind: String = d
        .query_one("SELECT CAST(asn1_well_formed(from_hex('30050201')) -> 'kind' AS VARCHAR)")
        .unwrap();
    assert!(!kind.is_empty(), "malformed kind should be set: {kind:?}");
}

#[test]
fn at_path() {
    let d = db();
    // $.0 -> the INTEGER 5.
    let v: String = d
        .query_one(&format!("SELECT asn1_at_path(from_hex('{SEQ_INT}'), '$.0')"))
        .unwrap();
    assert_eq!(v, "5");
    // Out-of-range path -> the core's Value::Null, rendered as the JSON
    // string "null" (the function itself still returns a value, not SQL NULL).
    let oob: String = d
        .query_one(&format!("SELECT asn1_at_path(from_hex('{SEQ_INT}'), '$.9')"))
        .unwrap();
    assert_eq!(oob, "null");
}

#[test]
fn oid_roundtrip() {
    let d = db();
    let name: String = d.query_one("SELECT asn1_oid_name('1.2.840.113549.1.1.11')").unwrap();
    assert_eq!(name, "sha256WithRSAEncryption");
    let dotted: String = d.query_one("SELECT asn1_oid('sha256WithRSAEncryption')").unwrap();
    assert_eq!(dotted, "1.2.840.113549.1.1.11");
    // Unknown -> NULL.
    let unknown: Option<String> = d.query_one("SELECT asn1_oid_name('99.99.99')").unwrap();
    assert!(unknown.is_none());
}

#[test]
fn to_der() {
    let d = db();
    // The input is already canonical DER, so re-encoding is identity (5 bytes).
    let len: i64 = d
        .query_one(&format!("SELECT octet_length(asn1_to_der(from_hex('{SEQ_INT}')))"))
        .unwrap();
    assert_eq!(len, 5);
}

#[test]
fn total_on_garbage() {
    let d = db();
    // Malformed blob: to_json returns an {error,kind} JSON object (never errors).
    let bad: String = d.query_one("SELECT asn1_to_json('garbage-not-der')").unwrap();
    assert!(bad.contains("\"error\""), "expected an error object: {bad}");
    // NULL input -> NULL output (no panic, no error).
    let nullj: Option<String> = d.query_one("SELECT asn1_to_json(NULL)").unwrap();
    assert!(nullj.is_none());
}
