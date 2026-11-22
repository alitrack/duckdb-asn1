# duckdb-asn1

**ASN.1 BER/CER/DER, in SQL.** Decode a DER/BER blob to a nested JSON tree,
render it like `openssl asn1parse`, resolve OBJECT IDENTIFIERS to names,
triage well-formedness, pull a node out by path, and re-encode to canonical
DER — right in DuckDB. No `openssl` on the box, no Python `pyasn1`, no
`asn1crypto`: the parser is pure Rust, compiled in.

```sql
LOAD 'asn1.duckdb_extension';   -- or `duckdb -unsigned -c "LOAD '...'"`

-- The classic SEQUENCE { INTEGER 5 } (hex 3003020105)
SELECT asn1_to_json(from_hex('3003020105'))  AS json;   -- [5]
SELECT asn1_dump (from_hex('3003020105'), 'openssl');
--     0:d=0 hl=2 l=   3 cons: SEQUENCE
--     2:d=1 hl=2 l=   1 prim: INTEGER:5

SELECT asn1_oid_name('1.2.840.113549.1.1.11');          -- sha256WithRSAEncryption
SELECT asn1_oid  ('sha256WithRSAEncryption');           -- 1.2.840.113549.1.1.11
SELECT asn1_well_formed(from_hex('3003020105')) -> 'ok';  -- true
```

## Why

DER/BER is the wire format under TLS certificates, PKI, Kerberos, CMS, SNMP,
LDAP and a pile of government/telecom protocols. Inspecting one today means
copying bytes into `openssl asn1parse`, or a Python notebook with `asn1crypto`
/ `pyasn1`, then pasting the tree back. This extension makes the codec a
first-class SQL primitive: the `payload` is a BLOB column, the output is a
VARCHAR / BOOLEAN / BLOB / flat STRUCT you can filter, join and aggregate on.
Useful for cert-trust audits, CRL/OCSP triage, Kerberos ticket forensics, and
any pipeline that ingests binary protocol captures into a database.

## Install

Once accepted into [DuckDB's community extensions](https://github.com/duckdb/community-extensions):

```sql
INSTALL asn1 FROM community;
LOAD asn1;
```

Until it lands in the community registry, build from source:

```bash
git clone https://github.com/alitrack/duckdb-asn1 && cd duckdb-asn1
git submodule update --init --recursive
make release          # -> build/release/asn1.duckdb_extension
```

```sql
LOAD 'path/to/asn1.duckdb_extension';
```

## Functions

| Function | Returns | Notes |
|---|---|---|
| `asn1_to_json(payload)` | `VARCHAR` | Nested JSON projection of the TLV tree. A malformed blob yields `{"error": …, "kind": …}` (never a SQL error). |
| `asn1_dump(payload, fmt)` | `VARCHAR` | `openssl asn1parse`-style tree; `fmt` in `{'openssl'` (default), `'dumpasn1'` (Gutmann-style with OID names)`. A malformed blob renders a `<parse error: …>` line. |
| `asn1_is_valid(payload, rules)` | `BOOLEAN` | Well-formed under `rules` in `{'der','cer','ber'}` (default `der`). |
| `asn1_well_formed(payload)` | `STRUCT(ok, error, kind)` | BER triage with a classified failure `kind` (`truncated`, `length-overflow`, `invalid-tag`, …). |
| `asn1_at_path(payload, path)` | `VARCHAR` | The JSON value at a node path, e.g. `asn1_at_path(b, '$.0.2')`; a missed path returns the JSON string `"null"`, an unparseable blob returns SQL `NULL`. |
| `asn1_oid_name(dotted)` | `VARCHAR` | Resolve a dotted OID to its registered name (`'2.5.4.3'` → `'id-at-commonName'`). `NULL` if unknown. |
| `asn1_oid(name)` | `VARCHAR` | Inverse of `asn1_oid_name`. `NULL` if unknown. |
| `asn1_to_der(payload)` | `BLOB` | Re-encode to canonical DER (definite minimal lengths, sorted `SET`); `NULL` if the blob won't parse. |

`payload` is a `BLOB` of DER/BER bytes (`from_hex('…')` for literals, a
`BLOB` column from `read_blob`/`read_parquet` for real data). The OID helpers
take a `VARCHAR`. The `fmt` / `rules` / `path` arguments are regular columns,
so you can vary them per row in a `CASE` or join them from a config table; a
`NULL` `fmt`/`rules` falls back to the default.

## Scope (v1)

- **Scalars only** — the VGI worker's file/glob-sourced tables (`pem_decode`,
  `cms_signers`, `pkcs12_bags`, `ldap_messages`, `snmp_varbinds`, `oid_registry`)
  are not ported; feed BLOBs in directly.
- **No MAP return** — `asn1_to_json` returns a JSON `VARCHAR` (a DuckDB
  `MAP` would be a natural shape but the bundled 1.1.0 test harness has no
  MAP type); use `->` on the JSON or `json_extract` to drill in.
- **No structural security decoders** — the `security` module (Kerberos ticket,
  PKCS#8, CMS certs, SNMP varbinds, LDAP, OCSP) is ported into `asn1_core`
  but not surfaced in v1; the generic codec + OID + dump covers the common
  triage path.
- **Canonical re-encode only** — `asn1_to_der` always emits canonical DER
  (the core `reencode` ignores a rules argument); use it to normalize
  BER→DER for fingerprinting / diffing.

## Build

```sh
make release        # -> target/release/asn1.duckdb_extension
make test           # bundled DuckDB runs tests/integration.rs (SQL-level)
```

The cdylib links only the DuckDB C extension ABI (resolved at `LOAD` time) and
`asn1_core` (pure Rust, no native, no I/O). `panic = "unwind"` keeps a bug in
the extension from aborting the host process.
