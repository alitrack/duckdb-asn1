# Extension configuration for `DuckDB`'s build system.
# Required by extension-ci-tools even for pure-Rust (cargo) extensions.
# See: https://github.com/duckdb/extension-ci-tools

duckdb_extension_load(asn1
	LOAD_TESTS
	GIT_URL https://github.com/alitrack/duckdb-asn1
	GIT_TAG main
)
