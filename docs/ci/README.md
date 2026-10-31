# Rust core CI job

The `rust-core` job in `.github/workflows/ci.yml` runs `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo deny check` from `crates/encryptoglyph`, using `crates/encryptoglyph/deny.toml`. It also runs `scripts/check-license-metadata.py --require-cargo-metadata`, which reads `cargo metadata` and requires the crate license to be Apache-2.0.

The `license-metadata` job runs the same script without Cargo, and checks `Cargo.toml`, `bindings/ts/package.json`, and `api/pyproject.toml`.

`docs/ci/rust-core-job.patch` is the diff that added the original rust-core job. It is already applied.
