# Rust core CI job

The `rust-core` job in `.github/workflows/ci.yml` runs `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo deny check` from `crates/encryptoglyph`, using `crates/encryptoglyph/deny.toml`.

`docs/ci/rust-core-job.patch` is the diff that added the job. It is already applied.
