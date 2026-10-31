# Rust core CI job (pending)

The bot token lacks the GitHub `workflow` scope, so it cannot edit `.github/workflows/`. To enable the job, someone with that scope runs `git apply docs/ci/rust-core-job.patch` and commits. The job runs cargo test, clippy -D warnings and cargo deny check, using `crates/encryptoglyph/deny.toml`.
