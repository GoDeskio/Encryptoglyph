# Contributing

Thanks for helping with Encryptoglyph. This project is licensed under the Apache License, Version 2.0. Contributions are accepted under that same license. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Do not report vulnerabilities as public issues or pull requests. Email [security@komboe.com](mailto:security@komboe.com). The process is in [SECURITY.md](SECURITY.md).

## What to work on

Open a pull request against `main`. Keep the change focused, and describe the behavior you are adding or fixing.

## Development

CI runs the checks below. Rust stable and Python 3.12 match the GitHub Actions runners.

### Rust core

From `crates/encryptoglyph`:

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo deny check
```

`cargo deny check` enforces the license, advisory, ban, and source policy in `crates/encryptoglyph/deny.toml`. Dependency licenses must stay inside that allow list.

### API

From `api`:

```bash
python -m pip install ruff==0.16.10
ruff check .
python -m pip install -r requirements-dev.txt
pytest
```

### License metadata

The crate, npm package, and Python project metadata must say `Apache-2.0`:

```bash
python3 scripts/check-license-metadata.py
```

On a machine with Rust installed, also check the Cargo package metadata:

```bash
python3 scripts/check-license-metadata.py --require-cargo-metadata
```

## Code of conduct

This project uses the [Contributor Covenant](CODE_OF_CONDUCT.md). Report conduct issues to [security@komboe.com](mailto:security@komboe.com).
