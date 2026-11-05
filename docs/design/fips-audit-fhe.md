# FIPS mode, external audit, FHE watch (backlog #17, #19, #20)

## #17 FIPS mode (blocked; design only)
- **Goal:** a `fips` cargo feature (and Python env flag) that routes AES-256-GCM, HKDF-SHA256, HMAC and the DRBG through a FIPS 140-3 validated module (aws-lc-rs `fips` feature, CMVP cert for AWS-LC FIPS 3.0). Non-approved algorithms (XChaCha20-Poly1305, Argon2id, X25519, ML-KEM pre-validation) fail closed.
- **Wire impact:** FIPS mode writes v1/alg 1 (AES-256-GCM) envelopes, or a future v3 with AES-GCM and key commitment. Readers stay the same.
- **Interface:** a `CryptoProvider` trait (`aead_seal`, `aead_open`, `hkdf`, `hmac`, `random`) with `RustCryptoProvider` (default) and `AwsLcFipsProvider`. Selection happens at compile time, and a startup self-test runs.
- **Blocker:** the aws-lc FIPS build needs CMake, Go and a pinned toolchain in CI, plus a decision on which validated cert and platform to claim. A "FIPS" claim is only valid on the validated build and OS. Needs Dustin's go-ahead and CI runner time. Nothing ships until then.

## #19 External audit (real blocker: vendor and money)
- **Scope:** `crates/encryptoglyph` (envelope, stream, shamir, ff1, token, pq, policy), `api/eg_crypto`, and the KDF parameters.
- **Candidates to quote:** Trail of Bits, NCC Group, Cure53, Least Authority. Typical crypto-library engagements run 2–4 engineer-weeks.
- **Prep done in-repo:** spec (`docs/SPEC-ENVELOPE.md`, PR #19), test vectors, clippy, and the cargo-deny policy (PR #15).
- **Needs:** a budget decision and a signed SOW. No code action possible.

## #20 FHE research watch (not code)
- Track OpenFHE and TFHE-rs (Zama; check the license before any use) for encrypted aggregate queries.
- Review twice a year. Adopt only if a GoDesk use case needs computation on ciphertext that blind indexes and order-revealing buckets can't cover.
