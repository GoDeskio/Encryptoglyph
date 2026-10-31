# Encryptoglyph security hardening (2026-10-31)

Status of the data-encryption core (`api/eg_crypto`) and what comes next. Mirrors the
Komboe AEAD v2 upgrade (GoDeskio/Komboe #74), but Encryptoglyph is not bound to the
Bitwarden SDK, so it uses real **XChaCha20-Poly1305** (libsodium) instead of XAES-256-GCM.

## Library shape
Encryptoglyph is the single shared GoDesk crypto library (no separate SDK fork):
- `crates/encryptoglyph` — Rust core (RustCrypto `chacha20poly1305`, `aes-gcm`, `hkdf`, `argon2`, `subtle`, `zeroize`; `#![forbid(unsafe_code)]`). Source of truth.
- `wasm` feature + `bindings/ts` — WASM build and TypeScript wrapper for web vaults, extensions, desktop, and Node.
- `api/eg_crypto` — Python implementation, wire-compatible (to become a PyO3 binding of the core).
- `testvectors/envelope.json` — shared vectors checked by Rust and Python tests.
- Komboe adoption plan: `docs/design/komboe-integration.md`.

## Done in this change
| Control | Implementation |
|---|---|
| Versioned AEAD envelope | `EG` magic + version + alg + key id + nonce + ct/tag. v2 = XChaCha20-Poly1305-IETF (libsodium via PyNaCl), 192-bit random nonce, default for all new writes. |
| Backward-compatible decrypt | v1 = AES-256-GCM (96-bit nonce, pyca/cryptography), the format the plan's Tink-style SDK specified. Still decrypts; `needs_rewrap()` flags it. No v1 data existed in the repo before this change. |
| Upgrade on read/unlock | `rewrap()` decrypts any supported version/key and re-encrypts as v2 under the current key. |
| Downgrade guard | Header is authenticated as AAD (version/alg bytes can't be flipped); version↔alg pairing is enforced; `decrypt(min_version=2)` rejects legacy once migration is finished. |
| Password-based keys | `derive_root_key_from_password()` = Argon2id (libsodium, MODERATE ops/mem by default), 16-byte random salt. |
| Key separation | HKDF-SHA256 per root key / purpose / tenant / algorithm. Root keys never encrypt data directly. |
| Anti-swap AAD | Canonical length-prefixed (tenant, purpose, table, record id, field, schema version). Moving a ciphertext to another row/field/tenant fails authentication. |
| Rotation | `Keyring` with key ids, `add()` (new current), `rewrap()`, `retire()` (cannot retire current). |
| Constant-time compares | `ct_equal` / `verify_blind_index` use `hmac.compare_digest`. Blind index = truncated HMAC-SHA256, per tenant/field. |
| Uniform errors | All failures raise a single non-specific `DecryptError` (no padding/tag oracle detail). |
| Zero-knowledge, no backdoor | No escrow/master override key in the library. Escrow (plan §3) must remain dual-control, customer-visible, and audited; it is a custody feature, not a crypto bypass. |

Tests: `api/tests/test_crypto.py` (round-trip, nonce uniqueness, tamper every header/body region, truncation, wrong AAD per field, AAD unambiguity, legacy decrypt + upgrade, downgrade guard, version forgery, rotation + retire, wrong key, HKDF separation, Argon2id, blind index, keyring validation).

## Next steps
1. **KMS/HSM custody:** root keys come from OpenBao Transit (`datakey` → wrapped DEK) per plan §2, never from env files. v2: HSM/PKCS#11 or cloud KMS auto-unseal; Shamir 3-of-5 until then.
2. **Envelope encryption per site:** one KEK per site in OpenBao, per-record or per-table DEKs wrapped by it; store the wrapped DEK + KEK version next to data; bulk rewrap worker (`eg-worker`) with progress and evidence records.
3. **Post-quantum hybrid:** for key exchange/transport (agent enrolment, escrow bundles) use X25519 + ML-KEM-768 hybrid (FIPS 203) once a vetted library is available in our stacks (liboqs / OpenSSL 3.5+ / age PQ plugin). Symmetric XChaCha20-Poly1305 with 256-bit keys is already PQ-adequate.
4. **Key commitment:** Poly1305/GCM aren't key-committing. Add a commitment tag (HMAC of key id + nonce under a derived key) if multi-key/partitioning-oracle scenarios arise.
5. **Memory hygiene:** the Rust core zeroises keys; replace the pure-Python path with a PyO3 binding of the core.
6. **Bindings:** publish the WASM/TS package to the internal registry with a CI wasm-pack build + TS vector test; add UniFFI (mobile) and a Go binding if needed.
7. **Ittia and other GoDesk sites:** adopt `eg_crypto` v2 (or the SDKs) for field-level encryption of tokens and PII.
8. **Audit:** third-party crypto review of this design + the M6 pentest; fuzz `parse_header`; add CI dependency/license scan.
9. **CI for the Rust core/WASM:** the push token lacks `workflow` scope, so `.github/workflows/ci.yml` still runs only the Python jobs. Add a `rust-core` job (`cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo check --features wasm --target wasm32-unknown-unknown`, wasm-bindgen build + `node bindings/ts/vector-test.cjs`). Verified locally on 2026-10-31.
