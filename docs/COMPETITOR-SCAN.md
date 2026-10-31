# Encryptoglyph competitor & feature scan (2026-10-31)

Method: public docs, papers, standards and open-source code only. No proprietary code was copied and no closed software was decompiled. Code under BUSL, AGPL, SSPL or other copyleft/source-available licenses (Vault, CipherStash Proxy, Infisical core, Proton clients, Signal libsignal) is studied for design only and must never enter this tree. Pricing is public list pricing as published; verify before quoting to customers.

## 1. Feature matrix

Legend: Y = yes, P = partial / add-on, N = no.

| Platform | License | Core crypto | Key mgmt | Search/query | Tokenize | FPE | Audit | FIPS 140-3 | PQC | Pricing model |
|---|---|---|---|---|---|---|---|---|---|---|
| HashiCorp Vault Transit | BUSL 1.1 | AES-GCM-96, ChaCha20-Poly1305, RSA, ECDSA, Ed25519 | Versioned keys, rotate/rewrap, min-decrypt version, BYOK/HSM (Ent) | Convergent (deterministic) enc | Y (Ent Transform) | Y FF3-1 (Ent) | Y audit devices | Y (Ent FIPS build) | P (ML-DSA/SLH-DSA preview) | Ent per-client / HCP hourly |
| OpenBao Transit | MPL-2.0 | Same as Vault OSS Transit | Versioned keys, rotate/rewrap, namespaces | Convergent | N | N | Y | N | N | Free |
| AWS KMS + Encryption SDK | Apache-2.0 SDK | AES-256-GCM, HKDF, key-committing suites, ECDSA signed messages | Envelope / data keys, multi-region, hierarchical keyring, XKS | P (DB-ESDK beacons) | N | N | Y CloudTrail | Y (KMS HSM L3) | Y ML-DSA keys, hybrid PQ TLS | ~$1/key/mo + $0.03/10k req |
| Google Cloud KMS + Tink | Apache-2.0 Tink | AES-GCM, AES-GCM-SIV, XChaCha20-Poly1305, AES-SIV, hybrid HPKE, streaming AEAD | Keysets with key IDs, rotation, EKM, Cloud HSM | Deterministic AEAD (AES-SIV) | N (DLP does) | Y via Sensitive Data Protection | Y Cloud Audit Logs | Y (Cloud HSM L3) | Y ML-KEM / ML-DSA / X-Wing previews | ~$0.06/key ver/mo + ops |
| Azure Key Vault / Managed HSM | Proprietary service | RSA, EC, AES (MHSM) | Rotation policies, BYOK, Managed HSM | N (SQL Always Encrypted does) | N | N | Y Monitor | Y (MHSM L3) | P roadmap | per-op / hourly HSM |
| Thales CipherTrust | Proprietary | AES, RSA, FPE FF1/FF3-1 | Central KMS, CCKM multi-cloud, Luna HSM | P | Y (vaulted + vaultless) | Y | Y | Y | Y PQC-ready Luna | Enterprise quote |
| Fortanix DSM | Proprietary | AES, RSA, EC, FPE | SaaS HSM (SGX), quorum approvals | N | Y | Y | Y | Y L3 | Y ML-KEM/ML-DSA | Enterprise / SaaS tiers |
| Virtru (TDF) | OpenTDF BSD-3-Clause | AES-256-GCM per object, RSA/EC key wrap | Customer-hosted key server, policy attributes | N | N | N | Y per-object access log | P | P | per user |
| Tresorit | Proprietary | AES-256, RSA-4096, client-side E2EE | Per-file keys, user keys | N | N | N | Y admin logs | N | N | per user |
| Proton / OpenPGP.js | LGPL-3.0 (OpenPGP.js), GPL clients | OpenPGP (Curve25519, AES), RFC 9580 crypto refresh | User keys, key transparency | P (local search index) | N | N | P | N | Y PQC OpenPGP draft (ML-KEM + X25519) | per user |
| Cryptomator | GPL-3.0 | AES-SIV filenames, AES-GCM content, scrypt | Masterkey file, Hub for teams | N | N | N | P (Hub) | N | N | Free / Hub per user |
| Skiff-style E2EE (Skiff, Standard Notes) | AGPL (SN) | XChaCha20-Poly1305, Argon2id | Per-item keys, sharing via public keys | P client-side index | N | N | N | N | N | per user |
| MongoDB Queryable Encryption | Proprietary server / Apache libmongocrypt | AES-256-CBC+HMAC, structured encryption | KMS providers, DEK per field | Y equality + range | N | N | P | P | N | in Atlas tiers |
| Postgres pgcrypto / pg_tde | PostgreSQL / MIT-like | AES, PGP (pgcrypto); AES TDE (pg_tde) | Manual (pgcrypto); Vault/KMIP providers (pg_tde) | N | N | N | N | N | N | Free |
| CipherStash | Proxy: source-available; libs Apache/MIT | AES-GCM-SIV + ORE / match index (EQL) | ZeroKMS per-value keys, key sets | Y equality, range, match, JSON | N | N | Y | P | N | usage tiers |
| Ubiq | Proprietary, open SDKs | AES-GCM, FF1/FF3-1 | API-key based, rotation | N | Y | Y | Y | P | N | usage tiers |
| Piiano Vault | Proprietary | AES-GCM | Data-vault model | Y (blind index) | Y | P | Y | P | N | tiers |
| Evervault | Proprietary, open SDKs | AES-256-GCM, ECDH P-256 | Keys in Nitro enclaves | N | Y (relay) | N | Y | PCI L1 | N | usage |
| VGS | Proprietary | AES | Vault + aliases | N | Y | Y | Y | PCI L1 | N | usage / enterprise |
| Bitwarden Secrets Manager | GPL/BWL | AES-256-CBC+HMAC, PBKDF2/Argon2id | Machine accounts, org keys | N | N | N | Y event logs | N | N | per user / free tier |
| Infisical | MIT core + proprietary EE | AES-256-GCM, KMS mode | Secret versioning, rotation, KMIP, HSM | N | N | N | Y | P (FIPS image) | N | per identity |
| Doppler | Proprietary | AES-256-GCM | Managed, BYOK (Ent) | N | N | N | Y | N | N | per user |
| SOPS | MPL-2.0 | AES-256-GCM per value + key groups | age/PGP/KMS/Vault, Shamir key groups | N | N | N | N | N | N | Free |
| age | BSD-3-Clause | X25519 + ChaCha20-Poly1305 STREAM, scrypt | Recipients, plugins (YubiKey, KMS) | N | N | N | N | N | Y ML-KEM-768 hybrid recipients (v1.3) | Free |
| libsodium | ISC | XChaCha20-Poly1305, secretstream, X25519, Ed25519, Argon2id | Primitives only | N | N | N | N | N | N | Free |
| Signal protocol | AGPL libsignal | X3DH/PQXDH, Double Ratchet, SPQR | Per-message ratchet keys | N | N | N | N | N | Y PQXDH + ML-KEM ratchet | Free |
| Keybase | BSD | NaCl, saltpack | Per-device keys, sigchain | N | N | N | Y public sigchain | N | N | Free |
| Cloudflare (Keyless SSL, Workers secrets, Zero Trust) | Proprietary; CIRCL BSD-3 | AES-GCM, HPKE, CIRCL PQ | Keyless SSL, geo key manager | N | N | N | Y | P | Y X25519MLKEM768 by default | plan-based |
| Also: Google Private Join/AWS Clean Rooms, Microsoft SEAL (MIT, FHE), Zama TFHE (BSD-3-Clause-Clear), Hashicorp Boundary | various | FHE / MPC | — | Y compute on ciphertext | — | — | — | — | — | research watch |

## 2. Encryptoglyph today (main 43d61f7)

Has: XChaCha20-Poly1305 default, versioned envelope with legacy decrypt, Argon2id password KDF, HKDF per-site/per-purpose key separation, record-bound AAD, key rotation without data loss, no master key or backdoor, 37 tests, Python API + TS bindings.

Lacks (vs the field): KMS/HSM backends, envelope data keys with KEK wrapping, key commitment, deterministic/searchable encryption, tokenization, FPE, streaming/large-file AEAD, audit log, crypto-shredding, PQC hybrid, signing, policy/ABAC, multi-tenant namespaces, FIPS mode, test vectors published, CI on the Rust core, third-party audit.

## 3. Prioritized backlog

| # | Item | Learn from | Why | Size |
|---|---|---|---|---|
| 1 | Rust core in CI (cargo test, clippy, cargo-deny, cargo-audit, Wycheproof vectors) | Tink, Wycheproof (Apache-2.0) | Nothing else is trustworthy without it | S |
| 2 | Envelope encryption: per-record DEK wrapped by tenant KEK; KEK provider trait (local, OpenBao Transit, AWS/GCP/Azure KMS, PKCS#11/KMIP HSM) | AWS ESDK, Tink KMS envelope, OpenBao | Key custody outside the app; MSP selling point | M |
| 3 | Key commitment (HMAC/BLAKE3 commitment over key in header, or committing AEAD construction) | AWS ESDK committing suites, paper "Partitioning Oracle Attacks" | Blocks multi-key / partitioning attacks | S |
| 4 | Crypto-shredding: per-tenant / per-subject keys, destroy key = erase data, signed shred receipt | AWS KMS key deletion, CipherStash ZeroKMS | GDPR erasure + insurer evidence | S |
| 5 | Tamper-evident audit log (hash-chained, signed, exportable to SIEM) | Vault audit devices, Keybase sigchain, CloudTrail | SOC2 / auditor evidence | M |
| 6 | Hybrid PQC key wrap: X25519 + ML-KEM-768 (HPKE / X-Wing) for KEK wrap and sharing; ML-DSA signatures later | age 1.3, Cloudflare CIRCL, Signal PQXDH, Tink | Harvest-now-decrypt-later protection | M |
| 7 | Searchable encryption: deterministic AEAD (AES-SIV / XChaCha-SIV) for equality + HMAC blind indexes; later ORE/range | Tink DAEAD, CipherStash EQL design, MongoDB QE papers | Query encrypted DB columns | M |
| 8 | Tokenization service (vaulted random tokens + vaultless deterministic), detokenize with policy | VGS, Evervault, Piiano, Thales | PCI/PII scope reduction | M |
| 9 | Format-preserving encryption FF1 (NIST SP 800-38G; avoid FF3-1, withdrawn in 800-38G Rev.1 draft) | Ubiq, Thales, Vault Transform | Encrypt SSNs/cards keeping format | M |
| 10 | Streaming AEAD for large files/backups (STREAM / secretstream chunking) | age, libsodium secretstream, Tink streaming AEAD | Backups and attachments | S |
| 11 | Postgres integration: pg extension or app-side column encryption + pg_tde provider for at-rest | pg_tde, CipherStash | Encrypt all GoDesk site backends | L |
| 12 | Policy / ABAC per object (who can decrypt what, time-bound) | OpenTDF (BSD-3) | Fine-grained sharing | M |
| 13 | Multi-tenant namespaces + quotas + per-tenant rate limits | OpenBao namespaces | MSP model | M |
| 14 | Secrets manager surface (versioned secrets, rotation hooks) – or integrate Komboe/Infisical-style | Infisical (MIT core), SOPS | One console | L |
| 15 | Quorum / M-of-N approval and Shamir unseal for root ops | Fortanix, Vault unseal, SOPS key groups | No single admin can exfiltrate | M |
| 16 | Signing + verification (Ed25519, ML-DSA) for artifacts/receipts | Tink, Sigstore | Integrity proofs | S |
| 17 | FIPS mode (aws-lc-rs FIPS backend for AES-GCM/HKDF/PBKDF2 path) | AWS-LC FIPS 140-3 cert | Federal/health buyers | M |
| 18 | Published test vectors + spec of envelope format | age spec, Tink | Interop, audits | S |
| 19 | External audit (NCC/Trail of Bits/Cure53) + bug bounty | Cryptomator, age, Proton | Trust | L |
| 20 | Research watch: FHE (SEAL/TFHE), clean rooms | Zama, MS SEAL | Future compute-on-ciphertext | — |

## 4. License guardrails
- OK to depend on: Apache-2.0, MIT, BSD, ISC, MPL-2.0 (file-level, unmodified) crates such as RustCrypto, aws-lc-rs, libsodium bindings, ring, Tink-rs designs.
- Design study only, never copy code: Vault (BUSL), libsignal (AGPL), Standard Notes (AGPL), Proton clients (GPL), Cryptomator (GPL), CipherStash Proxy (source-available), any closed SaaS.
- Enforce with `cargo-deny` license allow-list in CI (backlog #1).

## 5. REA (Reverse Engineer Anything) status
- Version pinned: `rea-agents@6.5.0` (local clone 42fc6c53a). It has not been run yet.
- Lab: none available on 2026-10-31. The shared box has no Docker, Podman or VM, and the REA safe-lab rule forbids running it on the shared host. The "how it works" findings come from public docs, specs, whitepapers and open-source code.
- Next: rerun in a snapshotted, credential-free lab VM against open-source projects and public clients. Roll back after each job. Never copy closed-source code into the tree.

## 6. REA findings + features to adopt (static scan 2026-10-31, rea-agents 6.5.0)

Static only: OSS repos cloned and parsed with `analyze-javascript-application`; vendor sites inspected unauthenticated; Standard Notes desktop `app.asar` (official .deb) parsed inertly on the lab PC. Nothing executed. Raw summaries: `GoDeskio/rea-scans` → `encryptoglyph/reports/*.summary.json`.

| Target | What the static graph / source shows | Adopt |
|---|---|---|
| AWS Encryption SDK (JS) | `branch-keystore-node` (hierarchical keyring: branch keys wrapped by KMS, authenticated encryption context), committing suites | #2 envelope KEK provider with *branch key* cache; #3 key commitment |
| CipherStash (EQL) | `*OrdOre` / `*OrdOreQuery` bindings for every scalar type → ORE range queries next to blind indexes | #7 searchable: add typed equality + range index API surface |
| Evervault | `attestationDoc`, `pcrManager`: client verifies enclave attestation (PCRs) before sending data | New #21: attested decrypt service (Nitro/SEV) – later |
| Ubiq | `fpeEncryptDecrypt`, `structuredEncryptDecrypt`, `encryption-pipeline` | #9 FF1 FPE as a "structured" API |
| Vault / OpenBao Transit (UI source) | `min_decryption_version`, rewrap, key versions per key | Add `min_decryption_kid` policy to `Keyring` (cheap, complements `rewrap`) |
| VGS | Collect.js style iframe fields (bundle only core-js polyfills visible) | #8 tokenization: hosted-field capture later |
| Standard Notes desktop | Electron asar, local-first E2E (scan on lab PC) | Interop / export format ideas only |
| Infisical | very large monorepo (2.5 GB); secret rotation + versioning | #14 stays L; keep in Komboe |

Implemented from this scan:
- **#5 tamper-evident audit log** — PR #5 (`encryptoglyph::audit`).
- **#4 crypto-shredding** — `Keyring::shred` + `ShredReceipt` (receipt appended to the audit chain as erasure evidence).

Next (ranked): #3 key commitment (S) → `min_decryption_kid` (S) → #2 envelope/branch-key KEK provider (M) → #7 typed equality/range indexes (M).
