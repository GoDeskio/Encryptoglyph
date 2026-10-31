# Komboe ← Encryptoglyph integration (design, not yet implemented)

Decision (Dustin, 2026-10-31): no separate SDK fork. **Encryptoglyph is the single shared
GoDesk crypto library**: a Rust core (`crates/encryptoglyph`) with bindings — WASM +
TypeScript wrapper (`bindings/ts`) for web vault/extension/desktop, a native Rust crate for
the Vaultwarden-based server and CLI tooling, and the Python package (`api/eg_crypto`,
wire-compatible, to be replaced by a PyO3 binding of the same core). Komboe is **not**
changed by this PR.

## Today in Komboe (GoDeskio/Komboe #74, docs/design/xchacha20.md)
- Bitwarden `EncString` types 0/2 (AES-CBC+HMAC) plus the new AEAD v2 type using
  **XAES-256-GCM** (192-bit nonce), because the Bitwarden SDK it builds on pins that cipher.
- Off by default; old vaults decrypt and upgrade on unlock; downgrade guard via minimum type.

## Target
Komboe's AEAD v2 path calls Encryptoglyph's v2 envelope (**XChaCha20-Poly1305**, 192-bit
nonce) instead of XAES-256-GCM. Zero-knowledge is unchanged: the key used is the user's
symmetric vault key (derived client-side from the master password via Argon2id/KDF and
never sent to the server). Encryptoglyph adds no escrow or server key. Admin password
reset and Key Connector stay absent.

## Swap plan
1. **New EncString type** (e.g. type 8 "EG2") whose payload is an Encryptoglyph envelope,
   base64 encoded. Keep the XAES type decryptable (read-only) — never reuse its type number.
2. **Key mapping:** Komboe's 64-byte user key (enc||mac) → Encryptoglyph `Keyring` with
   kid = `uk-<keyVersion>` and root key = HKDF(userKey, "komboe/eg-root/v1") (32 bytes).
   Org keys get their own keyring (kid = `org-<id>-<ver>`); purpose = `cipher`, `folder`,
   `send`, `attachment`; tenant = user id or org id.
3. **AAD binding:** RecordContext {tenant: user/org id, purpose, table: item type,
   record_id: cipher id, field: field name, schema_version}. This adds anti-swap
   protection Bitwarden's format lacks. Caveat: cipher ids must exist before encryption
   (new items need a client-generated UUID) and moves between orgs require rewrap.
4. **Clients:** web vault, browser extension, desktop (Electron) load `@godesk/encryptoglyph`
   (WASM) behind the existing `EncryptService`; route type 8 encrypt/decrypt there. The
   extension's MV3 CSP needs `wasm-unsafe-eval` (already required by the Bitwarden SDK WASM).
   CLI uses the same WASM build in Node. Mobile (later): UniFFI bindings of the Rust core.
5. **Server (Vaultwarden):** stores type-8 strings opaquely; only needs validation that
   accepts the new prefix. No server-side keys.
6. **Rollout:** feature flag (off) → write EG2 for new items; on unlock, `needsRewrap` →
   rewrap XAES/legacy items in the background; once an account is fully migrated set
   `minVersion` = EG2 for that account (downgrade guard); keep the XAES reader for one
   release cycle, then remove.
7. **Tests:** shared vectors in `testvectors/` run in Rust, Python, and the TS wrapper; Komboe
   adds round-trip/legacy/rotation tests in its client test suite and an e2e unlock-upgrade test.

## Open questions
- Exact EncString type number (check Bitwarden's reserved range to avoid collisions).
- Whether to bind AAD for attachments (file id) and Sends (access id) in v1 or later.
- Key commitment (see SECURITY-HARDENING.md §next steps) before enabling multi-key Sends.
