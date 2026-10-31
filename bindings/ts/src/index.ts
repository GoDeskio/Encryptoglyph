// Thin typed wrapper over the Rust/WASM core. All crypto happens in Rust; nothing here
// touches key material beyond passing bytes through.
import { WasmKeyring, deriveRootKeyFromPassword as wasmDerive } from "../pkg/encryptoglyph.js";

export const VERSION_LEGACY = 1;
export const VERSION_V2 = 2;

export interface RecordContext {
  tenant: string;
  purpose: string;
  table: string;
  recordId: string;
  field?: string;
  schemaVersion?: number;
}

export class Keyring {
  private readonly inner: WasmKeyring;
  constructor(kid: string, key: Uint8Array) { this.inner = new WasmKeyring(kid, key); }
  add(kid: string, key: Uint8Array, makeCurrent = true): void { this.inner.add(kid, key, makeCurrent); }
  retire(kid: string): void { this.inner.retire(kid); }
  get current(): string { return this.inner.current(); }

  encrypt(c: RecordContext, plaintext: Uint8Array): Uint8Array {
    return this.inner.encrypt(c.tenant, c.purpose, c.table, c.recordId, c.field ?? "", c.schemaVersion ?? 1, plaintext);
  }
  decrypt(c: RecordContext, blob: Uint8Array, minVersion = VERSION_LEGACY): Uint8Array {
    return this.inner.decrypt(c.tenant, c.purpose, c.table, c.recordId, c.field ?? "", c.schemaVersion ?? 1, blob, minVersion);
  }
  rewrap(c: RecordContext, blob: Uint8Array): Uint8Array {
    return this.inner.rewrap(c.tenant, c.purpose, c.table, c.recordId, c.field ?? "", c.schemaVersion ?? 1, blob);
  }
  needsRewrap(blob: Uint8Array): boolean { return this.inner.needsRewrap(blob); }
}

/** Argon2id (m=256 MiB, t=3, p=1). salt: 16 random bytes stored with the account. */
export function deriveRootKeyFromPassword(password: string, salt: Uint8Array): Uint8Array {
  return wasmDerive(new TextEncoder().encode(password), salt);
}
