//! wasm-bindgen surface for the web vault / extensions (see bindings/ts).
use crate::*;
use wasm_bindgen::prelude::*;

fn ctx(
    tenant: &str,
    purpose: &str,
    table: &str,
    record_id: &str,
    field: &str,
    schema_version: u32,
) -> RecordContext {
    RecordContext {
        tenant: tenant.into(),
        purpose: purpose.into(),
        table: table.into(),
        record_id: record_id.into(),
        field: field.into(),
        schema_version,
    }
}
fn je(e: Error) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
pub struct WasmKeyring(Keyring);

#[wasm_bindgen]
impl WasmKeyring {
    #[wasm_bindgen(constructor)]
    pub fn new(kid: &str, key: &[u8]) -> Result<WasmKeyring, JsError> {
        Keyring::new(kid, key).map(WasmKeyring).map_err(je)
    }
    pub fn add(&mut self, kid: &str, key: &[u8], make_current: bool) -> Result<(), JsError> {
        self.0.add(kid, key, make_current).map_err(je)
    }
    pub fn retire(&mut self, kid: &str) -> Result<(), JsError> {
        self.0.retire(kid).map_err(je)
    }
    pub fn current(&self) -> String {
        self.0.current().into()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(
        &self,
        tenant: &str,
        purpose: &str,
        table: &str,
        record_id: &str,
        field: &str,
        schema_version: u32,
        pt: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        crate::encrypt(
            &self.0,
            &ctx(tenant, purpose, table, record_id, field, schema_version),
            pt,
        )
        .map_err(je)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt(
        &self,
        tenant: &str,
        purpose: &str,
        table: &str,
        record_id: &str,
        field: &str,
        schema_version: u32,
        blob: &[u8],
        min_version: u8,
    ) -> Result<Vec<u8>, JsError> {
        crate::decrypt(
            &self.0,
            &ctx(tenant, purpose, table, record_id, field, schema_version),
            blob,
            min_version,
        )
        .map(|z| z.to_vec())
        .map_err(je)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn rewrap(
        &self,
        tenant: &str,
        purpose: &str,
        table: &str,
        record_id: &str,
        field: &str,
        schema_version: u32,
        blob: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        crate::rewrap(
            &self.0,
            &ctx(tenant, purpose, table, record_id, field, schema_version),
            blob,
        )
        .map_err(je)
    }
    #[wasm_bindgen(js_name = needsRewrap)]
    pub fn needs_rewrap(&self, blob: &[u8]) -> Result<bool, JsError> {
        crate::needs_rewrap(&self.0, blob).map_err(je)
    }
}

#[wasm_bindgen(js_name = deriveRootKeyFromPassword)]
pub fn derive_pw(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsError> {
    derive_root_key_from_password(password, salt)
        .map(|k| k.to_vec())
        .map_err(je)
}
