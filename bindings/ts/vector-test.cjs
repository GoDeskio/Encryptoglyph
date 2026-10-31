// Usage: node vector-test.cjs <wasm-bindgen nodejs out dir>
const eg = require(require("path").resolve(process.argv[2], "encryptoglyph.js"));
const v = require("../../testvectors/envelope.json");
const h = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const kr = new eg.WasmKeyring(v.kid, h(v.key_hex));
const c = v.ctx;
for (const f of ["v2_hex", "v1_hex"]) {
  const pt = Buffer.from(kr.decrypt(...c, h(v[f]), 1)).toString();
  if (pt !== v.plaintext) throw new Error("vector " + f);
}
const blob = kr.encrypt(...c, Buffer.from("x"));
blob[blob.length - 1] ^= 1;
let threw = false; try { kr.decrypt(...c, blob, 1); } catch { threw = true; }
if (!threw) throw new Error("tamper not detected");
let dg = false; try { kr.decrypt(...c, h(v.v1_hex), 2); } catch { dg = true; }
if (!dg) throw new Error("downgrade not blocked");
console.log("wasm vectors OK");
