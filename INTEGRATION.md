# Adopt Encryptoglyph

Encryptoglyph 0.2.0 exposes two surfaces that share one envelope: the in-process library, and the versioned HTTP sidecar (`/v1`, header `X-Encryptoglyph-Api: 1`). Keys created through the sidecar stay in process memory. Responses carry fingerprints, never key bytes. The assistant endpoint refuses plaintext and key fields.

## In process

```python
from eg_crypto import Keyring, RecordContext, encrypt, decrypt

kr = Keyring({kid: key}, kid)
ctx = RecordContext("acme", "field", "customers", "42", "email")
blob = encrypt(kr, ctx, b"ada@example.com")
assert decrypt(kr, ctx, blob) == b"ada@example.com"
```

`api/eg_crypto` is the Python package. `crates/encryptoglyph` is the Rust source of truth. Both check `testvectors/envelope.json`.

## Sidecar

Run the API (it also serves the console):

```bash
cd api
python -m pip install -r requirements.txt
BUILD_SHA="$(git rev-parse --short=12 HEAD)" python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

```python
import os
from encryptoglyph_client import Encryptoglyph

eg = Encryptoglyph(os.environ["EG_URL"])
eg.session()
sealed = eg.seal(
    {"tenant": "acme", "purpose": "field", "table": "customers", "record_id": "42", "field": "email"},
    b"ada@example.com",
)
```

The client is `sdk/python/encryptoglyph_client.py`. The browser equivalent is `sdk/js/encryptoglyph.js`. Set `EG_URL` to the sidecar origin. No secret belongs in the repo or in that environment variable.

A GoDesk app (GitGoat, RailYard, Portkyl, Komboe, Cerebro, or another service) vendors one client and calls `session` then `seal`. The same record context must be presented to open the blob.

## Updates

`VERSION` is the product version. `GET /v1/update` compares it with the public GitHub release for `GoDeskio/Encryptoglyph` and returns `update_available` without downloading anything.

```bash
python scripts/encryptoglyph-update.py --check
python scripts/encryptoglyph-update.py --download /tmp/encryptoglyph-next
```

The downloader accepts only `https://api.github.com/repos/GoDeskio/Encryptoglyph/tarball/<tag>`, checks the gzip header, and extracts into a new directory. It does not run the archive.

Tagged releases (`v*`) are checked by `.github/workflows/release.yml`, which fails if the tag disagrees with `VERSION`. Publishing the GitHub release is a separate maintainer step. This tree does not deploy.
