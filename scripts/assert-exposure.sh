#!/usr/bin/env bash
# Build and start the API image, then prove /healthz is status+build only
# and that docs, redoc, openapi, and swagger are not served.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

image="encryptoglyph-api:exposure"
name="encryptoglyph-exposure-$$"
sha="0123456789abcdef0123456789abcdef"
expected="${sha:0:12}"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build -t "$image" -f api/Dockerfile api
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -e "BUILD_SHA=${sha}" "$image" >/dev/null

ready=0
for _ in $(seq 1 30); do
  if docker exec "$name" python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=2).read()' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "api container did not become ready" >&2
  docker logs "$name" >&2 || true
  exit 1
fi

docker exec -i "$name" python - "$expected" <<'PY'
import json
import sys
import urllib.error
import urllib.request

expected = sys.argv[1]
base = "http://127.0.0.1:8000"

with urllib.request.urlopen(base + "/healthz", timeout=5) as response:
    if response.status != 200:
        raise SystemExit(f"/healthz returned {response.status}")
    body = json.load(response)

if body != {"status": "ok", "build": expected}:
    raise SystemExit(f"/healthz body {body!r} != status+build only")

for path in ("/docs", "/redoc", "/openapi.json", "/swagger"):
    try:
        urllib.request.urlopen(base + path, timeout=5)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise SystemExit(f"{path} returned {exc.code}")
    else:
        raise SystemExit(f"{path} was reachable")

print("exposure ok")
PY
