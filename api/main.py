import os

from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    build = os.environ.get("BUILD_SHA", "")[:12]
    return {"status": "ok", "build": build}
