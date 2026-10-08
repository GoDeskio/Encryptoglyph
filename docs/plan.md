# Encryptoglyph build plan (2026-10-08)

- **Codename history:** researched as "Hieroglyph" (Research/2026-10-05-hieroglyph-encryption-product-research.md). Dustin prefers **Encryptoglyph**. On 10/5, encryptoglyph.com/.io/.dev and GitHub `encryptoglyph` appeared free (not authoritative; confirm at a registrar and run a USPTO/EUIPO search before buying).
- **Repo status (checked 2026-10-07 ~9:25 PM PT):** `GoDeskio/Encryptoglyph` is **not visible** to the Cursor GitHub app (`scm_repo_not_accessible`). A GoDeskio search for glyph/encrypt/crypt/vault repos returns nothing. Treat it as **not created**. The agents have no sanctioned way to create a GitHub repo. **Richard or Dustin must create an empty private `GoDeskio/Encryptoglyph`** (default branch `main`, no template) and grant it to the Cursor GitHub app. After that, a CloudAgent pushes the scaffold PR in §9.
- **Owners:** Jonathan (software: API, UI, agent, SDKs) and Richard (deploy and infra: OpenBao ops, PKI, Traefik, backups). Dustin decides the items in §10.
- Not legal advice. Counsel should review licensing, export, and HIPAA/BAA before anything is sold.

## 1. What it is
It's one console for encryption at rest, key custody, and encrypted backup. It's built for MSPs (GoDesk first), self-hostable on Proxmox, or hosted by GoDesk. It produces insurer- and auditor-ready evidence.

The tenant model is **tenant → site → device**. Each tenant gets an OpenBao namespace. Each site gets a Transit KEK, a restic repo key, an age keypair, and a blind-index HMAC key.

## 2. Architecture
```
            Traefik (HTTPS, house certs) ── Authentik/Authelia forward-auth (admin UI only)
                        │
      ┌─────────────────┴──────────────────┐
      │  eg-console (Node/TS, Next or Vite SPA)   ← GoDesk-proprietary
      │  eg-api (Python FastAPI)                  ← GoDesk-proprietary: RBAC, audit, orchestration
      │  eg-worker (Python, same image)           ← schedules: backups, rotation, restore tests
      └───────┬────────────────────┬───────┘
              │ Vault-compatible   │ Postgres (app state, audit index)
              ▼ HTTP API (mTLS)    ▼
         OpenBao (MPL-2.0)      postgres:16
         - namespace per tenant
         - transit: per-site KEK (datakey/rotate/rewrap), per-tenant HMAC index key
         - kv-v2: age secret keys, recovery keys (BitLocker/LUKS), restic repo passwords (wrapped)
         - audit device → file → Loki
              ▲
              │ AppRole / cert auth, mTLS
      eg-agent (Go or Python single binary) on hosts
         Linux: cryptsetup/LUKS2 status, Clevis/Tang (CLI only, unmodified GPL tools)
         Proxmox: ZFS encryption status, PBS client-side enc status
         Windows (v1): BitLocker via PowerShell, escrow recovery password
         Files: age (escrow bundles), gocryptfs (live folders, Linux)
         Backup: restic → rest-server (LAN) + `restic copy` → S3-compatible off-site w/ object lock
      SDKs: python (Tink AEAD + blind index), node (node:crypto AES-256-GCM / libsodium + blind index)
```
Rules:
- OpenBao, Postgres, and rest-server are **never** on `proxy-net`. Only `eg-console` and `eg-api` get Traefik labels. Nothing publishes host ports, and nothing is bare-LAN published.
- Secrets reach containers through `env_file` (gitignored), never through git. The OpenBao unseal and recovery shares live **offline** (Sam/Proton Pass plus paper in the safe), never on the box.
- `/healthz` returns only `{"status":"ok","build":"<sha12>"}`. There's no `/docs`, `/openapi.json`, swagger, or redoc in production (FastAPI `docs_url=None, redoc_url=None, openapi_url=None`). The Public site exposure check must PASS before and after every deploy.

## 3. MVP scope (target ~8–10 weeks, 2 people)
In:
1. OpenBao in Docker: a single node with file storage plus Raft-ready config, the audit device on, and a namespace per tenant. Transit has one KEK per site with a rotation policy, plus a tenant HMAC key for blind indexes.
2. eg-api: tenants, sites, devices, and keys (metadata only; key material stays in OpenBao). An escrow-retrieval request with **two-person approval** and an audit log. Backup policy CRUD.
3. restic orchestration: per-site repo, the password is a random DEK wrapped by the site KEK, schedules, `forget --keep-*` retention, off-site `restic copy`, and a weekly automated restore test with a stored evidence record.
4. age: per-site keypair generation. The secret key goes in KV. Escrow bundles go to recipients = site key + GoDesk recovery key.
5. eg-agent v0 (Linux/Proxmox): enrol over mTLS, report LUKS/ZFS status, run restic jobs, escrow LUKS recovery material.
6. Console v0: tenants, sites, devices, key inventory with rotation status, backup health, restore-test results, and escrow approvals.
7. Python SDK v0: envelope encryption (DEK AES-256-GCM via Tink, wrapped by Transit `datakey`), a key-version header, and a blind index (truncated HMAC-SHA256 of the normalised value).
8. Dogfood on GoDesk's own stack. Candidates: the restic rest-server on web-g3, the DATA_KEKs/age keys the sites use today, and Mongo dumps.

Out of MVP (v1+): the Windows/BitLocker agent, the Node SDK, the rotation orchestrator with bulk rewrap, Clevis/Tang, compliance report packs, SSO/RBAC beyond admin/operator/auditor, white-labelling, billing/metering, HSM, Kopia/PBS integrations, and RMM/PSA integrations.

## 4. Milestones
| # | Milestone | Exit criteria |
|---|---|---|
| M0 | Repo + scaffold (after the repo exists) | README/plan, `docker-compose.yml` skeleton (openbao, postgres, eg-api, eg-console, rest-server; only api/console on proxy-net), `.env.example`, CI (lint, unit, compose config, exposure probe, secret scan), LICENSE marked TODO for Dustin |
| M1 (wk 1–2) | KMS core | OpenBao dev/prod compose profiles, init/unseal runbook, namespace + transit + kv bootstrap script, audit to Loki, OpenBao snapshot backup |
| M2 (wk 2–4) | API + data model | FastAPI with tenants/sites/devices/keys, AppRole for the API, mTLS PKI (step-ca), audit table, escrow request + dual approval, tests |
| M3 (wk 3–6) | Backup | restic orchestration, wrapped repo passwords, retention, off-site copy to an S3-compatible bucket with object lock, restore-test job + evidence |
| M4 (wk 5–8) | Agent v0 + SDK v0 | Linux/Proxmox agent enrolment + status + restic runner; Python SDK published to the internal index with docs and test vectors |
| M5 (wk 7–10) | Console v0 + dogfood | Console behind Traefik + forward-auth, GoDesk tenant live on GoDesk3, first quarterly KEK rotation rehearsal, KMS DR test (restore OpenBao from snapshot on a clean VM) |
| M6 | Pre-sale gate | Third-party pentest, counsel review (license, export ENC, BAA template), pricing validated with 5–10 MSP interviews |

## 5. Repo layout (proposed)
```
Encryptoglyph/
  README.md                 # product summary + link to this plan
  docs/plan.md              # this file
  docs/architecture.md, docs/runbooks/{openbao-init,unseal,dr,rotation}.md
  deploy/
    docker-compose.yml      # openbao, postgres, eg-api, eg-worker, eg-console, rest-server
    docker-compose.dev.yml  # dev-mode OpenBao, seeded tenant
    traefik-labels.md       # labels documented; proxy-net external
    openbao/config.hcl, openbao/policies/*.hcl, openbao/bootstrap.sh
    .env.example            # names only, no values
  api/                      # Python 3.12 FastAPI (eg-api + eg-worker)
  console/                  # TypeScript UI
  agent/                    # Go (preferred for single static binary) or Python
  sdk/python/, sdk/node/    # node is v1
  scripts/assert-exposure.sh  # /docs,/openapi.json,/swagger,/redoc → 404; /healthz → ok+build only
  .github/workflows/ci.yml  # lint, test, compose config, exposure, gitleaks
  LICENSE                   # TODO(Dustin)
  THIRD_PARTY_NOTICES.md
```

## 6. License guardrails
- **OpenBao (MPL-2.0):** use the unmodified upstream image. Any change goes in a plugin or a separate file, or is upstreamed. If we distribute modified MPL files, we publish their source.
- **Permissive deps (fine to embed):** restic BSD-2, age BSD-3, gocryptfs MIT, Tink Apache-2.0, libsodium ISC, SOPS MPL-2.0 (optional).
- **GPL tools** (cryptsetup, Clevis/Tang): the agent calls them as separate, unmodified OS programs. Never link or vendor them.
- **Never pull in:** HashiCorp Vault ≥1.15 or Cosmian KMS (BUSL-1.1), or Vault Enterprise plugins.
- **AGPL** (Cryptomator Hub, PBS, Teleport): don't fork or host-modify. Integrate only through their documented client APIs, or buy a license.
- **VeraCrypt** (TrueCrypt License 3.0): don't bundle it without counsel.
- **Trademarks:** don't brand anything "OpenBao" or "restic". Attribute them in THIRD_PARTY_NOTICES.md.
- **Our crypto:** use only vetted AEADs (Tink, libsodium, node:crypto AES-GCM). No custom primitives. Publish the SDK design and get it reviewed.
- **Export:** standard crypto only, which avoids the 742.15(b) notification. Commercial binaries/SaaS need an ENC/mass-market self-classification before the first sale (counsel).
- **CI:** gitleaks plus a license scan (e.g. `licensee`/`go-licenses`/`pip-licenses`) that fails on BUSL/AGPL in the dependency tree.

## 7. Self-hosting on GoDesk3
- **VM:** a dedicated Proxmox VM on GoDesk3 (not an LXC, so OpenBao gets mlock and memory isolation). Suggested: 2 vCPU, 4 GB RAM, a 40 GB disk on LUKS2. Not on Jonathan (RAM is tight).
- **Ingress:** house Traefik with HTTPS only. Hostnames TBD (e.g. `eg.home.arpa` LAN-only for the console at first). There's **no public exposure** until the M6 pentest. Public exposure would need a Cloudflare tunnel route plus a Dustin decision. Admin routes sit behind forward-auth.
- **IdP:** the brief says Authentik, and the 10/7 notes show authentik running. The NetBox research note says the house IdP is Authelia. **Confirm which one fronts admin apps** (decision in §10). The console also does its own RBAC.
- **OpenBao exposure:** OpenBao listens only on an internal Docker network plus an mTLS listener for agents on the LAN (Traefik TCP passthrough with SNI, or a dedicated LAN-only entrypoint, per Richard). It's never on proxy-net HTTP.
- **Backups:** daily OpenBao Raft snapshots, age-encrypted to the recovery key, go to D: and the PBS sync. Postgres dump the same way. Each month, restore OpenBao into a scratch VM as a DR test.
- **Unseal:** MVP uses Shamir 3-of-5. Shares go to Dustin, Sam, Richard, and two offline media. Auto-unseal (transit-on-second-OpenBao, or an HSM in v2) is a later decision.
- **Monitoring:** Kuma on `/healthz` and the OpenBao `sys/health` (internal). Audit log to Loki, with Grafana alerts on unseal events, root token use, and escrow reveals.

## 8. Risks to manage from day one
- **Key custody liability:** GoDesk becomes a HIPAA business associate for any healthcare tenant. Use per-tenant namespaces, dual control on reveal, separate key storage from backup storage, and a customer-held break-glass key.
- **KMS outage = no unlocks/restores:** test HA/DR before any customer goes live.
- **Proxmox ZFS native encryption is "experimental":** prefer LUKS under ZFS.
- **Upstream advisories** (OpenBao, restic, Kopia): subscribe and ship fast updates.

## 9. Scaffold PR (CloudAgent brief, runs once the empty repo exists)
Repo GoDeskio/Encryptoglyph, base `main`. Open ONE ready-for-review PR "Scaffold Encryptoglyph (plan, compose skeleton, CI)". It contains:
- README.md (summary + link to docs/plan.md, which is a copy of this file)
- deploy/docker-compose.yml: openbao (official `openbao/openbao` image pinned by digest, `cap_add: IPC_LOCK`, internal network only), postgres:16 (internal), eg-api and eg-console placeholders (Traefik labels with `traefik.enable=true`, websecure entrypoint, TLS, `proxy-net` external), rest-server (internal). No `ports:` anywhere. `env_file: .env` (gitignored) and a committed `.env.example` with names only.
- api/ minimal FastAPI with only `/healthz` → `{"status":"ok","build":BUILD_SHA[:12]}`, docs/openapi disabled, plus a pytest.
- scripts/assert-exposure.sh, plus CI (.github/workflows/ci.yml): lint, pytest, `docker compose config -q`, exposure probe against the api container, gitleaks.
- LICENSE containing only `TODO(Dustin): choose license (proprietary/All rights reserved vs source-available)`, plus THIRD_PARTY_NOTICES.md.
- Rules: no secrets, no deploy, no repo settings or branch-protection changes, no merge. Get CI green and report PR URL + head SHA + CI per job.

## 10. Decisions needed from Dustin
1. **Create the repo** `GoDeskio/Encryptoglyph` (private, empty, `main`) and grant it to the Cursor GitHub app, or have Richard do it. This blocks M0.
2. **Name:** buy encryptoglyph.com/.io/.dev after a registrar check and a trademark search?
3. **License for GoDesk-owned code:** proprietary (all rights reserved) vs source-available (e.g. FSL/BSL-style with an Apache change date) vs open-core. This affects the SDK license too (permissive SDKs help adoption).
4. **IdP** for admin apps: Authentik or Authelia.
5. **Agent language:** Go (single static binary, matches OpenBao/restic/age) vs Python (team familiarity).
6. **Hosting model for the first customers:** GoDesk-hosted multi-tenant vs per-customer appliance VM.
7. **Unseal custody:** who holds the 5 Shamir shares, and when auto-unseal/HSM comes in.
8. **Priority vs other work:** MVP is ~16–20 person-weeks. Start date, and whether Windows/BitLocker (the biggest market gap since MBAM ended) gets pulled into the MVP.
9. **Counsel budget:** license/export/BAA review before the first sale. Also the pentest vendor and budget before GA.
