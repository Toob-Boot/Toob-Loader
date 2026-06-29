# Toob Registry — Production Architecture

## 1. Problem Statement

The current registry lives entirely on GitHub as `Toob-Boot/Toob-Registry`. Scripts, workflows, Go tooling, and actual hardware data (chips, drivers, crypto, arch) coexist in one repo. The CLI downloads ZIP archives directly from GitHub. This creates three critical risks:

1. **GitHub as SPOF** — If GitHub is down, no CLI can sync, no builds can resolve dependencies
2. **No immutability guarantee** — Git history can be force-pushed; no WORM protection
3. **Mixed concerns** — Internal CI scripts (`semver_calc.go`, `build_registry.go`) are public alongside consumable registry data

---

## 2. Repository Split

### Toob-Registry (Private Monorepo — existing)

The **internal development repo**. Stays as submodule of `Toob-Loader`. Contains everything:

```
Toob-Registry/                    (Private)
├── .github/workflows/            ← CI/CD pipelines
│   ├── main-release.yml
│   ├── pr-validator.yml
│   ├── version-index.yml
│   └── community-ingest.yml      ← [NEW] mirrors PRs from Public
├── scripts/                      ← Go build/release tooling
│   ├── build_registry.go
│   ├── semver_calc.go            ← becomes revision_calc.go
│   ├── matrix_generator.go
│   └── ...
├── chips/                        ← Hardware data (source of truth)
├── drivers/
├── crypto/
├── arch/
├── soc/
├── toolchains/
├── integrations/
├── registry.json                 ← Generated index
└── docs/
```

### Toob-Registry-Public (Public Read-Only Mirror — new)

The **community-facing repo**. Contains only consumable registry content. No scripts, no workflows (except the PR template).

```
Toob-Registry-Public/             (Public)
├── chips/
├── drivers/
├── crypto/
├── arch/
├── soc/
├── toolchains/
├── integrations/
├── registry.json
├── compatibility_matrix.json
├── CONTRIBUTING.md
└── README.md
```

### Sync Direction

```
Community PR ──► Toob-Registry-Public ──► community-ingest.yml
                                              │
                                              ▼
                                    Toob-Registry (Private)
                                         │ (merge + test)
                                         ▼
                                    Release Pipeline
                                         │
                            ┌────────────┼────────────┐
                            ▼            ▼            ▼
                     PostgreSQL    S3 Storage    Public Mirror
                     (metadata)   (tarballs)    (git push)
```

---

## 3. Infrastructure Topology

```
                         ┌──────────────────────┐
                         │   CLOUDFLARE CDN      │
                         │   (Edge Cache + WAF)  │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
          ┌─────────────────┐             ┌─────────────────┐
          │  API Server 1   │             │  API Server 2   │
          │  (Falkenstein)   │             │  (Helsinki)     │
          │  Go Binary       │             │  Go Binary       │
          │  CX22 ~4€/mo    │             │  CX22 ~4€/mo    │
          └────────┬────────┘             └────────┬────────┘
                   │                               │
                   └───────────┬───────────────────┘
                               │
                   ┌───────────┴───────────┐
                   ▼                       ▼
         ┌──────────────────┐    ┌──────────────────┐
         │ Managed Postgres │    │ Hetzner Object   │
         │ (Primary + RR)   │    │ Storage (S3)     │
         │ Metadata + Matrix│    │ WORM-Locked      │
         └──────────────────┘    │ .tar.gz Packages │
                                 └────────▲─────────┘
                                          │ Upload
                              ┌───────────┴──────────┐
                              │  Ephemeral Workers   │
                              │  (Nomad + Firecracker)│
                              │  CCX22 Dedicated CPU  │
                              │  On-Demand Scaling    │
                              └──────────────────────┘
```

### Component Roles

| Component | Purpose | Cost |
|---|---|---|
| **Cloudflare** (Free/Pro) | DDoS protection, edge caching of registry.json + tarballs, geo-routing to nearest API | ~0€ |
| **API Server ×2** (CX22) | Go API serving registry queries, tarball URLs, matrix lookups | ~8€/mo |
| **Managed PostgreSQL** | Package metadata, compatibility matrix, revision tracking | ~10€/mo |
| **S3 Object Storage** | Immutable tarball storage with WORM Object Locking | ~2€/mo base |
| **Build Workers** (CCX22) | Ephemeral Firecracker MicroVMs for compilation, pay-per-minute | Variable |

**Base cost without build load: ~20€/month**

---

## 4. Versioning: Monotonic Integer Revision

SemVer inheritance is replaced by a simple, monotonically increasing integer.

```
registry_revision: 1
registry_revision: 2   ← any change to any package
registry_revision: 3
...
```

Individual packages keep their own SemVer (e.g. `monocypher@1.2.1`), but the **global registry state** is tracked by a single integer. This simplifies sync logic enormously:

```
CLI: "I have revision 47"
API: "Current is 52. Here are the 5 changelog entries."
```

### PostgreSQL Schema (Core)

```sql
CREATE TABLE registry_revisions (
    revision    BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    commit_sha  TEXT NOT NULL,
    changelog   JSONB NOT NULL  -- [{package, old_version, new_version, bump_type}]
);

CREATE TABLE packages (
    name        TEXT PRIMARY KEY,
    category    TEXT NOT NULL,   -- 'chip', 'driver', 'crypto', 'arch', 'toolchain', 'integration'
    version     TEXT NOT NULL,
    revision    BIGINT REFERENCES registry_revisions(revision),
    manifest    JSONB NOT NULL,  -- full chip_manifest.json / driver manifest
    tarball_sha TEXT NOT NULL,
    tarball_url TEXT NOT NULL,   -- S3 presigned or CDN path
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE compatibility_matrix (
    id              BIGSERIAL PRIMARY KEY,
    chip            TEXT NOT NULL,
    chip_version    TEXT NOT NULL,
    env_hash        TEXT NOT NULL,
    dependencies    JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, VERIFIED, FAILED
    tested_at       TIMESTAMPTZ,
    revision        BIGINT REFERENCES registry_revisions(revision)
);
```

---

## 5. The PR-to-Release Security Pipeline

### Phase 1: Community Contribution (Public Repo)

1. Contributor opens PR against `Toob-Registry-Public`
2. GitHub Actions runs **read-only** linting (clang-tidy, manifest schema validation)
3. No secrets, no write access, no cache persistence

### Phase 2: Ingestion (Private Monorepo)

4. `community-ingest.yml` on `Toob-Registry` creates an isolated branch mirroring the PR changes
5. Ephemeral CI runner on Hetzner executes the full compatibility matrix dry-run:
   - Compile test against all affected chips × RTOS combinations
   - Static analysis (SAST) for crypto and HAL code
   - No artifacts uploaded, no DB writes
6. Results are posted back to the PR on `Toob-Registry-Public` via GitHub API

### Phase 3: Human Review Gate

7. Core team reviews the code on the private monorepo branch
8. **Four-eyes principle**: At least one certified maintainer must approve
9. Merge to `main` on `Toob-Registry`

### Phase 4: Atomic Release

10. `main-release.yml` triggers:
    - `revision_calc.go` increments the global revision integer
    - `build_registry.go` regenerates `registry.json`
    - Each changed package is tarball'd and **signed** (Ed25519 via KMS)
    - Tarballs uploaded to S3 with **Object Locking (WORM)**
    - Metadata written to PostgreSQL (atomic transaction)
    - Cloudflare cache purged for affected paths

### Phase 5: Distribution

11. `registry.json` committed to `Toob-Registry` main
12. Public mirror bot pushes content (no scripts) to `Toob-Registry-Public`
13. CLI users see new packages immediately via API or `toob registry sync`

---

## 6. API Server Design

### Endpoints

```
GET  /api/v1/registry/revision          → { "revision": 52 }
GET  /api/v1/registry/sync?since=47     → { "changes": [...], "revision": 52 }
GET  /api/v1/registry/index             → full registry.json (Cloudflare cached)

GET  /api/v1/resolve/chip?name=esp32c6  → chip manifest + tarball URL
GET  /api/v1/resolve/matrix             → compatibility matrix
GET  /api/v1/resolve/integrations       → available RTOS integrations

GET  /api/v1/package/{name}/download    → 302 redirect to S3 signed URL
GET  /api/v1/package/{name}/signature   → Ed25519 signature of tarball

POST /api/v1/admin/publish              → (authenticated) trigger release
POST /api/v1/admin/matrix-trigger       → (authenticated) retry failed matrix jobs
POST /api/v1/admin/cache-purge          → (authenticated) Cloudflare invalidation
```

### Cloudflare Caching Strategy

| Path Pattern | Cache TTL | Rationale |
|---|---|---|
| `/api/v1/registry/index` | 5 min | Frequently polled, tolerates slight staleness |
| `/api/v1/package/*/download` | 24h | Tarballs are immutable (WORM) |
| `/api/v1/registry/revision` | 30s | Lightweight polling endpoint |
| `/api/v1/resolve/*` | 2 min | Near-realtime for interactive CLI |

---

## 7. CLI Integration Changes

The CLI currently downloads ZIP archives from GitHub. The migration path:

### Current Flow
```
CLI → GitHub raw (version_index.json) → GitHub archive ZIP → local cache
```

### Target Flow
```
CLI → Cloudflare/API (revision check) → S3 tarball (per-package) → local cache
```

### Key Changes in `internal/registry/cache.go`

1. **`getLatestStableVersion()`** — Query `/api/v1/registry/revision` instead of GitHub raw
2. **`buildDownloadURL()`** — Return API package download URL instead of GitHub archive URL
3. **`Sync()`** — Differential sync: only download changed packages since last known revision
4. **`VerifyHead()`** — Verify Ed25519 signature of each tarball against embedded public key
5. **Fallback chain preserved**: API → GitHub mirror → local cache

### Backward Compatibility

The `registry.json` format stays identical. The CLI just changes *where* it fetches from. Old CLI versions still work via the GitHub mirror.

---

## 8. Build Worker Architecture

### Nomad + Firecracker

```
Build Request (API Queue)
        │
        ▼
   Nomad Scheduler
        │
        ▼
   Hetzner API: Spin up CCX22 (dedicated CPU)
        │
        ▼
   Firecracker MicroVM (ephemeral)
   ┌──────────────────────────────┐
   │  Minimal Linux Kernel        │
   │  toob-compiler Docker image  │
   │  Compile → tarball → S3     │
   │  Sign hash via KMS API      │
   └──────────────────────────────┘
        │
        ▼
   VM destroyed (zero state residue)
```

### Security Properties

- **Hardware isolation**: Firecracker uses KVM, not container namespaces
- **Network sandboxing**: Egress whitelist only (github.com, S3 endpoint, API server)
- **No shared caches**: Each MicroVM boots from a read-only rootfs
- **Ephemeral**: VM is destroyed after single job, no cross-contamination possible
- **OIDC tokens**: Short-lived credentials per job, no static secrets on workers

---

## 9. Security Model Summary

| Attack Vector | Mitigation |
|---|---|
| GitHub compromise | Registry data served from S3/PostgreSQL, not GitHub. Mirror is read-only |
| Cache poisoning | No shared caches. Ephemeral workers. Per-branch cache isolation |
| Tarball tampering | S3 WORM Object Locking. Ed25519 signatures verified by CLI |
| Token theft | OIDC short-lived tokens. No `pull_request_target`. Minimal GitHub permissions |
| Supply chain injection | Four-eyes review. Isolated CI dry-runs. No auto-merge |
| DDoS | Cloudflare WAF + rate limiting. API servers behind edge cache |
| Data exfiltration from builds | Firecracker isolation. Strict egress firewall |
| Single region failure | Multi-region API (Falkenstein + Helsinki). Cloudflare geo-routing |

---

## 10. Phased Rollout

### Phase 1: Repository Split (Week 1)
- Populate `Toob-Registry-Public` with content-only export from `Toob-Registry`
- Set up mirror bot (GitHub Action on private repo → push to public)
- Add `CONTRIBUTING.md` and PR templates to public repo

### Phase 2: API + Database (Week 2-3)
- Deploy Go API server on Hetzner CX22 (single region first)
- Set up Managed PostgreSQL, import current `registry.json` into SQL schema
- Wire Cloudflare DNS and caching rules

### Phase 3: S3 + Signatures (Week 3-4)
- Configure Hetzner Object Storage with WORM
- Implement tarball packaging + Ed25519 signing in release pipeline
- Migrate CLI to fetch from API (keep GitHub fallback)

### Phase 4: Second Region + Hardening (Week 5-6)
- Deploy API Server 2 in Helsinki
- Cloudflare load balancing between regions
- Integer revision system replaces SemVer inheritance

### Phase 5: Build Cloud (Week 7+)
- Nomad cluster on Hetzner
- Firecracker integration for ephemeral build workers
- Community PR ingestion pipeline (`community-ingest.yml`)

### Phase 6: OTA / Update Cloud (Future)
- Firmware delivery via same S3 + Cloudflare infrastructure
- Device fleet management API
- Rollout policies (canary, staged, geographic)
