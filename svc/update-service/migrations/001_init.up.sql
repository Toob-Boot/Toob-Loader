-- +goose Up
-- +goose StatementBegin

-- ============================================================================
-- UPD-010: Schema v1 — Toob Update Service
--
-- Tables: products, product_svn_floor, artifacts, releases,
--         devices, assignments, device_events
--
-- Design principles:
--   1. Critical invariants live in DB constraints, not application code.
--   2. device_events is append-only (enforced via GRANT, not schema).
--   3. All content-addressed digests are exactly 32 bytes (SHA-256).
--   4. Foreign keys enforce referential integrity at the DB level.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- products — registered product families
-- ---------------------------------------------------------------------------
CREATE TABLE products (
    id              TEXT        PRIMARY KEY,
    vendor_id       SMALLINT    NOT NULL,
    product_id      SMALLINT    NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (vendor_id, product_id)
);

-- ---------------------------------------------------------------------------
-- product_svn_floor — per-slot SVN monotonicity guard (§7.3)
--
-- App and Stage-1 have independent SVN lines. The Core enforces this
-- separation via ROLLBACK_TARGET_APP / _STAGE1 / _RECOVERY. A single
-- shared counter would either inflate the app floor or undercut stage-1.
-- ---------------------------------------------------------------------------
CREATE TABLE product_svn_floor (
    product         TEXT        NOT NULL REFERENCES products(id),
    target_slot     SMALLINT    NOT NULL,
    max_published_svn INTEGER  NOT NULL DEFAULT 0,

    PRIMARY KEY (product, target_slot)
);

-- ---------------------------------------------------------------------------
-- artifacts — content-addressed firmware blobs
--
-- Metadata is extracted from the signed TBM1 header at ingest time
-- (UPD-011, UPD-014). Operator inputs are plausibility checks only —
-- the artifact is the authority over itself.
-- ---------------------------------------------------------------------------
CREATE TABLE artifacts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product         TEXT        NOT NULL REFERENCES products(id),
    build_number    INTEGER     NOT NULL,
    kind            TEXT        NOT NULL CHECK (kind IN ('full', 'delta')),
    base_build      INTEGER,
    digest          BYTEA       NOT NULL,
    size_bytes      INTEGER     NOT NULL,
    svn             INTEGER     NOT NULL,
    stage1_svn      INTEGER     NOT NULL DEFAULT 0,
    key_index       SMALLINT    NOT NULL,
    hw_rev_min      SMALLINT    NOT NULL,
    hw_rev_max      SMALLINT    NOT NULL,
    min_reader_major SMALLINT   NOT NULL,
    min_reader_minor SMALLINT   NOT NULL,
    fw_ver_major    SMALLINT    NOT NULL,
    fw_ver_minor    SMALLINT    NOT NULL,
    fw_ver_patch    SMALLINT    NOT NULL,
    sbom_digest     BYTEA       NOT NULL,
    target_slot     SMALLINT    NOT NULL,
    image_count     SMALLINT    NOT NULL,
    admitted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- C1: delta artifacts must reference a base build; full artifacts must not.
    CHECK ((kind = 'delta') = (base_build IS NOT NULL)),

    -- C2: digest is always SHA-256 (32 bytes)
    CHECK (octet_length(digest) = 32),

    -- C3: sbom_digest is always SHA-256 (32 bytes)
    CHECK (octet_length(sbom_digest) = 32)
);

-- C4: build_number uniqueness per product+kind+base.
-- COALESCE(base_build, -1) because PostgreSQL UNIQUE treats each NULL
-- as distinct — two full-image artifacts for the same build would pass.
CREATE UNIQUE INDEX artifacts_build_unique
    ON artifacts (product, build_number, kind, COALESCE(base_build, -1));

-- ---------------------------------------------------------------------------
-- releases — atomic channel pointer
--
-- A release binds (product, channel) → artifact. The partial unique index
-- guarantees that at most one release is active per (product, channel).
-- Deactivation sets active=false and writes deactivated_at — the row is
-- never deleted (audit trail).
-- ---------------------------------------------------------------------------
CREATE TABLE releases (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    product         TEXT        NOT NULL REFERENCES products(id),
    channel         TEXT        NOT NULL DEFAULT 'stable',
    artifact_id     UUID        NOT NULL REFERENCES artifacts(id),
    active          BOOLEAN     NOT NULL DEFAULT true,
    activated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at  TIMESTAMPTZ
);

-- C5: at most one active release per (product, channel)
CREATE UNIQUE INDEX releases_one_active
    ON releases (product, channel) WHERE active = true;

-- ---------------------------------------------------------------------------
-- devices — enrolled devices (populated by UPD-030 Enrollment)
--
-- device_id = SHA-256(chip_uid ‖ root_pubkey ‖ "toob-device-id-v1"),
-- computed during provisioning (§4.1). token_hmac = HMAC-SHA256(server_key,
-- secret) for constant-time authentication (§7.1).
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    device_id       BYTEA       PRIMARY KEY,
    vendor_id       SMALLINT    NOT NULL,
    product_id      SMALLINT    NOT NULL,
    product         TEXT        NOT NULL REFERENCES products(id),
    hw_rev          SMALLINT    NOT NULL,
    key_index       SMALLINT    NOT NULL,
    staging_capacity INTEGER    NOT NULL,
    reader_major    SMALLINT    NOT NULL,
    reader_minor    SMALLINT    NOT NULL,
    channel         TEXT        NOT NULL DEFAULT 'stable',
    token_hmac      BYTEA       NOT NULL,
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checkin_at TIMESTAMPTZ,
    health          TEXT        NOT NULL DEFAULT 'ok'
        CHECK (health IN ('ok', 'suspect', 'quarantined')),

    -- device_id is always SHA-256 (32 bytes)
    CHECK (octet_length(device_id) = 32),

    -- token_hmac is always HMAC-SHA256 (32 bytes)
    CHECK (octet_length(token_hmac) = 32)
);

-- ---------------------------------------------------------------------------
-- assignments — desired-state binding (device → artifact)
--
-- The partial unique index enforces that a device can have at most one
-- non-terminal assignment. Terminal states: confirmed, failed, superseded.
-- ---------------------------------------------------------------------------
CREATE TABLE assignments (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       BYTEA       NOT NULL REFERENCES devices(device_id),
    artifact_id     UUID        NOT NULL REFERENCES artifacts(id),
    state           TEXT        NOT NULL DEFAULT 'offered'
        CHECK (state IN ('offered', 'downloading', 'staged',
                         'confirmed', 'failed', 'superseded')),
    attempts        SMALLINT    NOT NULL DEFAULT 0,
    source          TEXT        NOT NULL DEFAULT 'resolver'
        CHECK (source IN ('resolver', 'pin')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- C6: at most one open (non-terminal) assignment per device
CREATE UNIQUE INDEX assignments_one_open
    ON assignments (device_id)
    WHERE state IN ('offered', 'downloading', 'staged');

-- ---------------------------------------------------------------------------
-- device_events — append-only audit log
--
-- No UPDATE/DELETE grant is given to the application role (toob_svc).
-- This is enforced at the GRANT level, not in the schema, because
-- CHECK constraints cannot restrict DML operations.
-- ---------------------------------------------------------------------------
CREATE TABLE device_events (
    id              BIGSERIAL   PRIMARY KEY,
    device_id       BYTEA       NOT NULL,
    event_type      TEXT        NOT NULL,
    payload         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_device_events_device
    ON device_events (device_id, created_at);

-- ---------------------------------------------------------------------------
-- Application role permissions (idempotent, safe to re-run)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'toob_svc') THEN
        CREATE ROLE toob_svc WITH LOGIN;
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE ON products, product_svn_floor, artifacts,
    releases, devices, assignments TO toob_svc;

-- Append-only: SELECT + INSERT only, no UPDATE/DELETE
GRANT SELECT, INSERT ON device_events TO toob_svc;
GRANT USAGE, SELECT ON SEQUENCE device_events_id_seq TO toob_svc;

-- +goose StatementEnd
