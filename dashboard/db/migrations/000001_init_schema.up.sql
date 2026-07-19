-- FR-23 Phase 1 schema: Fleet Overview + Identity Governance (read-only).
-- All data originates from the gateway via dashboard-api ingest endpoints.
-- AC-23.10: no column in this schema accepts raw secret material, tool-call
-- parameters, response bodies, or DLP match content.

BEGIN;

-- Enum types matching dashboard-proto wire format (snake_case).
CREATE TYPE event_decision AS ENUM ('allowed', 'denied', 'warned');
CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'critical');
CREATE TYPE agent_status   AS ENUM ('active', 'inactive', 'revoked');

-- ─── agents ────────────────────────────────────────────────────────────────────
-- Auto-registered on first event ingest. The gateway is the source of truth
-- for which agents exist; the dashboard never creates agents independently.
CREATE TABLE agents (
    agent_id       TEXT          PRIMARY KEY,  -- OIDC sub claim
    display_name   TEXT,
    status         agent_status  NOT NULL DEFAULT 'active',
    policy_version TEXT,
    first_seen_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX idx_agents_status      ON agents (status);
CREATE INDEX idx_agents_last_seen   ON agents (last_seen_at DESC);

-- ─── telemetry_events ──────────────────────────────────────────────────────────
-- Redacted events from the gateway. dlp/injection/semantic findings are stored
-- as JSONB arrays of typed objects (category + pattern_name + count), never
-- raw match content.
CREATE TABLE telemetry_events (
    event_id            UUID          PRIMARY KEY,
    timestamp_ms        BIGINT        NOT NULL,
    session_id          TEXT          NOT NULL,
    agent_id            TEXT          NOT NULL REFERENCES agents(agent_id),
    tool_name           TEXT          NOT NULL,
    decision            event_decision NOT NULL,
    dlp_findings        JSONB         NOT NULL DEFAULT '[]',
    injection_findings  JSONB         NOT NULL DEFAULT '[]',
    semantic_findings   JSONB         NOT NULL DEFAULT '[]',
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_agent_time  ON telemetry_events (agent_id, timestamp_ms DESC);
CREATE INDEX idx_events_decision    ON telemetry_events (decision);
CREATE INDEX idx_events_timestamp   ON telemetry_events (timestamp_ms DESC);
CREATE INDEX idx_events_session     ON telemetry_events (session_id);

-- ─── alerts ────────────────────────────────────────────────────────────────────
-- Real-time alerts derived from events. One event can produce multiple alerts
-- (e.g. DLP finding + injection finding in the same tool call).
CREATE TABLE alerts (
    alert_id    UUID            PRIMARY KEY,
    severity    alert_severity  NOT NULL,
    event_id    UUID            NOT NULL REFERENCES telemetry_events(event_id),
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_severity_time ON alerts (severity, created_at DESC);
CREATE INDEX idx_alerts_event         ON alerts (event_id);

-- ─── identity_credentials ──────────────────────────────────────────────────────
-- Credential metadata only. The credential value itself is never stored here
-- (AC-23.10). rotation_history is a JSONB array of {rotated_at_ms, reason}.
CREATE TABLE identity_credentials (
    credential_id      TEXT      PRIMARY KEY,
    agent_id           TEXT      NOT NULL REFERENCES agents(agent_id),
    scope              TEXT[]    NOT NULL DEFAULT '{}',
    ttl_seconds        BIGINT   NOT NULL,
    created_at_ms      BIGINT   NOT NULL,
    expires_at_ms      BIGINT   NOT NULL,
    last_rotated_at_ms BIGINT,
    rotation_history   JSONB    NOT NULL DEFAULT '[]',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_credentials_agent   ON identity_credentials (agent_id);
CREATE INDEX idx_credentials_expiry  ON identity_credentials (expires_at_ms);

COMMIT;
