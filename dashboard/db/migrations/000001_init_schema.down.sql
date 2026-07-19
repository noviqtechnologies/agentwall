BEGIN;

DROP TABLE IF EXISTS identity_credentials;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS telemetry_events;
DROP TABLE IF EXISTS agents;

DROP TYPE IF EXISTS agent_status;
DROP TYPE IF EXISTS alert_severity;
DROP TYPE IF EXISTS event_decision;

COMMIT;
