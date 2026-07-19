package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/noviqtechnologies/agentwall/dashboard/api/internal/model"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

// UpsertAgent ensures the agent exists, updating last_seen_at on conflict.
func (s *Store) UpsertAgent(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (agent_id, first_seen_at, last_seen_at)
		VALUES ($1, now(), now())
		ON CONFLICT (agent_id) DO UPDATE SET
			last_seen_at = now(),
			updated_at   = now()
	`, agentID)
	return err
}

// InsertEvent persists a redacted event. Caller must UpsertAgent first.
func (s *Store) InsertEvent(ctx context.Context, e *model.RedactedEvent) error {
	dlp, _ := json.Marshal(e.DlpFindings)
	inj, _ := json.Marshal(e.InjectionFindings)
	sem, _ := json.Marshal(e.SemanticFindings)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO telemetry_events
			(event_id, timestamp_ms, session_id, agent_id, tool_name,
			 decision, dlp_findings, injection_findings, semantic_findings)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, e.EventID, e.TimestampMs, e.SessionID, e.AgentID, e.ToolName,
		e.Decision, dlp, inj, sem)
	return err
}

// InsertAlert persists an alert.
func (s *Store) InsertAlert(ctx context.Context, a *model.RedactedAlert) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (alert_id, severity, event_id)
		VALUES ($1, $2, $3)
	`, a.AlertID, a.Severity, a.Event.EventID)
	return err
}

// UpsertCredential persists or updates credential metadata.
func (s *Store) UpsertCredential(ctx context.Context, c *model.SanitizedCredentialMeta) error {
	history, _ := json.Marshal(c.RotationHistory)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO identity_credentials
			(credential_id, agent_id, scope, ttl_seconds,
			 created_at_ms, expires_at_ms, last_rotated_at_ms, rotation_history)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (credential_id) DO UPDATE SET
			scope              = EXCLUDED.scope,
			ttl_seconds        = EXCLUDED.ttl_seconds,
			expires_at_ms      = EXCLUDED.expires_at_ms,
			last_rotated_at_ms = EXCLUDED.last_rotated_at_ms,
			rotation_history   = EXCLUDED.rotation_history,
			updated_at         = now()
	`, c.CredentialID, c.AgentID, c.Scope, c.TTLSeconds,
		c.CreatedAtMs, c.ExpiresAtMs, c.LastRotatedAtMs, history)
	return err
}

// ── Read queries (Fleet Overview + Identity Governance) ────────────────────

type AgentSummary struct {
	AgentID       string    `json:"agent_id"`
	DisplayName   *string   `json:"display_name"`
	Status        string    `json:"status"`
	PolicyVersion *string   `json:"policy_version"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	EventCount    int64     `json:"event_count"`
	AlertCount    int64     `json:"alert_count"`
}

func (s *Store) ListAgents(ctx context.Context, limit, offset int) ([]AgentSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.agent_id,
			a.display_name,
			a.status,
			a.policy_version,
			a.last_seen_at,
			COALESCE(e.cnt, 0) AS event_count,
			COALESCE(al.cnt, 0) AS alert_count
		FROM agents a
		LEFT JOIN (
			SELECT agent_id, COUNT(*) AS cnt
			FROM telemetry_events
			GROUP BY agent_id
		) e ON e.agent_id = a.agent_id
		LEFT JOIN (
			SELECT te.agent_id, COUNT(*) AS cnt
			FROM alerts al
			JOIN telemetry_events te ON te.event_id = al.event_id
			GROUP BY te.agent_id
		) al ON al.agent_id = a.agent_id
		ORDER BY a.last_seen_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []AgentSummary
	for rows.Next() {
		var a AgentSummary
		if err := rows.Scan(&a.AgentID, &a.DisplayName, &a.Status,
			&a.PolicyVersion, &a.LastSeenAt, &a.EventCount, &a.AlertCount); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

type FleetStats struct {
	TotalAgents   int64 `json:"total_agents"`
	ActiveAgents  int64 `json:"active_agents"`
	TotalEvents   int64 `json:"total_events"`
	DeniedEvents  int64 `json:"denied_events"`
	TotalAlerts   int64 `json:"total_alerts"`
	CriticalAlerts int64 `json:"critical_alerts"`
}

func (s *Store) GetFleetStats(ctx context.Context) (*FleetStats, error) {
	var stats FleetStats
	err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM agents),
			(SELECT COUNT(*) FROM agents WHERE status = 'active'),
			(SELECT COUNT(*) FROM telemetry_events),
			(SELECT COUNT(*) FROM telemetry_events WHERE decision = 'denied'),
			(SELECT COUNT(*) FROM alerts),
			(SELECT COUNT(*) FROM alerts WHERE severity = 'critical')
	`).Scan(&stats.TotalAgents, &stats.ActiveAgents, &stats.TotalEvents,
		&stats.DeniedEvents, &stats.TotalAlerts, &stats.CriticalAlerts)
	return &stats, err
}

func (s *Store) ListRecentAlerts(ctx context.Context, limit int) ([]model.RedactedAlert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			a.alert_id, a.severity,
			e.event_id, e.timestamp_ms, e.session_id, e.agent_id,
			e.tool_name, e.decision,
			e.dlp_findings, e.injection_findings, e.semantic_findings
		FROM alerts a
		JOIN telemetry_events e ON e.event_id = a.event_id
		ORDER BY a.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []model.RedactedAlert
	for rows.Next() {
		var al model.RedactedAlert
		var dlpJSON, injJSON, semJSON []byte
		if err := rows.Scan(
			&al.AlertID, &al.Severity,
			&al.Event.EventID, &al.Event.TimestampMs, &al.Event.SessionID,
			&al.Event.AgentID, &al.Event.ToolName, &al.Event.Decision,
			&dlpJSON, &injJSON, &semJSON,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dlpJSON, &al.Event.DlpFindings)
		_ = json.Unmarshal(injJSON, &al.Event.InjectionFindings)
		_ = json.Unmarshal(semJSON, &al.Event.SemanticFindings)
		alerts = append(alerts, al)
	}
	return alerts, rows.Err()
}

type RecentEvent struct {
	model.RedactedEvent
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) ListRecentEvents(ctx context.Context, agentID string, limit int) ([]RecentEvent, error) {
	query := `
		SELECT event_id, timestamp_ms, session_id, agent_id, tool_name,
		       decision, dlp_findings, injection_findings, semantic_findings, created_at
		FROM telemetry_events
	`
	var args []any
	if agentID != "" {
		query += ` WHERE agent_id = $1 ORDER BY timestamp_ms DESC LIMIT $2`
		args = []any{agentID, limit}
	} else {
		query += ` ORDER BY timestamp_ms DESC LIMIT $1`
		args = []any{limit}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []RecentEvent
	for rows.Next() {
		var e RecentEvent
		var dlpJSON, injJSON, semJSON []byte
		if err := rows.Scan(
			&e.EventID, &e.TimestampMs, &e.SessionID, &e.AgentID,
			&e.ToolName, &e.Decision,
			&dlpJSON, &injJSON, &semJSON, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dlpJSON, &e.DlpFindings)
		_ = json.Unmarshal(injJSON, &e.InjectionFindings)
		_ = json.Unmarshal(semJSON, &e.SemanticFindings)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) ListCredentials(ctx context.Context, agentID string) ([]model.SanitizedCredentialMeta, error) {
	query := `
		SELECT credential_id, agent_id, scope, ttl_seconds,
		       created_at_ms, expires_at_ms, last_rotated_at_ms, rotation_history
		FROM identity_credentials
	`
	var args []any
	if agentID != "" {
		query += ` WHERE agent_id = $1 ORDER BY expires_at_ms ASC`
		args = []any{agentID}
	} else {
		query += ` ORDER BY expires_at_ms ASC`
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []model.SanitizedCredentialMeta
	for rows.Next() {
		var c model.SanitizedCredentialMeta
		var historyJSON []byte
		if err := rows.Scan(
			&c.CredentialID, &c.AgentID, &c.Scope, &c.TTLSeconds,
			&c.CreatedAtMs, &c.ExpiresAtMs, &c.LastRotatedAtMs, &historyJSON,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(historyJSON, &c.RotationHistory)
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// DecisionBreakdown returns counts per decision type for the heatmap.
type DecisionBreakdown struct {
	Hour     string `json:"hour"`
	Allowed  int64  `json:"allowed"`
	Denied   int64  `json:"denied"`
	Warned   int64  `json:"warned"`
}

func (s *Store) GetDecisionHeatmap(ctx context.Context, hours int) ([]DecisionBreakdown, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			to_char(to_timestamp(timestamp_ms / 1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:00') AS hour,
			COUNT(*) FILTER (WHERE decision = 'allowed') AS allowed,
			COUNT(*) FILTER (WHERE decision = 'denied')  AS denied,
			COUNT(*) FILTER (WHERE decision = 'warned')  AS warned
		FROM telemetry_events
		WHERE timestamp_ms > (EXTRACT(EPOCH FROM now()) * 1000 - $1 * 3600000)::BIGINT
		GROUP BY hour
		ORDER BY hour
	`, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var breakdown []DecisionBreakdown
	for rows.Next() {
		var b DecisionBreakdown
		if err := rows.Scan(&b.Hour, &b.Allowed, &b.Denied, &b.Warned); err != nil {
			return nil, err
		}
		breakdown = append(breakdown, b)
	}
	return breakdown, rows.Err()
}

// RunMigrations applies the SQL migration files. For Phase 1, this is a
// simple single-file apply. Phase 2 will switch to golang-migrate.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationSQL string) error {
	_, err := pool.Exec(ctx, migrationSQL)
	return err
}

// Transactional helper for ingest operations.
func (s *Store) InTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
