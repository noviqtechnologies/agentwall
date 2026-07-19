package model

// Wire types mirroring dashboard-proto (Rust). The JSON field names match
// the Rust serde output exactly — snake_case enums, camelCase-free.
// AC-23.10: no field here accepts raw secret material.

type RedactedEvent struct {
	EventID           string                    `json:"event_id"`
	TimestampMs       int64                     `json:"timestamp_ms"`
	SessionID         string                    `json:"session_id"`
	AgentID           string                    `json:"agent_id"`
	ToolName          string                    `json:"tool_name"`
	Decision          string                    `json:"decision"`
	DlpFindings       []RedactedDlpFinding      `json:"dlp_findings"`
	InjectionFindings []RedactedInjectionFinding `json:"injection_findings"`
	SemanticFindings  []RedactedSemanticFinding  `json:"semantic_findings"`
}

type RedactedDlpFinding struct {
	Category    string `json:"category"`
	PatternName string `json:"pattern_name"`
	Count       uint32 `json:"count"`
}

type RedactedInjectionFinding struct {
	PatternName string `json:"pattern_name"`
	Count       uint32 `json:"count"`
}

type RedactedSemanticFinding struct {
	AnomalyScore float32 `json:"anomaly_score"`
	FindingType  string  `json:"finding_type"`
}

type RedactedAlert struct {
	AlertID  string        `json:"alert_id"`
	Severity string        `json:"severity"`
	Event    RedactedEvent `json:"event"`
}

type SanitizedCredentialMeta struct {
	CredentialID    string           `json:"credential_id"`
	AgentID         string           `json:"agent_id"`
	Scope           []string         `json:"scope"`
	TTLSeconds      uint64           `json:"ttl_seconds"`
	CreatedAtMs     int64            `json:"created_at_ms"`
	ExpiresAtMs     int64            `json:"expires_at_ms"`
	LastRotatedAtMs *int64           `json:"last_rotated_at_ms"`
	RotationHistory []RotationRecord `json:"rotation_history"`
}

type RotationRecord struct {
	RotatedAtMs int64  `json:"rotated_at_ms"`
	Reason      string `json:"reason"`
}

// Validation helpers.

var validDecisions = map[string]bool{
	"allowed": true,
	"denied":  true,
	"warned":  true,
}

var validSeverities = map[string]bool{
	"info":     true,
	"warning":  true,
	"critical": true,
}

func (e *RedactedEvent) Valid() bool {
	return e.EventID != "" &&
		e.SessionID != "" &&
		e.AgentID != "" &&
		e.ToolName != "" &&
		validDecisions[e.Decision]
}

func (a *RedactedAlert) Valid() bool {
	return a.AlertID != "" &&
		validSeverities[a.Severity] &&
		a.Event.Valid()
}
