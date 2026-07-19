const BASE = '/api/v1'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

// Fleet Overview
export interface FleetStats {
  total_agents: number
  active_agents: number
  total_events: number
  denied_events: number
  total_alerts: number
  critical_alerts: number
}

export interface AgentSummary {
  agent_id: string
  display_name: string | null
  status: string
  policy_version: string | null
  last_seen_at: string
  event_count: number
  alert_count: number
}

export interface DecisionBreakdown {
  hour: string
  allowed: number
  denied: number
  warned: number
}

export interface RedactedEvent {
  event_id: string
  timestamp_ms: number
  session_id: string
  agent_id: string
  tool_name: string
  decision: string
  dlp_findings: { category: string; pattern_name: string; count: number }[]
  injection_findings: { pattern_name: string; count: number }[]
  semantic_findings: { anomaly_score: number; finding_type: string }[]
}

export interface RedactedAlert {
  alert_id: string
  severity: string
  event: RedactedEvent
}

// Identity Governance
export interface CredentialMeta {
  credential_id: string
  agent_id: string
  scope: string[]
  ttl_seconds: number
  created_at_ms: number
  expires_at_ms: number
  last_rotated_at_ms: number | null
  rotation_history: { rotated_at_ms: number; reason: string }[]
}

export const api = {
  getFleetOverview: () => get<FleetStats>('/fleet/overview'),
  listAgents: (limit = 50, offset = 0) =>
    get<AgentSummary[]>(`/fleet/agents?limit=${limit}&offset=${offset}`),
  getHeatmap: (hours = 24) =>
    get<DecisionBreakdown[]>(`/fleet/heatmap?hours=${hours}`),
  listEvents: (limit = 100) =>
    get<RedactedEvent[]>(`/fleet/events?limit=${limit}`),
  listRecentAlerts: (limit = 50) =>
    get<RedactedAlert[]>(`/alerts/recent?limit=${limit}`),
  listCredentials: (agentId?: string) =>
    get<CredentialMeta[]>(
      `/identity/credentials${agentId ? `?agent_id=${agentId}` : ''}`
    ),
}

// SSE stream for real-time alerts (AC-23.2).
export function subscribeAlerts(
  onAlert: (alert: RedactedAlert) => void,
  onError?: (err: Event) => void
): () => void {
  const es = new EventSource(`${BASE}/alerts/stream`)
  es.onmessage = (e) => {
    try {
      onAlert(JSON.parse(e.data))
    } catch { /* ignore malformed */ }
  }
  es.onerror = (e) => onError?.(e)
  return () => es.close()
}
