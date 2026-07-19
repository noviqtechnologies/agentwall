import { useEffect, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
} from 'recharts'
import {
  api, subscribeAlerts,
  type FleetStats, type AgentSummary, type DecisionBreakdown, type RedactedAlert,
} from '../api/client'

const DECISION_COLORS: Record<string, string> = {
  allowed: '#22c55e',
  denied: '#ef4444',
  warned: '#f59e0b',
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'danger',
  warning: 'warning',
  info: 'info',
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function FleetOverview() {
  const [stats, setStats] = useState<FleetStats | null>(null)
  const [agents, setAgents] = useState<AgentSummary[]>([])
  const [heatmap, setHeatmap] = useState<DecisionBreakdown[]>([])
  const [alerts, setAlerts] = useState<RedactedAlert[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.getFleetOverview(),
      api.listAgents(),
      api.getHeatmap(),
      api.listRecentAlerts(),
    ]).then(([s, a, h, al]) => {
      setStats(s)
      setAgents(a)
      setHeatmap(h)
      setAlerts(al)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  // Real-time alert stream (AC-23.2).
  useEffect(() => {
    const unsub = subscribeAlerts((alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 100))
      // Bump stats counters optimistically.
      setStats((prev) =>
        prev ? {
          ...prev,
          total_alerts: prev.total_alerts + 1,
          critical_alerts:
            alert.severity === 'critical'
              ? prev.critical_alerts + 1
              : prev.critical_alerts,
        } : prev
      )
    })
    return unsub
  }, [])

  if (loading) return <div className="loading">Loading fleet data</div>

  return (
    <>
      <div className="page-header">
        <h1>Fleet Overview</h1>
        <p>Real-time agent activity, policy decisions, and security alerts</p>
      </div>

      {/* Stat tiles */}
      {stats && (
        <div className="stats-grid">
          <div className="card stat-tile">
            <div className="stat-value">{stats.total_agents}</div>
            <div className="stat-label">Total Agents</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.active_agents}</div>
            <div className="stat-label">Active</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value">{stats.total_events.toLocaleString()}</div>
            <div className="stat-label">Total Events</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.denied_events.toLocaleString()}</div>
            <div className="stat-label">Denied</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: 'var(--warning)' }}>{stats.total_alerts}</div>
            <div className="stat-label">Alerts</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.critical_alerts}</div>
            <div className="stat-label">Critical</div>
          </div>
        </div>
      )}

      {/* Decision heatmap */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title">Decision Heatmap (24h)</div>
        {heatmap.length > 0 ? (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={heatmap}>
              <XAxis
                dataKey="hour"
                tick={{ fill: '#5a5a6e', fontSize: 11 }}
                tickFormatter={(v: string) => v.split(' ')[1] || v}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#5a5a6e', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#1a1a24',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: 8,
                  fontSize: 13,
                }}
              />
              <Bar dataKey="allowed" stackId="a" fill={DECISION_COLORS.allowed} radius={[0, 0, 0, 0]} />
              <Bar dataKey="warned" stackId="a" fill={DECISION_COLORS.warned} />
              <Bar dataKey="denied" stackId="a" fill={DECISION_COLORS.denied} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">No events in the last 24 hours</div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {/* Agents table */}
        <div className="card">
          <div className="card-title">Agents</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Alerts</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {agents.length === 0 ? (
                  <tr><td colSpan={5} className="empty-state">No agents registered</td></tr>
                ) : agents.map((a) => (
                  <tr key={a.agent_id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{a.agent_id}</td>
                    <td>
                      <span className={`badge badge-${a.status === 'active' ? 'success' : a.status === 'revoked' ? 'danger' : 'warning'}`}>
                        {a.status}
                      </span>
                    </td>
                    <td>{a.event_count.toLocaleString()}</td>
                    <td>{a.alert_count}</td>
                    <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{timeAgo(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Alert feed */}
        <div className="card">
          <div className="card-title">Alert Feed (Live)</div>
          <div className="alert-feed">
            {alerts.length === 0 ? (
              <div className="empty-state">No alerts</div>
            ) : alerts.map((a) => (
              <div className="alert-item" key={a.alert_id}>
                <div className={`alert-dot ${a.severity}`} />
                <div className="alert-body">
                  <div className="alert-title">
                    {a.event.dlp_findings.length > 0
                      ? `DLP: ${a.event.dlp_findings.map(f => f.category).join(', ')}`
                      : a.event.injection_findings.length > 0
                        ? `Injection: ${a.event.injection_findings.map(f => f.pattern_name).join(', ')}`
                        : a.event.semantic_findings.length > 0
                          ? `Semantic: ${a.event.semantic_findings.map(f => f.finding_type).join(', ')}`
                          : `${a.event.decision} — ${a.event.tool_name}`
                    }
                  </div>
                  <div className="alert-meta">
                    {a.event.agent_id} &middot; {a.event.tool_name} &middot; {formatTime(a.event.timestamp_ms)}
                  </div>
                </div>
                <span className={`badge badge-${SEVERITY_CLASS[a.severity] || 'info'}`}>
                  {a.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}
