import { useEffect, useState } from 'react'
import { api, type CredentialMeta } from '../api/client'

function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString([], {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function ttlDisplay(seconds: number): string {
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

function expiryStatus(expiresAtMs: number): { label: string; cls: string } {
  const remaining = expiresAtMs - Date.now()
  if (remaining <= 0) return { label: 'Expired', cls: 'danger' }
  if (remaining < 3600_000) return { label: 'Expiring soon', cls: 'warning' }
  return { label: 'Active', cls: 'success' }
}

const REASON_LABELS: Record<string, string> = {
  scheduled: 'Scheduled',
  manual: 'Manual',
  compromise: 'Compromise',
  policy_change: 'Policy Change',
}

export default function IdentityGovernance() {
  const [credentials, setCredentials] = useState<CredentialMeta[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.listCredentials()
      .then(setCredentials)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="loading">Loading identity data</div>

  return (
    <>
      <div className="page-header">
        <h1>Identity Governance</h1>
        <p>Agent credentials, scopes, TTLs, and rotation history (read-only)</p>
      </div>

      {/* Summary stats */}
      <div className="stats-grid">
        <div className="card stat-tile">
          <div className="stat-value">{credentials.length}</div>
          <div className="stat-label">Total Credentials</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {credentials.filter(c => c.expires_at_ms > Date.now()).length}
          </div>
          <div className="stat-label">Active</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--danger)' }}>
            {credentials.filter(c => c.expires_at_ms <= Date.now()).length}
          </div>
          <div className="stat-label">Expired</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--warning)' }}>
            {credentials.filter(c => {
              const remaining = c.expires_at_ms - Date.now()
              return remaining > 0 && remaining < 3600_000
            }).length}
          </div>
          <div className="stat-label">Expiring Soon</div>
        </div>
      </div>

      {/* Credential cards */}
      {credentials.length === 0 ? (
        <div className="card empty-state">No credentials registered</div>
      ) : (
        <div className="cred-grid">
          {credentials.map((c) => {
            const status = expiryStatus(c.expires_at_ms)
            return (
              <div className="card cred-card" key={c.credential_id}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div className="cred-id">{c.credential_id}</div>
                  <span className={`badge badge-${status.cls}`}>{status.label}</span>
                </div>

                <div className="cred-scope">
                  {c.scope.map((s) => (
                    <span className="scope-tag" key={s}>{s}</span>
                  ))}
                </div>

                <div className="cred-detail" style={{ marginTop: 12 }}>
                  <span>Agent</span>
                  <span>{c.agent_id}</span>
                </div>
                <div className="cred-detail">
                  <span>TTL</span>
                  <span>{ttlDisplay(c.ttl_seconds)}</span>
                </div>
                <div className="cred-detail">
                  <span>Created</span>
                  <span>{formatDate(c.created_at_ms)}</span>
                </div>
                <div className="cred-detail">
                  <span>Expires</span>
                  <span>{formatDate(c.expires_at_ms)}</span>
                </div>
                {c.last_rotated_at_ms && (
                  <div className="cred-detail">
                    <span>Last Rotated</span>
                    <span>{formatDate(c.last_rotated_at_ms)}</span>
                  </div>
                )}

                {/* Rotation history */}
                {c.rotation_history.length > 0 && (
                  <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                    <div className="card-title" style={{ marginBottom: 8 }}>Rotation History</div>
                    {c.rotation_history.map((r, i) => (
                      <div className="cred-detail" key={i}>
                        <span>{REASON_LABELS[r.reason] || r.reason}</span>
                        <span>{formatDate(r.rotated_at_ms)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </>
  )
}
