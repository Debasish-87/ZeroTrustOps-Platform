import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

const API = '/api'

const SEV_COLOR = {
  CRITICAL: '#f85149', HIGH: '#f0883e',
  MEDIUM: '#d29922',   LOW: '#58a6ff', INFO: '#8b949e'
}

function StatCard({ label, value, color, icon }) {
  return (
    <div style={{
      background: 'var(--bg2)', border: '1px solid var(--border)',
      borderLeft: `3px solid ${color}`, borderRadius: 'var(--radius)',
      padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14
    }}>
      <span style={{ fontSize: 28 }}>{icon}</span>
      <div>
        <div style={{ fontSize: 28, fontWeight: 800, color, lineHeight: 1 }}>{value ?? '—'}</div>
        <div style={{ fontSize: 11, color: 'var(--text2)', textTransform: 'uppercase',
                      letterSpacing: '0.5px', marginTop: 3 }}>{label}</div>
      </div>
    </div>
  )
}

function GateBadge({ gate }) {
  if (!gate) return <span style={{ color: 'var(--text2)' }}>—</span>
  const ok = gate === 'PASS'
  return (
    <span style={{
      background: ok ? '#1a3a2a' : '#3a1a1a',
      color: ok ? 'var(--green)' : 'var(--red)',
      border: `1px solid ${ok ? 'var(--green)' : 'var(--red)'}`,
      borderRadius: 20, padding: '2px 10px', fontSize: 11, fontWeight: 700
    }}>
      {ok ? '✅ PASS' : '🚫 FAIL'}
    </span>
  )
}

export default function Dashboard() {
  const [stats, setStats]   = useState(null)
  const [scans, setScans]   = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch(`${API}/stats`).then(r => r.json()),
      fetch(`${API}/scans?limit=10`).then(r => r.json())
    ]).then(([s, sc]) => {
      setStats(s); setScans(sc); setLoading(false)
    }).catch(() => setLoading(false))

    // Auto-refresh every 10 seconds
    const t = setInterval(() => {
      fetch(`${API}/scans?limit=10`).then(r => r.json()).then(setScans).catch(() => {})
      fetch(`${API}/stats`).then(r => r.json()).then(setStats).catch(() => {})
    }, 10000)
    return () => clearInterval(t)
  }, [])

  return (
    <div style={{ padding: 32 }}>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800 }}>Dashboard</h1>
        <p style={{ color: 'var(--text2)', marginTop: 4 }}>
          Security scan overview across all connected repositories
        </p>
      </div>

      {/* Stats */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginBottom: 32 }}>
          <StatCard label="Repositories"   value={stats.total_repos}    color="var(--accent)" icon="📁" />
          <StatCard label="Total Scans"    value={stats.total_scans}    color="var(--blue)"   icon="🔍" />
          <StatCard label="Passed"         value={stats.passed_scans}   color="var(--green)"  icon="✅" />
          <StatCard label="Failed"         value={stats.failed_scans}   color="var(--red)"    icon="🚫" />
        </div>
      )}

      {stats && (stats.total_critical > 0 || stats.total_high > 0) && (
        <div style={{
          background: '#3a1a1a', border: '1px solid var(--red)',
          borderRadius: 'var(--radius)', padding: '12px 16px',
          marginBottom: 24, display: 'flex', gap: 20
        }}>
          <span>⚠️</span>
          <span style={{ color: 'var(--red)', fontWeight: 600 }}>
            Active findings: {stats.total_critical} CRITICAL · {stats.total_high} HIGH
          </span>
        </div>
      )}

      {/* Recent scans */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between',
                      alignItems: 'center', marginBottom: 14 }}>
          <h2 style={{ fontSize: 15, fontWeight: 700 }}>Recent Scans</h2>
          <Link to="/scans" style={{ fontSize: 13, color: 'var(--accent)' }}>View all →</Link>
        </div>

        <div style={{
          background: 'var(--bg2)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', overflow: 'hidden'
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Repository', 'Branch', 'Pusher', 'Commit', 'Gate', 'Time', ''].map(h => (
                  <th key={h} style={{
                    padding: '10px 14px', textAlign: 'left', fontSize: 11,
                    fontWeight: 700, color: 'var(--text2)',
                    textTransform: 'uppercase', letterSpacing: '0.5px'
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={{ padding: 24, textAlign: 'center', color: 'var(--text2)' }}>
                  Loading...
                </td></tr>
              ) : scans.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: 24, textAlign: 'center', color: 'var(--text2)' }}>
                  No scans yet. Connect a repository and push code to start.
                </td></tr>
              ) : scans.map(scan => (
                <tr key={scan.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 14px', fontWeight: 600 }}>
                    {scan.repo_name}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 12,
                                   background: 'var(--bg3)', padding: '2px 6px',
                                   borderRadius: 4 }}>
                      {scan.branch}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--text2)' }}>
                    {scan.triggered_by || '—'}
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text2)' }}>
                    {scan.commit_sha?.slice(0,7) || '—'}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    {scan.status === 'running' ? (
                      <span style={{ color: 'var(--yellow)', fontSize: 12 }}>⏳ Running...</span>
                    ) : (
                      <GateBadge gate={scan.gate_decision} />
                    )}
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--text2)', fontSize: 12 }}>
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <Link to={`/scans/${scan.id}`} style={{ fontSize: 12 }}>Details →</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
