import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

const API = '/api'

export default function Scans() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`${API}/scans?limit=50`).then(r => r.json())
      .then(d => { setScans(d); setLoading(false) })
      .catch(() => setLoading(false))

    const t = setInterval(() => {
      fetch(`${API}/scans?limit=50`).then(r => r.json()).then(setScans).catch(() => {})
    }, 8000)
    return () => clearInterval(t)
  }, [])

  return (
    <div style={{ padding: 32 }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800 }}>All Scans</h1>
        <p style={{ color: 'var(--text2)', marginTop: 4 }}>
          Complete scan history across all repositories
        </p>
      </div>

      <div style={{
        background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', overflow: 'hidden'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)' }}>
              {['#', 'Repository', 'Branch', 'Commit', 'Pusher', 'Findings', 'Gate', 'Time', ''].map(h => (
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
              <tr><td colSpan={9} style={{ padding: 24, textAlign: 'center', color: 'var(--text2)' }}>Loading...</td></tr>
            ) : scans.length === 0 ? (
              <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: 'var(--text2)' }}>
                No scans yet. Push code to a connected repository to start.
              </td></tr>
            ) : scans.map(scan => (
              <tr key={scan.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '10px 14px', color: 'var(--text2)', fontFamily: 'var(--mono)', fontSize: 12 }}>
                  #{scan.id}
                </td>
                <td style={{ padding: '10px 14px', fontWeight: 600 }}>{scan.repo_name}</td>
                <td style={{ padding: '10px 14px' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 12,
                                 background: 'var(--bg3)', padding: '2px 6px', borderRadius: 4 }}>
                    {scan.branch}
                  </span>
                </td>
                <td style={{ padding: '10px 14px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text2)' }}>
                  {scan.commit_sha?.slice(0,7) || '—'}
                </td>
                <td style={{ padding: '10px 14px', color: 'var(--text2)' }}>
                  {scan.triggered_by || '—'}
                </td>
                <td style={{ padding: '10px 14px' }}>
                  {(scan.critical_count || 0) > 0 && (
                    <span style={{ color: '#f85149', fontWeight: 700, fontSize: 12, marginRight: 6 }}>
                      {scan.critical_count}C
                    </span>
                  )}
                  {(scan.high_count || 0) > 0 && (
                    <span style={{ color: '#f0883e', fontWeight: 700, fontSize: 12, marginRight: 6 }}>
                      {scan.high_count}H
                    </span>
                  )}
                  {(scan.finding_count || 0) === 0 && (
                    <span style={{ color: 'var(--text2)', fontSize: 12 }}>—</span>
                  )}
                </td>
                <td style={{ padding: '10px 14px' }}>
                  {scan.status === 'running' ? (
                    <span style={{ color: 'var(--yellow)', fontSize: 12 }}>⏳ Running</span>
                  ) : scan.gate_decision ? (
                    <span style={{
                      color: scan.gate_decision === 'PASS' ? 'var(--green)' : 'var(--red)',
                      fontWeight: 700, fontSize: 12
                    }}>
                      {scan.gate_decision === 'PASS' ? '✅ PASS' : '🚫 FAIL'}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text2)', fontSize: 12 }}>{scan.status}</span>
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
  )
}
