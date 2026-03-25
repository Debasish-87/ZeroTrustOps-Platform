import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'

const API = '/api'
const SEV_COLOR = {
  CRITICAL: '#f85149', HIGH: '#f0883e',
  MEDIUM: '#d29922',   LOW: '#58a6ff', INFO: '#8b949e'
}

export default function ScanDetail() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('ALL')

  useEffect(() => {
    const load = () => {
      fetch(`${API}/scans/${id}`).then(r => r.json())
        .then(d => { setScan(d); setLoading(false) })
        .catch(() => setLoading(false))
    }
    load()
    // Auto-refresh if scan is running
    const t = setInterval(() => {
      if (scan?.status === 'running') load()
    }, 5000)
    return () => clearInterval(t)
  }, [id])

  if (loading) return (
    <div style={{ padding: 32, color: 'var(--text2)' }}>Loading scan...</div>
  )

  if (!scan) return (
    <div style={{ padding: 32 }}>
      <div style={{ color: 'var(--red)' }}>Scan not found.</div>
      <Link to="/scans" style={{ marginTop: 12, display: 'inline-block' }}>← Back to Scans</Link>
    </div>
  )

  const findings = scan.findings || []
  const filtered = filter === 'ALL' ? findings :
    findings.filter(f => f.severity === filter)

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  const gate = scan.gate_decision
  const isRunning = scan.status === 'running'

  return (
    <div style={{ padding: 32 }}>

      {/* Back */}
      <Link to="/scans" style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 20, display: 'inline-block' }}>
        ← Back to Scans
      </Link>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between',
                    alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800 }}>Scan #{scan.id}</h1>
          <div style={{ color: 'var(--text2)', fontSize: 13, marginTop: 4 }}>
            {scan.repo_name} · {scan.branch} · by {scan.triggered_by || '—'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2, fontFamily: 'var(--mono)' }}>
            {scan.commit_sha} · {scan.commit_message?.slice(0, 80)}
          </div>
        </div>

        <div style={{ textAlign: 'right' }}>
          {isRunning ? (
            <div style={{ color: 'var(--yellow)', fontWeight: 700, fontSize: 18 }}>⏳ Running...</div>
          ) : gate ? (
            <div style={{
              color: gate === 'PASS' ? 'var(--green)' : 'var(--red)',
              fontWeight: 800, fontSize: 24
            }}>
              {gate === 'PASS' ? '✅ PASS' : '🚫 FAIL'}
            </div>
          ) : null}
          {scan.duration_ms && (
            <div style={{ fontSize: 12, color: 'var(--text2)', marginTop: 4 }}>
              {(scan.duration_ms / 1000).toFixed(1)}s
            </div>
          )}
        </div>
      </div>

      {/* Gate banner */}
      {!isRunning && gate && (
        <div style={{
          background: gate === 'PASS' ? '#1a3a2a' : '#3a1a1a',
          border: `1px solid ${gate === 'PASS' ? 'var(--green)' : 'var(--red)'}`,
          borderRadius: 'var(--radius)', padding: '14px 18px',
          marginBottom: 24, display: 'flex', alignItems: 'center', gap: 12
        }}>
          <span style={{ fontSize: 24 }}>{gate === 'PASS' ? '✅' : '🚫'}</span>
          <div>
            <div style={{ fontWeight: 700, color: gate === 'PASS' ? 'var(--green)' : 'var(--red)' }}>
              {gate === 'PASS'
                ? 'Security Gate PASSED — No CRITICAL or HIGH findings'
                : `Security Gate FAILED — ${(counts.CRITICAL||0)} CRITICAL · ${(counts.HIGH||0)} HIGH findings blocked deploy`}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2 }}>
              {findings.length} total findings across all scanners
            </div>
          </div>
        </div>
      )}

      {/* Severity summary */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
          const count = sev === 'ALL' ? findings.length : (counts[sev] || 0)
          const active = filter === sev
          return (
            <button key={sev} onClick={() => setFilter(sev)} style={{
              background: active ? (SEV_COLOR[sev] || 'var(--accent)') + '33' : 'var(--bg2)',
              border: `1px solid ${active ? (SEV_COLOR[sev] || 'var(--accent)') : 'var(--border)'}`,
              color: active ? (SEV_COLOR[sev] || 'var(--accent)') : 'var(--text2)',
              borderRadius: 20, padding: '4px 14px', fontSize: 12, fontWeight: 600
            }}>
              {sev} ({count})
            </button>
          )
        })}
      </div>

      {/* Findings table */}
      <div style={{
        background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', overflow: 'hidden'
      }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text2)' }}>
            {isRunning ? '⏳ Scan in progress...' : '✅ No findings for this filter'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Tool', 'Rule ID', 'Severity', 'Title', 'File', 'Remediation'].map(h => (
                  <th key={h} style={{
                    padding: '10px 14px', textAlign: 'left', fontSize: 11,
                    fontWeight: 700, color: 'var(--text2)',
                    textTransform: 'uppercase', letterSpacing: '0.5px'
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((f, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{
                      background: 'var(--bg3)', padding: '2px 8px',
                      borderRadius: 4, fontSize: 11, fontWeight: 600
                    }}>{f.tool}</span>
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text2)' }}>
                    {f.rule_id}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{
                      background: (SEV_COLOR[f.severity] || '#888') + '22',
                      color: SEV_COLOR[f.severity] || '#888',
                      border: `1px solid ${(SEV_COLOR[f.severity] || '#888')}44`,
                      borderRadius: 20, padding: '2px 8px', fontSize: 11, fontWeight: 700
                    }}>{f.severity}</span>
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 13, maxWidth: 280 }}>
                    {f.title}
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--mono)', fontSize: 11,
                               color: 'var(--text2)', maxWidth: 200, overflow: 'hidden',
                               textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.file_path}
                  </td>
                  <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text2)', maxWidth: 220 }}>
                    {f.remediation?.slice(0, 80)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
