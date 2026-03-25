import React, { useState, useEffect } from 'react'

const API = '/api'

export default function Repositories() {
  const [repos, setRepos]     = useState([])
  const [loading, setLoading] = useState(true)
  const [adding, setAdding]   = useState(false)
  const [form, setForm]       = useState({ full_name: '', clone_url: '', branch: 'main' })
  const [msg, setMsg]         = useState(null)

  const load = () => {
    fetch(`${API}/repos`).then(r => r.json())
      .then(d => { setRepos(d); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const addRepo = async (e) => {
    e.preventDefault()
    setMsg(null)
    try {
      // Auto-fill clone_url from full_name
      const clone_url = form.clone_url ||
        `https://github.com/${form.full_name}.git`

      const res = await fetch(`${API}/repos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, clone_url })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail)
      setMsg({ type: 'success', text: `✅ Repository "${form.full_name}" connected!` })
      setForm({ full_name: '', clone_url: '', branch: 'main' })
      setAdding(false)
      load()
    } catch (err) {
      setMsg({ type: 'error', text: `❌ ${err.message}` })
    }
  }

  const removeRepo = async (id, name) => {
    if (!confirm(`Remove "${name}"?`)) return
    await fetch(`${API}/repos/${id}`, { method: 'DELETE' })
    load()
  }

  const triggerScan = async (repo) => {
    const res = await fetch(`${API}/scans/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo_full_name: repo.full_name,
        triggered_by: 'manual',
        commit_message: 'Manual scan trigger'
      })
    })
    const data = await res.json()
    setMsg({ type: 'success', text: `✅ Scan #${data.scan_id} started for ${repo.full_name}` })
    setTimeout(() => setMsg(null), 4000)
  }

  return (
    <div style={{ padding: 32 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between',
                    alignItems: 'flex-start', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Repositories</h1>
          <p style={{ color: 'var(--text2)', marginTop: 4 }}>
            Connect GitHub repositories to scan on every push
          </p>
        </div>
        <button onClick={() => setAdding(!adding)} style={{
          background: 'var(--accent)', color: '#fff',
          borderRadius: 'var(--radius)', padding: '8px 16px',
          fontSize: 13, fontWeight: 600
        }}>
          + Connect Repository
        </button>
      </div>

      {/* Message */}
      {msg && (
        <div style={{
          background: msg.type === 'success' ? '#1a3a2a' : '#3a1a1a',
          border: `1px solid ${msg.type === 'success' ? 'var(--green)' : 'var(--red)'}`,
          color: msg.type === 'success' ? 'var(--green)' : 'var(--red)',
          borderRadius: 'var(--radius)', padding: '10px 14px',
          marginBottom: 20, fontSize: 13
        }}>{msg.text}</div>
      )}

      {/* Add form */}
      {adding && (
        <div style={{
          background: 'var(--bg2)', border: '1px solid var(--accent)',
          borderRadius: 'var(--radius)', padding: 20, marginBottom: 24
        }}>
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>
            Connect a GitHub Repository
          </h3>
          <form onSubmit={addRepo}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 12, alignItems: 'end' }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text2)', display: 'block', marginBottom: 4 }}>
                  Repository (owner/repo) *
                </label>
                <input
                  placeholder="Debasish-87/my-app"
                  value={form.full_name}
                  onChange={e => setForm({...form, full_name: e.target.value})}
                  required
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text2)', display: 'block', marginBottom: 4 }}>
                  Branch
                </label>
                <input
                  placeholder="main"
                  value={form.branch}
                  onChange={e => setForm({...form, branch: e.target.value})}
                />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="submit" style={{
                  background: 'var(--accent)', color: '#fff',
                  borderRadius: 'var(--radius)', padding: '8px 16px',
                  fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap'
                }}>
                  Connect
                </button>
                <button type="button" onClick={() => setAdding(false)} style={{
                  background: 'var(--bg3)', color: 'var(--text2)',
                  borderRadius: 'var(--radius)', padding: '8px 12px', fontSize: 13
                }}>
                  Cancel
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* Repos list */}
      <div style={{
        background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', overflow: 'hidden'
      }}>
        {loading ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text2)' }}>Loading...</div>
        ) : repos.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--text2)' }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>📁</div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>No repositories connected</div>
            <div style={{ fontSize: 13 }}>Click "Connect Repository" to add your first repo</div>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Repository', 'Branch', 'Total Scans', 'Last Scan', 'Last Result', 'Actions'].map(h => (
                  <th key={h} style={{
                    padding: '10px 14px', textAlign: 'left', fontSize: 11,
                    fontWeight: 700, color: 'var(--text2)',
                    textTransform: 'uppercase', letterSpacing: '0.5px'
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {repos.map(repo => (
                <tr key={repo.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '12px 14px' }}>
                    <div style={{ fontWeight: 600 }}>{repo.full_name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 2, fontFamily: 'var(--mono)' }}>
                      {repo.clone_url}
                    </div>
                  </td>
                  <td style={{ padding: '12px 14px' }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 12,
                                   background: 'var(--bg3)', padding: '2px 6px', borderRadius: 4 }}>
                      {repo.branch}
                    </span>
                  </td>
                  <td style={{ padding: '12px 14px', color: 'var(--text2)' }}>
                    {repo.total_scans || 0}
                  </td>
                  <td style={{ padding: '12px 14px', color: 'var(--text2)', fontSize: 12 }}>
                    {repo.last_scan ? new Date(repo.last_scan).toLocaleDateString() : 'Never'}
                  </td>
                  <td style={{ padding: '12px 14px' }}>
                    {repo.last_gate ? (
                      <span style={{
                        color: repo.last_gate === 'PASS' ? 'var(--green)' : 'var(--red)',
                        fontWeight: 700, fontSize: 12
                      }}>
                        {repo.last_gate === 'PASS' ? '✅ PASS' : '🚫 FAIL'}
                      </span>
                    ) : <span style={{ color: 'var(--text2)' }}>—</span>}
                  </td>
                  <td style={{ padding: '12px 14px' }}>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button onClick={() => triggerScan(repo)} style={{
                        background: 'var(--bg3)', color: 'var(--text)',
                        border: '1px solid var(--border)', borderRadius: 6,
                        padding: '4px 10px', fontSize: 12
                      }}>
                        ▶ Scan Now
                      </button>
                      <button onClick={() => removeRepo(repo.id, repo.full_name)} style={{
                        background: 'transparent', color: 'var(--red)',
                        border: '1px solid var(--red)', borderRadius: 6,
                        padding: '4px 10px', fontSize: 12
                      }}>
                        Remove
                      </button>
                    </div>
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
