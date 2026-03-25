import React, { useState, useEffect } from 'react'

const API = '/api'

function CopyBox({ label, value }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div style={{ marginBottom: 16 }}>
      {label && <div style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 6 }}>{label}</div>}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        background: 'var(--bg)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', padding: '10px 14px'
      }}>
        <code style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 13,
                       color: 'var(--blue)', wordBreak: 'break-all' }}>
          {value}
        </code>
        <button onClick={copy} style={{
          background: copied ? 'var(--green)' : 'var(--bg3)',
          color: copied ? '#fff' : 'var(--text2)',
          border: `1px solid ${copied ? 'var(--green)' : 'var(--border)'}`,
          borderRadius: 6, padding: '4px 10px', fontSize: 12,
          transition: 'all 0.2s', whiteSpace: 'nowrap'
        }}>
          {copied ? '✅ Copied' : 'Copy'}
        </button>
      </div>
    </div>
  )
}

function Step({ number, title, children }) {
  return (
    <div style={{
      background: 'var(--bg2)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: 24, marginBottom: 20
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <div style={{
          width: 28, height: 28, background: 'var(--accent)',
          borderRadius: '50%', display: 'flex', alignItems: 'center',
          justifyContent: 'center', fontSize: 13, fontWeight: 800,
          color: '#fff', flexShrink: 0
        }}>{number}</div>
        <h3 style={{ fontSize: 15, fontWeight: 700 }}>{title}</h3>
      </div>
      {children}
    </div>
  )
}

export default function Setup() {
  const [health, setHealth] = useState(null)
  const [serverUrl, setServerUrl] = useState(window.location.origin)

  useEffect(() => {
    fetch(`${API.replace('/api', '')}/health`).then(r => r.json()).then(setHealth).catch(() => {})
  }, [])

  const webhookUrl = `${serverUrl}/webhook/github`

  return (
    <div style={{ padding: 32, maxWidth: 860 }}>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800 }}>Setup & Webhook Configuration</h1>
        <p style={{ color: 'var(--text2)', marginTop: 4 }}>
          Connect your GitHub repositories so every push triggers an automatic security scan.
        </p>
      </div>

      {/* Platform status */}
      <div style={{
        background: health?.sectl ? '#1a3a2a' : '#3a1a1a',
        border: `1px solid ${health?.sectl ? 'var(--green)' : 'var(--red)'}`,
        borderRadius: 'var(--radius)', padding: '12px 18px',
        marginBottom: 28, display: 'flex', gap: 24
      }}>
        <span style={{ color: health?.sectl ? 'var(--green)' : 'var(--red)', fontWeight: 600 }}>
          {health?.sectl ? '✅ Platform is running' : '⏳ Platform starting...'}
        </span>
        {health && (
          <>
            <span style={{ color: 'var(--text2)', fontSize: 13 }}>
              SecTL: {health.sectl ? '✅ Ready' : '❌ Not found'}
            </span>
            <span style={{ color: 'var(--text2)', fontSize: 13 }}>
              v{health.version}
            </span>
          </>
        )}
      </div>

      {/* How it works */}
      <div style={{
        background: 'var(--bg2)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', padding: 20, marginBottom: 28
      }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 14 }}>How it works</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8,
                      flexWrap: 'wrap', fontSize: 13 }}>
          {[
            'Developer pushes code',
            '→',
            'GitHub sends webhook',
            '→',
            'Platform clones repo',
            '→',
            'SecTL scans code',
            '→',
            'PASS / FAIL decision',
            '→',
            'Results on dashboard'
          ].map((item, i) => (
            <span key={i} style={{
              color: item === '→' ? 'var(--text2)' :
                     item.includes('PASS') ? 'var(--green)' :
                     item.includes('FAIL') ? 'var(--red)' : 'var(--text)',
              fontWeight: item === '→' ? 400 : 500
            }}>{item}</span>
          ))}
        </div>
      </div>

      {/* Step 1: Webhook URL */}
      <Step number="1" title="Get your Webhook URL">
        <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 14 }}>
          This is the URL GitHub will send push events to. If you're running locally,
          use ngrok to get a public URL first.
        </p>

        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: 12, color: 'var(--text2)', display: 'block', marginBottom: 6 }}>
            Your server URL (update if different)
          </label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              value={serverUrl}
              onChange={e => setServerUrl(e.target.value)}
              placeholder="https://your-server.com or https://abc.ngrok-free.dev"
              style={{ flex: 1 }}
            />
          </div>
        </div>

        <CopyBox label="Webhook URL to paste in GitHub:" value={webhookUrl} />

        <div style={{
          background: 'var(--bg3)', borderRadius: 6,
          padding: '10px 14px', fontSize: 12, color: 'var(--text2)'
        }}>
          💡 <strong style={{ color: 'var(--text)' }}>Running locally?</strong> Use ngrok:
          <code style={{ fontFamily: 'var(--mono)', color: 'var(--blue)',
                         marginLeft: 8 }}>ngrok http 3000</code>
          → copy the https URL → paste above
        </div>
      </Step>

      {/* Step 2: GitHub Setup */}
      <Step number="2" title="Add Webhook to GitHub Repository">
        <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 16 }}>
          Go to your GitHub repository and add the webhook.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
          {[
            { step: '1', text: 'Open your GitHub repository' },
            { step: '2', text: 'Click Settings → Webhooks → Add webhook' },
            { step: '3', text: 'Paste the Webhook URL from Step 1' },
            { step: '4', text: 'Content type: application/json' },
            { step: '5', text: 'Secret: leave empty' },
            { step: '6', text: 'Events: Just the push event ✓' },
            { step: '7', text: 'Click Add webhook' },
          ].map(item => (
            <div key={item.step} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              <span style={{
                width: 20, height: 20, background: 'var(--bg3)',
                border: '1px solid var(--border)', borderRadius: '50%',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 11, fontWeight: 700, color: 'var(--text2)', flexShrink: 0
              }}>{item.step}</span>
              <span style={{ paddingTop: 1 }}>{item.text}</span>
            </div>
          ))}
        </div>

        <div style={{
          background: '#1a2a3a', border: '1px solid var(--blue)',
          borderRadius: 6, padding: '10px 14px',
          marginTop: 16, fontSize: 12, color: 'var(--blue)'
        }}>
          ℹ️ After adding the webhook, GitHub will send a <strong>ping</strong> event.
          The platform will auto-register the repository on the first real push.
        </div>
      </Step>

      {/* Step 3: Test */}
      <Step number="3" title="Test the Connection">
        <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 14 }}>
          Push any code change to trigger your first scan:
        </p>

        <CopyBox label="Push something to trigger a scan:" value={`git add . && git commit -m "test: trigger zerotrust scan" && git push`} />

        <p style={{ fontSize: 13, color: 'var(--text2)', marginTop: 12 }}>
          Or trigger manually from the{' '}
          <a href="/repositories">Repositories page</a>{' '}
          using the "▶ Scan Now" button.
        </p>

        <div style={{
          background: 'var(--bg3)', borderRadius: 6,
          padding: '10px 14px', marginTop: 14, fontSize: 12, color: 'var(--text2)'
        }}>
          After pushing, go to <a href="/dashboard">Dashboard</a> to see the scan running in real-time.
        </div>
      </Step>

      {/* Step 4: What gets scanned */}
      <Step number="4" title="What Gets Scanned">
        <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 16 }}>
          ZeroTrustOps automatically detects and scans:
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {[
            { icon: '📄', title: 'Kubernetes YAML', desc: 'manifests/, k8s/, kubernetes/, deploy/ — checks for privileged containers, RBAC issues, hardcoded secrets, missing security context', color: 'var(--blue)' },
            { icon: '🏗️', title: 'Terraform IaC', desc: 'infra/, terraform/ — checks for public S3 buckets, open security groups, unencrypted RDS, wildcard IAM policies', color: 'var(--accent)' },
            { icon: '🔑', title: 'Secrets Detection', desc: 'Full git history scan for hardcoded API keys, passwords, tokens, credentials anywhere in the codebase', color: 'var(--red)' },
            { icon: '📊', title: '74+ Security Rules', desc: 'K8S-001 to K8S-050 · TF-S3, TF-IAM, TF-SG, TF-RDS, TF-EKS · HELM rules · Supply chain checks', color: 'var(--green)' },
          ].map(item => (
            <div key={item.title} style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderLeft: `3px solid ${item.color}`,
              borderRadius: 6, padding: '12px 14px'
            }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>{item.icon} {item.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text2)' }}>{item.desc}</div>
            </div>
          ))}
        </div>
      </Step>

      {/* API Reference */}
      <Step number="5" title="API Reference">
        <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 14 }}>
          All platform functionality is available via REST API:
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            { method: 'POST', path: '/webhook/github',      desc: 'GitHub push webhook (auto-triggered)' },
            { method: 'GET',  path: '/api/repos',           desc: 'List connected repositories' },
            { method: 'POST', path: '/api/repos',           desc: 'Connect a new repository' },
            { method: 'GET',  path: '/api/scans',           desc: 'List all scans' },
            { method: 'GET',  path: '/api/scans/{id}',      desc: 'Get scan details + findings' },
            { method: 'POST', path: '/api/scans/trigger',   desc: 'Manually trigger a scan' },
            { method: 'GET',  path: '/api/stats',           desc: 'Dashboard statistics' },
            { method: 'GET',  path: '/health',              desc: 'Platform health check' },
          ].map(item => (
            <div key={item.path} style={{
              display: 'flex', alignItems: 'center', gap: 12,
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '8px 12px', fontSize: 12
            }}>
              <span style={{
                background: item.method === 'GET' ? '#1a3a2a' : '#1a2a3a',
                color: item.method === 'GET' ? 'var(--green)' : 'var(--blue)',
                padding: '2px 8px', borderRadius: 4, fontWeight: 700,
                fontFamily: 'var(--mono)', width: 44, textAlign: 'center', flexShrink: 0
              }}>{item.method}</span>
              <code style={{ fontFamily: 'var(--mono)', color: 'var(--text)', flex: 1 }}>{item.path}</code>
              <span style={{ color: 'var(--text2)' }}>{item.desc}</span>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 14 }}>
          <CopyBox label="Full API docs:" value={`${serverUrl}/docs`} />
        </div>
      </Step>

    </div>
  )
}
