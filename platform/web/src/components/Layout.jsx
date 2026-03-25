import React from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'

const nav = [
  { to: '/dashboard',     icon: '📊', label: 'Dashboard' },
  { to: '/repositories',  icon: '📁', label: 'Repositories' },
  { to: '/scans',         icon: '🔍', label: 'Scans' },
  { to: '/setup',         icon: '⚙️',  label: 'Setup & Webhook' },
]

export default function Layout() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>

      {/* Sidebar */}
      <aside style={{
        width: 220, background: 'var(--bg2)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top: 0, bottom: 0, left: 0,
        zIndex: 100
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 16px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--text)' }}>
            🔒 ZeroTrustOps
          </div>
          <div style={{ fontSize: 11, color: 'var(--text2)', marginTop: 2 }}>
            Security Enforcement Platform
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '8px 0' }}>
          {nav.map(item => (
            <NavLink key={item.to} to={item.to} style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 16px', fontSize: 13, fontWeight: 500,
              color: isActive ? 'var(--text)' : 'var(--text2)',
              background: isActive ? 'var(--bg3)' : 'transparent',
              borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
              transition: 'all 0.15s',
              textDecoration: 'none'
            })}>
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div style={{ padding: 16, borderTop: '1px solid var(--border)',
                      fontSize: 11, color: 'var(--text2)' }}>
          v1.0.0 · by darkrootx
        </div>
      </aside>

      {/* Main content */}
      <main style={{ marginLeft: 220, flex: 1, minHeight: '100vh' }}>
        <Outlet />
      </main>
    </div>
  )
}
