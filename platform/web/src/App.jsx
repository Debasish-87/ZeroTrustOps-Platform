import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Repositories from './pages/Repositories.jsx'
import Scans from './pages/Scans.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Setup from './pages/Setup.jsx'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="repositories" element={<Repositories />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="setup" element={<Setup />} />
      </Route>
    </Routes>
  )
}
