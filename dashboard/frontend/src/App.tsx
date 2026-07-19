import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import FleetOverview from './views/FleetOverview'
import IdentityGovernance from './views/IdentityGovernance'

export default function App() {
  return (
    <div className="app-shell">
      <nav className="sidebar">
        <div className="sidebar-logo">
          Agent<span>Wall</span>
        </div>
        <NavLink
          to="/fleet"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          Fleet Overview
        </NavLink>
        <NavLink
          to="/identity"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Identity Governance
        </NavLink>
      </nav>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Navigate to="/fleet" replace />} />
          <Route path="/fleet" element={<FleetOverview />} />
          <Route path="/identity" element={<IdentityGovernance />} />
        </Routes>
      </main>
    </div>
  )
}
