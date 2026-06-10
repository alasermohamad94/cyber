import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Analytics from './pages/Analytics';
import ThreatManagement from './pages/ThreatManagement';
import Settings from './pages/Settings';
import Incidents from './pages/Incidents';
import EntityTrust from './pages/EntityTrust';
import RealTimeMonitor from './pages/RealTimeMonitor';
import FirewallPanel from './pages/FirewallPanel';
import ReplayViewer from './pages/ReplayViewer';
import Investigation from './pages/Investigation';

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { session, loading } = useAuth();
  if (loading) {
    return (
      <div className="cds-login">
        <div className="text-center text-white">
          <i className="fas fa-spinner fa-spin fa-2x mb-3" />
          <p>جاري التحميل...</p>
        </div>
      </div>
    );
  }
  if (!session) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <Layout />
          </PrivateRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="threats" element={<ThreatManagement />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="entities" element={<EntityTrust />} />
        <Route path="monitor" element={<RealTimeMonitor />} />
        <Route path="firewall" element={<FirewallPanel />} />
        <Route path="replay" element={<ReplayViewer />} />
        <Route path="investigation" element={<Investigation />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
