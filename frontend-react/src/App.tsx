import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Dashboard from './pages/Dashboard';
import Violations from './pages/Violations';
import Targets from './pages/Targets';
import Monitoring from './pages/Monitoring';
import Hardening from './pages/Hardening';
import HardeningTemplates from './pages/HardeningTemplates';
import Integrations from './pages/Integrations';
import SecurityCorrelations from './pages/SecurityCorrelations';
import AttackMatrix from './pages/AttackMatrix';
import EventExplorer from './pages/EventExplorer';
import ComplianceFrameworks from './pages/ComplianceFrameworks';
import ComplianceControls from './pages/ComplianceControls';
import ComplianceDashboard from './pages/ComplianceDashboard';
import Alerts from './pages/Alerts';
import AuditEvents from './pages/AuditEvents';
import EventDetails from './pages/EventDetails';
import Settings from './pages/Settings';
import Plugins from './pages/Plugins';
import Login from './pages/Login';
import Layout from './components/Layout';
import { useAuthStore } from './stores/authStore';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
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
            <Route path="targets" element={<Targets />} />
            <Route path="violations" element={<Violations />} />
            <Route path="monitoring" element={<Monitoring />} />
            <Route path="hardening" element={<Hardening />} />
            <Route path="hardening-templates" element={<HardeningTemplates />} />
            <Route path="integrations" element={<Integrations />} />
            <Route path="correlations" element={<SecurityCorrelations />} />
            <Route path="attack-matrix" element={<AttackMatrix />} />
            <Route path="events-explorer" element={<EventExplorer />} />
            <Route path="compliance" element={<ComplianceFrameworks />} />
            <Route path="compliance-dashboard" element={<ComplianceDashboard />} />
            <Route path="compliance-controls" element={<ComplianceControls />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="audit-events" element={<AuditEvents />} />
            <Route path="audit-events/:id" element={<EventDetails />} />
            <Route path="plugins" element={<Plugins />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
