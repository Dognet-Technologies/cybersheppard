import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Dashboard from './pages/Dashboard';
import Violations from './pages/Violations';
import Targets from './pages/Targets';
import Monitoring from './pages/Monitoring';
import Hardening from './pages/Hardening';
import Integrations from './pages/Integrations';
import SecurityCorrelations from './pages/SecurityCorrelations';
import ComplianceFrameworks from './pages/ComplianceFrameworks';
import Alerts from './pages/Alerts';
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
            <Route path="integrations" element={<Integrations />} />
            <Route path="correlations" element={<SecurityCorrelations />} />
            <Route path="compliance" element={<ComplianceFrameworks />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="plugins" element={<Plugins />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
