import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { Shield, Home, AlertTriangle, Server, LogOut, Activity, User, Zap, Link2, Bell, FileCheck, FileText, Settings, Package, Crosshair, Search } from 'lucide-react';
import api from '../services/api';
import clsx from 'clsx';

export default function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuthStore();

  const handleLogout = async () => {
    await api.logout();
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 w-64 bg-gray-900 text-white">
        <div className="flex items-center space-x-3 p-6 border-b border-gray-800">
          <Shield className="w-8 h-8 text-blue-500" />
          <div>
            <span className="text-xl font-bold">CyberSheppard</span>
            <p className="text-xs text-gray-400">MicroSIEM Platform</p>
          </div>
        </div>

        <nav className="p-4 space-y-1">
          <NavLink to="/" icon={<Home />} label="Dashboard" currentPath={location.pathname} />
          <NavLink to="/targets" icon={<Server />} label="Targets" currentPath={location.pathname} />
          <NavLink to="/violations" icon={<AlertTriangle />} label="Violations" currentPath={location.pathname} />
          <NavLink to="/monitoring" icon={<Activity />} label="Monitoring" currentPath={location.pathname} />
          <NavLink to="/hardening" icon={<Shield />} label="Hardening" currentPath={location.pathname} />
          <NavLink to="/integrations" icon={<Link2 />} label="Integrations" currentPath={location.pathname} />
          <NavLink to="/correlations" icon={<Zap />} label="Correlations" currentPath={location.pathname} />
          <NavLink to="/attack-matrix" icon={<Crosshair />} label="ATT&amp;CK Matrix" currentPath={location.pathname} />
          <NavLink to="/compliance" icon={<FileCheck />} label="Compliance" currentPath={location.pathname} />
          <NavLink to="/alerts" icon={<Bell />} label="Alerts" currentPath={location.pathname} />
          <NavLink to="/audit-events" icon={<FileText />} label="Audit Events" currentPath={location.pathname} />
          <NavLink to="/events-explorer" icon={<Search />} label="Event Explorer" currentPath={location.pathname} />
          <NavLink to="/settings" icon={<Settings />} label="Settings" currentPath={location.pathname} />
          <NavLink to="/plugins" icon={<Package />} label="Plugins" currentPath={location.pathname} />
        </nav>

        <div className="absolute bottom-0 w-full p-4 border-t border-gray-800">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                <User className="w-4 h-4" />
              </div>
              <div>
                <p className="text-sm font-medium">{user?.username}</p>
                <p className="text-xs text-gray-400">{user?.role || 'Admin'}</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="text-gray-400 hover:text-white transition-colors"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="ml-64 p-8">
        <Outlet />
      </main>
    </div>
  );
}

function NavLink({ to, icon, label, currentPath }: any) {
  const isActive = currentPath === to || (to !== '/' && currentPath.startsWith(to));

  return (
    <Link
      to={to}
      className={clsx(
        'flex items-center space-x-3 px-4 py-3 rounded-lg transition-all',
        isActive
          ? 'bg-blue-600 text-white shadow-lg'
          : 'text-gray-300 hover:bg-gray-800 hover:text-white'
      )}
    >
      {icon}
      <span className="font-medium">{label}</span>
    </Link>
  );
}
