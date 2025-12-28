import { Outlet, Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { Shield, Home, AlertTriangle, Server, LogOut } from 'lucide-react';
import api from '../services/api';

export default function Layout() {
  const navigate = useNavigate();
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
          <Shield className="w-8 h-8" />
          <span className="text-xl font-bold">CyberSheppard</span>
        </div>

        <nav className="p-4 space-y-2">
          <NavLink to="/" icon={<Home />} label="Dashboard" />
          <NavLink to="/violations" icon={<AlertTriangle />} label="Violations" />
          <NavLink to="/targets" icon={<Server />} label="Targets" />
        </nav>

        <div className="absolute bottom-0 w-full p-4 border-t border-gray-800">
          <div className="flex items-center justify-between">
            <span className="text-sm">{user?.username}</span>
            <button onClick={handleLogout} className="text-gray-400 hover:text-white">
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

function NavLink({ to, icon, label }: any) {
  return (
    <Link
      to={to}
      className="flex items-center space-x-3 px-4 py-3 rounded-lg hover:bg-gray-800 transition-colors"
    >
      {icon}
      <span>{label}</span>
    </Link>
  );
}
