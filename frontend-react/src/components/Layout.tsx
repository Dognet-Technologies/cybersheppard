import { useCallback, useState } from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import {
  Shield, Home, Server, LogOut, Activity, User, Link2, FileCheck, Settings,
  Package, Crosshair, PanelLeftClose, PanelLeftOpen,
} from 'lucide-react';
import api from '../services/api';
import clsx from 'clsx';
import { Tooltip } from './ui';
import { HELP } from '../i18n/help';
import {
  getSidebarWidth, setSidebarWidth, getSidebarCollapsed, setSidebarCollapsed,
  SIDEBAR_MIN, SIDEBAR_MAX,
} from '../utils/prefs';

export default function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuthStore();

  const [collapsed, setCollapsed] = useState<boolean>(getSidebarCollapsed());
  const [width, setWidth] = useState<number>(getSidebarWidth());

  const handleLogout = async () => {
    await api.logout();
    logout();
    navigate('/login');
  };

  const toggle = () =>
    setCollapsed((c) => {
      const next = !c;
      setSidebarCollapsed(next);
      return next;
    });

  // Drag del bordo destro per ridimensionare la sidebar.
  const startResize = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      const startX = e.clientX;
      const startW = width;
      const onMove = (ev: MouseEvent) => {
        const w = Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, startW + (ev.clientX - startX)));
        setWidth(w);
      };
      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        document.body.style.userSelect = '';
        setWidth((w) => {
          setSidebarWidth(w);
          return w;
        });
      };
      document.body.style.userSelect = 'none';
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    },
    [width],
  );

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Bottone flottante per riaprire quando la sidebar è chiusa */}
      {collapsed && (
        <button
          onClick={toggle}
          title="Mostra il menu"
          aria-label="Mostra il menu"
          className="fixed top-4 left-4 z-50 p-2 rounded-lg bg-gray-900 text-white shadow-lg hover:bg-gray-800 transition-colors"
        >
          <PanelLeftOpen className="w-5 h-5" />
        </button>
      )}

      {/* Sidebar */}
      {!collapsed && (
        <aside
          className="fixed inset-y-0 left-0 bg-gray-900 text-white flex flex-col"
          style={{ width }}
        >
          <div className="flex items-center justify-between p-6 border-b border-gray-800">
            <div className="flex items-center space-x-3 min-w-0">
              <Shield className="w-8 h-8 text-blue-500 flex-shrink-0" />
              <div className="min-w-0">
                <span className="text-xl font-bold block truncate">CyberSheppard</span>
                <p className="text-xs text-gray-400 truncate">MicroSIEM Platform</p>
              </div>
            </div>
            <button
              onClick={toggle}
              title="Nascondi il menu"
              aria-label="Nascondi il menu"
              className="p-1.5 rounded text-gray-400 hover:text-white hover:bg-gray-800 transition-colors flex-shrink-0"
            >
              <PanelLeftClose className="w-5 h-5" />
            </button>
          </div>

          <nav className="p-4 space-y-1 overflow-y-auto flex-1">
            <NavLink to="/" icon={<Home />} label="Dashboard" info={HELP.nav.dashboard} currentPath={location.pathname} />
            <NavLink to="/targets" icon={<Server />} label="Targets" info={HELP.nav.targets} currentPath={location.pathname} />
            <NavLink to="/monitoring" icon={<Activity />} label="Monitoring" info={HELP.nav.monitoring} currentPath={location.pathname} />
            <NavLink to="/hardening" icon={<Shield />} label="Hardening" info={HELP.nav.hardening} currentPath={location.pathname} />
            <NavLink to="/integrations" icon={<Link2 />} label="Integrations" info={HELP.nav.integrations} currentPath={location.pathname} />
            <NavLink to="/detection" icon={<Crosshair />} label="Threat Detection" info={HELP.nav.detection} currentPath={location.pathname} />
            <NavLink to="/compliance" icon={<FileCheck />} label="Compliance" info={HELP.nav.compliance} currentPath={location.pathname} />
            <NavLink to="/settings" icon={<Settings />} label="Settings" info={HELP.nav.settings} currentPath={location.pathname} />
            <NavLink to="/plugins" icon={<Package />} label="Plugins" info={HELP.nav.plugins} currentPath={location.pathname} />
          </nav>

          <div className="w-full p-4 border-t border-gray-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 min-w-0">
                <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center flex-shrink-0">
                  <User className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">{user?.username}</p>
                  <p className="text-xs text-gray-400 truncate">{user?.role || 'Admin'}</p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="text-gray-400 hover:text-white transition-colors flex-shrink-0"
                title="Logout"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Maniglia di ridimensionamento (bordo destro) */}
          <div
            onMouseDown={startResize}
            title="Trascina per ridimensionare"
            className="absolute top-0 right-0 h-full w-1.5 cursor-col-resize hover:bg-blue-500/60 active:bg-blue-500"
          />
        </aside>
      )}

      {/* Main Content */}
      <main className="p-8 transition-[margin] duration-150" style={{ marginLeft: collapsed ? 0 : width }}>
        <Outlet />
      </main>
    </div>
  );
}

function NavLink({ to, icon, label, currentPath, info }: any) {
  const isActive = currentPath === to || (to !== '/' && currentPath.startsWith(to));

  return (
    <Tooltip content={info} side="right" wrapperClassName="block w-full">
      <Link
        to={to}
        className={clsx(
          'flex items-center space-x-3 px-4 py-3 rounded-lg transition-all w-full',
          isActive
            ? 'bg-blue-600 text-white shadow-lg'
            : 'text-gray-300 hover:bg-gray-800 hover:text-white'
        )}
      >
        <span className="flex-shrink-0">{icon}</span>
        <span className="font-medium truncate">{label}</span>
      </Link>
    </Tooltip>
  );
}
