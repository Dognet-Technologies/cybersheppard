// ============================================================================
// Settings Page - Comprehensive system settings management
// ============================================================================

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings as SettingsIcon,
  User,
  Palette,
  Activity,
  Database,
  Key,
  Link2,
  Save,
  Trash2,
  RefreshCw,
  Copy,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Plus,
} from 'lucide-react';
import api from '../services/api';
import { useAuthStore } from '../stores/authStore';
import { format } from 'date-fns';
import {
  PageHeader,
  Button,
  Table,
  StatusBadge,
} from '../components/ui';
import clsx from 'clsx';

type TabType = 'user' | 'appearance' | 'system' | 'database' | 'api-keys' | 'integrations';

export default function Settings() {
  const [activeTab, setActiveTab] = useState<TabType>('user');
  const { user } = useAuthStore();

  const tabs = [
    { id: 'user' as TabType, label: 'User Profile', icon: <User className="w-4 h-4" /> },
    { id: 'appearance' as TabType, label: 'Appearance', icon: <Palette className="w-4 h-4" /> },
    { id: 'system' as TabType, label: 'System Status', icon: <Activity className="w-4 h-4" /> },
    { id: 'database' as TabType, label: 'Database', icon: <Database className="w-4 h-4" /> },
    { id: 'api-keys' as TabType, label: 'API Keys', icon: <Key className="w-4 h-4" /> },
    { id: 'integrations' as TabType, label: 'Integrations', icon: <Link2 className="w-4 h-4" /> },
  ];

  return (
    <div>
      <PageHeader
        title="Settings"
        subtitle="Manage system configuration and preferences"
        icon={<SettingsIcon className="w-6 h-6" />}
      />

      {/* Tabs */}
      <div className="mb-6">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors',
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                )}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'user' && <UserProfileTab />}
        {activeTab === 'appearance' && <AppearanceTab />}
        {activeTab === 'system' && <SystemStatusTab />}
        {activeTab === 'database' && <DatabaseTab />}
        {activeTab === 'api-keys' && <ApiKeysTab />}
        {activeTab === 'integrations' && <IntegrationsTab />}
      </div>
    </div>
  );
}

// ============================================================================
// User Profile Tab
// ============================================================================

function UserProfileTab() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const [email, setEmail] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const { data: profile } = useQuery({
    queryKey: ['user-profile'],
    queryFn: () => api.getUserProfile(),
  });

  const updateProfileMutation = useMutation({
    mutationFn: (email: string) => api.updateUserProfile(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-profile'] });
      alert('Profile updated successfully');
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: ({ currentPassword, newPassword }: { currentPassword: string; newPassword: string }) =>
      api.changePassword(currentPassword, newPassword),
    onSuccess: () => {
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      alert('Password changed successfully');
    },
  });

  const handleUpdateProfile = () => {
    updateProfileMutation.mutate(email);
  };

  const handleChangePassword = () => {
    if (newPassword !== confirmPassword) {
      alert('Passwords do not match');
      return;
    }
    if (newPassword.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }
    changePasswordMutation.mutate({ currentPassword, newPassword });
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Profile Information */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Profile Information</h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={profile?.username || ''}
              disabled
              className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              type="email"
              value={email || profile?.email || ''}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
              placeholder="user@example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
            <input
              type="text"
              value={profile?.role || ''}
              disabled
              className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Member Since</label>
            <input
              type="text"
              value={profile?.created_at ? format(new Date(profile.created_at), 'PPP') : ''}
              disabled
              className="w-full px-3 py-2 border border-gray-300 rounded-md bg-gray-50"
            />
          </div>

          <Button
            onClick={handleUpdateProfile}
            loading={updateProfileMutation.isPending}
            className="w-full"
          >
            <Save className="w-4 h-4 mr-2" />
            Save Profile
          </Button>
        </div>
      </div>

      {/* Change Password */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Change Password</h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">Minimum 8 characters</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <Button
            onClick={handleChangePassword}
            loading={changePasswordMutation.isPending}
            disabled={!currentPassword || !newPassword || !confirmPassword}
            className="w-full"
          >
            <Key className="w-4 h-4 mr-2" />
            Change Password
          </Button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Appearance Tab
// ============================================================================

function AppearanceTab() {
  const queryClient = useQueryClient();
  const [selectedTheme, setSelectedTheme] = useState('light');

  const { data: settings } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.getAllSettings(),
  });

  const updateSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) =>
      api.updateSetting(key, value, 'admin'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
  });

  const currentTheme = settings?.find((s: any) => s.key === 'theme')?.value || 'light';

  const handleThemeChange = (theme: string) => {
    setSelectedTheme(theme);
    updateSettingMutation.mutate({ key: 'theme', value: theme });
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-6">Appearance Settings</h3>

      <div className="space-y-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-3">Theme</label>
          <div className="grid grid-cols-2 gap-4">
            <button
              onClick={() => handleThemeChange('light')}
              className={clsx(
                'p-4 border-2 rounded-lg transition-all',
                currentTheme === 'light'
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              )}
            >
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-white border-2 border-gray-300 rounded-lg"></div>
                <div>
                  <div className="font-medium text-gray-900">Light</div>
                  <div className="text-sm text-gray-500">Default theme</div>
                </div>
              </div>
            </button>

            <button
              onClick={() => handleThemeChange('dark')}
              className={clsx(
                'p-4 border-2 rounded-lg transition-all',
                currentTheme === 'dark'
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              )}
            >
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-gray-900 border-2 border-gray-700 rounded-lg"></div>
                <div>
                  <div className="font-medium text-gray-900">Dark</div>
                  <div className="text-sm text-gray-500">Coming soon</div>
                </div>
              </div>
            </button>
          </div>
        </div>

        <div className="pt-4 border-t">
          <p className="text-sm text-gray-500">
            Theme changes will be applied immediately. Dark mode is currently in development.
          </p>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// System Status Tab
// ============================================================================

function SystemStatusTab() {
  const { data: status, refetch } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => api.getSystemStatus(),
    refetchInterval: 30000, // Refresh every 30s
  });

  const { data: health } = useQuery({
    queryKey: ['system-health'],
    queryFn: () => api.getSystemHealth(),
    refetchInterval: 10000, // Refresh every 10s
  });

  const getHealthColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-600 bg-green-100';
      case 'degraded':
        return 'text-yellow-600 bg-yellow-100';
      case 'unhealthy':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="space-y-6">
      {/* System Health */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">System Health</h3>
          <span className={clsx('px-3 py-1 rounded-full text-sm font-medium', getHealthColor(health?.status || 'unknown'))}>
            {health?.status?.toUpperCase() || 'UNKNOWN'}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-sm text-gray-500">Backend</div>
            <div className="mt-1 flex items-center gap-2">
              {health?.backend_healthy ? (
                <CheckCircle className="w-5 h-5 text-green-500" />
              ) : (
                <XCircle className="w-5 h-5 text-red-500" />
              )}
              <span className="font-medium">{health?.backend_healthy ? 'Online' : 'Offline'}</span>
            </div>
          </div>

          <div>
            <div className="text-sm text-gray-500">Database</div>
            <div className="mt-1 flex items-center gap-2">
              {health?.database_healthy ? (
                <CheckCircle className="w-5 h-5 text-green-500" />
              ) : (
                <XCircle className="w-5 h-5 text-red-500" />
              )}
              <span className="font-medium">{health?.database_healthy ? 'Online' : 'Offline'}</span>
            </div>
          </div>

          <div>
            <div className="text-sm text-gray-500">Version</div>
            <div className="mt-1 font-medium">{health?.version || 'N/A'}</div>
          </div>

          <div>
            <div className="text-sm text-gray-500">Uptime</div>
            <div className="mt-1 font-medium">{health?.uptime_seconds || 0}s</div>
          </div>
        </div>
      </div>

      {/* Resource Usage */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Resource Usage</h3>
          <Button size="sm" variant="ghost" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* CPU */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-700">CPU Usage</span>
              <span className="text-sm font-bold text-gray-900">
                {status?.cpu_usage_percent?.toFixed(1) || 0}%
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all"
                style={{ width: `${status?.cpu_usage_percent || 0}%` }}
              ></div>
            </div>
          </div>

          {/* Memory */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-700">Memory Usage</span>
              <span className="text-sm font-bold text-gray-900">
                {status?.memory_usage_percent?.toFixed(1) || 0}%
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-green-600 h-2 rounded-full transition-all"
                style={{ width: `${status?.memory_usage_percent || 0}%` }}
              ></div>
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {status?.memory_used_mb || 0} MB / {status?.memory_total_mb || 0} MB
            </div>
          </div>

          {/* Disk */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-700">Disk Usage</span>
              <span className="text-sm font-bold text-gray-900">
                {status?.disk_usage_percent?.toFixed(1) || 0}%
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-purple-600 h-2 rounded-full transition-all"
                style={{ width: `${status?.disk_usage_percent || 0}%` }}
              ></div>
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {status?.disk_used_gb || 0} GB / {status?.disk_total_gb || 0} GB
            </div>
          </div>
        </div>

        {/* Database Connections */}
        <div className="mt-6 pt-6 border-t">
          <h4 className="text-sm font-medium text-gray-700 mb-3">Database Connections</h4>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <div className="text-xs text-gray-500">Active</div>
              <div className="mt-1 text-lg font-bold text-gray-900">
                {status?.db_connections_active || 0}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Idle</div>
              <div className="mt-1 text-lg font-bold text-gray-900">
                {status?.db_connections_idle || 0}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500">Max</div>
              <div className="mt-1 text-lg font-bold text-gray-900">
                {status?.db_connections_max || 0}
              </div>
            </div>
          </div>
        </div>

        {/* Agents Connected */}
        <div className="mt-6 pt-6 border-t">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-700">Connected Agents</span>
            <span className="text-2xl font-bold text-blue-600">{status?.agents_connected || 0}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Database Tab
// ============================================================================

function DatabaseTab() {
  const queryClient = useQueryClient();
  const [cleanupTarget, setCleanupTarget] = useState('auditd_events');
  const [retentionDays, setRetentionDays] = useState(90);

  const { data: stats, refetch: refetchStats } = useQuery({
    queryKey: ['database-stats'],
    queryFn: () => api.getDatabaseStats(),
  });

  const cleanupMutation = useMutation({
    mutationFn: ({ target, retentionDays }: { target: string; retentionDays: number }) =>
      api.triggerDatabaseCleanup(target, retentionDays),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['database-stats'] });
      const totalDeleted = data.reduce((sum: number, r: any) => sum + r.deleted_count, 0);
      alert(`Cleanup completed! Deleted ${totalDeleted} records.`);
    },
  });

  const handleCleanup = () => {
    if (!confirm(`Are you sure you want to delete records older than ${retentionDays} days from ${cleanupTarget}? This action cannot be undone.`)) {
      return;
    }
    cleanupMutation.mutate({ target: cleanupTarget, retentionDays });
  };

  return (
    <div className="space-y-6">
      {/* Database Statistics */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Database Statistics</h3>
          <Button size="sm" variant="ghost" onClick={() => refetchStats()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div>
            <div className="text-sm text-gray-500">Total Size</div>
            <div className="mt-1 text-2xl font-bold text-gray-900">{stats?.total_size_mb || 0} MB</div>
          </div>
          <div>
            <div className="text-sm text-gray-500">Targets</div>
            <div className="mt-1 text-2xl font-bold text-blue-600">{stats?.targets_count || 0}</div>
          </div>
          <div>
            <div className="text-sm text-gray-500">Audit Events</div>
            <div className="mt-1 text-2xl font-bold text-purple-600">{stats?.auditd_events_count || 0}</div>
            <div className="text-xs text-gray-500 mt-1">{stats?.auditd_events_size_mb || 0} MB</div>
          </div>
          <div>
            <div className="text-sm text-gray-500">Alerts</div>
            <div className="mt-1 text-2xl font-bold text-orange-600">{stats?.alerts_count || 0}</div>
            <div className="text-xs text-gray-500 mt-1">{stats?.alerts_size_mb || 0} MB</div>
          </div>
        </div>

        <div className="mt-6 pt-6 border-t grid grid-cols-2 gap-4">
          <div>
            <div className="text-sm text-gray-500">Oldest Audit Event</div>
            <div className="mt-1 text-sm font-medium text-gray-900">
              {stats?.oldest_auditd_event ? format(new Date(stats.oldest_auditd_event), 'PPp') : 'N/A'}
            </div>
          </div>
          <div>
            <div className="text-sm text-gray-500">Oldest Alert</div>
            <div className="mt-1 text-sm font-medium text-gray-900">
              {stats?.oldest_alert ? format(new Date(stats.oldest_alert), 'PPp') : 'N/A'}
            </div>
          </div>
        </div>
      </div>

      {/* Database Cleanup */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-orange-500" />
          <h3 className="text-lg font-semibold text-gray-900">Database Cleanup (Hard Delete)</h3>
        </div>

        <p className="text-sm text-gray-600 mb-6">
          Permanently delete old records to free up database space. This action cannot be undone.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Target Table</label>
            <select
              value={cleanupTarget}
              onChange={(e) => setCleanupTarget(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="auditd_events">Audit Events</option>
              <option value="alerts">Alerts (Resolved Only)</option>
              <option value="system_logs">System Logs</option>
              <option value="all">All Tables</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Retention Period (Days)</label>
            <input
              type="number"
              value={retentionDays}
              onChange={(e) => setRetentionDays(parseInt(e.target.value) || 90)}
              min="1"
              max="365"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
            />
          </div>
        </div>

        <Button
          onClick={handleCleanup}
          loading={cleanupMutation.isPending}
          variant="ghost"
          className="mt-4 border-red-300 text-red-600 hover:bg-red-50"
        >
          <Trash2 className="w-4 h-4 mr-2" />
          Delete Records Older Than {retentionDays} Days
        </Button>
      </div>
    </div>
  );
}

// ============================================================================
// API Keys Tab
// ============================================================================

function ApiKeysTab() {
  const queryClient = useQueryClient();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyDescription, setNewKeyDescription] = useState('');
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(['read']);
  const [newKeyExpireDays, setNewKeyExpireDays] = useState<number | undefined>(365);
  const [createdKey, setCreatedKey] = useState<string | null>(null);

  const { data: apiKeys } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => api.listApiKeys(),
  });

  const createKeyMutation = useMutation({
    mutationFn: (data: { name: string; description?: string; scopes: string[]; expires_in_days?: number }) =>
      api.createApiKey(data),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setCreatedKey(data.key);
      setShowCreateForm(false);
      setNewKeyName('');
      setNewKeyDescription('');
      setNewKeyScopes(['read']);
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (id: number) => api.revokeApiKey(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
  });

  const handleCreateKey = () => {
    if (!newKeyName) {
      alert('Please enter a key name');
      return;
    }
    createKeyMutation.mutate({
      name: newKeyName,
      description: newKeyDescription,
      scopes: newKeyScopes,
      expires_in_days: newKeyExpireDays,
    });
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    alert('API key copied to clipboard');
  };

  const columns = [
    {
      key: 'name',
      label: 'Name',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">{row.name}</div>
          {row.description && <div className="text-sm text-gray-500">{row.description}</div>}
        </div>
      ),
    },
    {
      key: 'key_prefix',
      label: 'Key',
      render: (row: any) => (
        <code className="text-xs bg-gray-100 px-2 py-1 rounded">{row.key_prefix}...</code>
      ),
    },
    {
      key: 'scopes',
      label: 'Scopes',
      render: (row: any) => (
        <div className="flex flex-wrap gap-1">
          {row.scopes.map((scope: string) => (
            <span key={scope} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
              {scope}
            </span>
          ))}
        </div>
      ),
    },
    {
      key: 'is_active',
      label: 'Status',
      render: (row: any) => (
        <StatusBadge status={row.is_active ? 'active' : 'revoked'} />
      ),
    },
    {
      key: 'expires_at',
      label: 'Expires',
      render: (row: any) => (
        <div className="text-sm text-gray-600">
          {row.expires_at ? format(new Date(row.expires_at), 'PP') : 'Never'}
        </div>
      ),
    },
    {
      key: 'last_used_at',
      label: 'Last Used',
      render: (row: any) => (
        <div className="text-sm text-gray-600">
          {row.last_used_at ? format(new Date(row.last_used_at), 'PPp') : 'Never'}
        </div>
      ),
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row: any) => (
        <div>
          {row.is_active && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                if (confirm('Are you sure you want to revoke this API key?')) {
                  revokeKeyMutation.mutate(row.id);
                }
              }}
              className="text-red-600 hover:text-red-700"
            >
              Revoke
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Created Key Modal */}
      {createdKey && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-6">
          <div className="flex items-start gap-3">
            <CheckCircle className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h4 className="text-lg font-semibold text-green-900 mb-2">API Key Created Successfully</h4>
              <p className="text-sm text-green-800 mb-3">
                Make sure to copy your API key now. You won't be able to see it again!
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-white border border-green-300 px-3 py-2 rounded text-sm font-mono">
                  {createdKey}
                </code>
                <Button size="sm" onClick={() => handleCopyKey(createdKey)}>
                  <Copy className="w-4 h-4 mr-2" />
                  Copy
                </Button>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setCreatedKey(null)}
                className="mt-3"
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Create API Key Form */}
      {showCreateForm && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New API Key</h3>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
                placeholder="Production API Key"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
              <input
                type="text"
                value={newKeyDescription}
                onChange={(e) => setNewKeyDescription(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
                placeholder="Used for FireDog integration"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Scopes</label>
              <div className="space-y-2">
                {['read', 'write', 'admin'].map((scope) => (
                  <label key={scope} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={newKeyScopes.includes(scope)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setNewKeyScopes([...newKeyScopes, scope]);
                        } else {
                          setNewKeyScopes(newKeyScopes.filter((s) => s !== scope));
                        }
                      }}
                      className="rounded border-gray-300"
                    />
                    <span className="text-sm text-gray-700">{scope}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Expires In (Days)</label>
              <input
                type="number"
                value={newKeyExpireDays || ''}
                onChange={(e) => setNewKeyExpireDays(e.target.value ? parseInt(e.target.value) : undefined)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:border-blue-500 focus:ring-blue-500"
                placeholder="365 (leave empty for no expiration)"
              />
            </div>

            <div className="flex gap-2">
              <Button onClick={handleCreateKey} loading={createKeyMutation.isPending}>
                <Plus className="w-4 h-4 mr-2" />
                Create API Key
              </Button>
              <Button variant="ghost" onClick={() => setShowCreateForm(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* API Keys List */}
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">API Keys</h3>
            {!showCreateForm && (
              <Button size="sm" onClick={() => setShowCreateForm(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Create API Key
              </Button>
            )}
          </div>
        </div>
        <Table
          data={apiKeys || []}
          columns={columns}
          emptyMessage="No API keys found. Create your first API key to get started."
        />
      </div>
    </div>
  );
}

// ============================================================================
// Integrations Tab
// ============================================================================

function IntegrationsTab() {
  const queryClient = useQueryClient();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingIntegration, setEditingIntegration] = useState<any>(null);

  const { data: integrations } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => api.listIntegrations(),
  });

  const createIntegrationMutation = useMutation({
    mutationFn: (data: any) => api.createIntegration(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setShowCreateForm(false);
    },
  });

  const updateIntegrationMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: any }) => api.updateIntegration(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setEditingIntegration(null);
    },
  });

  const deleteIntegrationMutation = useMutation({
    mutationFn: (id: number) => api.deleteIntegration(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });

  const testIntegrationMutation = useMutation({
    mutationFn: (id: number) => api.testIntegration(id),
    onSuccess: (data) => {
      alert(`Test ${data.status}: ${data.message}`);
    },
  });

  const syncMutation = useMutation({
    mutationFn: (id: number) => api.triggerSync(id),
    onSuccess: () => {
      alert('Sync triggered successfully');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });

  return (
    <div className="space-y-6">
      {/* Create/Edit Form */}
      {(showCreateForm || editingIntegration) && (
        <IntegrationForm
          integration={editingIntegration}
          onSave={(data) => {
            if (editingIntegration) {
              updateIntegrationMutation.mutate({ id: editingIntegration.id, data });
            } else {
              createIntegrationMutation.mutate(data);
            }
          }}
          onCancel={() => {
            setShowCreateForm(false);
            setEditingIntegration(null);
          }}
          loading={createIntegrationMutation.isPending || updateIntegrationMutation.isPending}
        />
      )}

      {/* Integrations List */}
      <div className="bg-white rounded-lg shadow">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">External Integrations</h3>
            {!showCreateForm && !editingIntegration && (
              <Button size="sm" onClick={() => setShowCreateForm(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Add Integration
              </Button>
            )}
          </div>
        </div>

        <div className="divide-y divide-gray-200">
          {integrations?.map((integration: any) => (
            <div key={integration.id} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h4 className="text-lg font-medium text-gray-900">{integration.name}</h4>
                    <span className={clsx(
                      'px-2 py-0.5 rounded-full text-xs font-medium',
                      integration.enabled
                        ? 'bg-green-100 text-green-800'
                        : 'bg-gray-100 text-gray-800'
                    )}>
                      {integration.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                      {integration.integration_type}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4 text-sm">
                    {integration.hostname && (
                      <div>
                        <div className="text-gray-500">Hostname</div>
                        <div className="font-medium text-gray-900">{integration.hostname}</div>
                      </div>
                    )}
                    {integration.ip_address && (
                      <div>
                        <div className="text-gray-500">IP Address</div>
                        <div className="font-medium text-gray-900">{integration.ip_address}</div>
                      </div>
                    )}
                    {integration.port && (
                      <div>
                        <div className="text-gray-500">Port</div>
                        <div className="font-medium text-gray-900">{integration.port}</div>
                      </div>
                    )}
                    {integration.last_sync_at && (
                      <div>
                        <div className="text-gray-500">Last Sync</div>
                        <div className="font-medium text-gray-900">
                          {format(new Date(integration.last_sync_at), 'PPp')}
                        </div>
                      </div>
                    )}
                  </div>

                  {integration.last_sync_status && (
                    <div className="mt-3">
                      <span className={clsx(
                        'inline-flex items-center gap-1 text-xs',
                        integration.last_sync_status === 'success' ? 'text-green-600' :
                        integration.last_sync_status === 'failed' ? 'text-red-600' :
                        'text-yellow-600'
                      )}>
                        {integration.last_sync_status === 'success' && <CheckCircle className="w-3 h-3" />}
                        {integration.last_sync_status === 'failed' && <XCircle className="w-3 h-3" />}
                        Last sync: {integration.last_sync_status}
                      </span>
                      {integration.last_sync_error && (
                        <div className="text-xs text-red-600 mt-1">{integration.last_sync_error}</div>
                      )}
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => testIntegrationMutation.mutate(integration.id)}
                    loading={testIntegrationMutation.isPending}
                  >
                    Test
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => syncMutation.mutate(integration.id)}
                    loading={syncMutation.isPending}
                    disabled={!integration.enabled}
                  >
                    <RefreshCw className="w-4 h-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setEditingIntegration(integration)}
                  >
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      if (confirm('Are you sure you want to delete this integration?')) {
                        deleteIntegrationMutation.mutate(integration.id);
                      }
                    }}
                    className="text-red-600 hover:text-red-700"
                  >
                    Delete
                  </Button>
                </div>
              </div>
            </div>
          ))}

          {(!integrations || integrations.length === 0) && !showCreateForm && (
            <div className="p-12 text-center text-gray-500">
              No integrations configured. Add FireDog or CyberSheppard slave integration to get started.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Integration Form Component
function IntegrationForm({
  integration,
  onSave,
  onCancel,
  loading,
}: {
  integration?: any;
  onSave: (data: any) => void;
  onCancel: () => void;
  loading: boolean;
}) {
  const [formData, setFormData] = useState({
    name: integration?.name || '',
    type: integration?.integration_type || 'firedog',
    api_key: '',
    hostname: integration?.hostname || '',
    ip_address: integration?.ip_address || '',
    port: integration?.port || 8080,
    use_ssl: integration?.use_ssl ?? true,
    sync_mode: integration?.sync_mode || 'pull',
    sync_interval: integration?.sync_interval || 300,
    enabled: integration?.enabled ?? false,
  });

  const handleSubmit = () => {
    if (!formData.name) {
      alert('Please enter a name');
      return;
    }
    onSave(formData);
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">
        {integration ? 'Edit Integration' : 'Create Integration'}
      </h3>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
            placeholder="FireDog Production"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Type *</label>
          <select
            value={formData.type}
            onChange={(e) => setFormData({ ...formData, type: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
          >
            <option value="firedog">FireDog</option>
            <option value="cybersheppard_slave">CyberSheppard Slave</option>
            <option value="sentinel_core">Sentinel Core</option>
            <option value="custom">Custom</option>
          </select>
        </div>

        <div className="col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-1">API Key</label>
          <input
            type="password"
            value={formData.api_key}
            onChange={(e) => setFormData({ ...formData, api_key: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
            placeholder="Enter shared API key"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Hostname</label>
          <input
            type="text"
            value={formData.hostname}
            onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
            placeholder="firedog.example.com"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">IP Address</label>
          <input
            type="text"
            value={formData.ip_address}
            onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
            placeholder="192.168.1.100"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
          <input
            type="number"
            value={formData.port}
            onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Sync Mode</label>
          <select
            value={formData.sync_mode}
            onChange={(e) => setFormData({ ...formData, sync_mode: e.target.value })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
          >
            <option value="pull">Pull (Fetch data)</option>
            <option value="push">Push (Send data)</option>
            <option value="bidirectional">Bidirectional</option>
          </select>
        </div>

        <div className="col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-1">Sync Interval (seconds)</label>
          <input
            type="number"
            value={formData.sync_interval}
            onChange={(e) => setFormData({ ...formData, sync_interval: parseInt(e.target.value) })}
            className="w-full px-3 py-2 border border-gray-300 rounded-md"
          />
        </div>

        <div className="col-span-2">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={formData.use_ssl}
              onChange={(e) => setFormData({ ...formData, use_ssl: e.target.checked })}
              className="rounded border-gray-300"
            />
            <span className="text-sm text-gray-700">Use SSL/TLS</span>
          </label>
        </div>

        <div className="col-span-2">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="rounded border-gray-300"
            />
            <span className="text-sm text-gray-700">Enable integration</span>
          </label>
        </div>
      </div>

      <div className="flex gap-2 mt-6">
        <Button onClick={handleSubmit} loading={loading}>
          <Save className="w-4 h-4 mr-2" />
          Save Integration
        </Button>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
