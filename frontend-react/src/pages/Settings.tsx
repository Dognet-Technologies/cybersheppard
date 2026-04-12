// ============================================================================
// Settings Page - Comprehensive system settings management
// ============================================================================

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings as SettingsIcon,
  User,
  Palette,
  Database,
  Key,
  Activity,
  Shield,
  Save,
  Trash2,
  Plus,
  Copy,
  CheckCircle,
  AlertCircle,
} from 'lucide-react';
import api from '../services/api';
import { useAuthStore } from '../stores/authStore';

type TabType = 'user' | 'system' | 'themes' | 'api-keys' | 'health' | 'database';

export default function Settings() {
  const [activeTab, setActiveTab] = useState<TabType>('user');
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-500 mt-1">Manage system and user preferences</p>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6" aria-label="Tabs">
            <TabButton
              icon={<User className="w-4 h-4" />}
              label="User"
              active={activeTab === 'user'}
              onClick={() => setActiveTab('user')}
            />
            <TabButton
              icon={<SettingsIcon className="w-4 h-4" />}
              label="System"
              active={activeTab === 'system'}
              onClick={() => setActiveTab('system')}
            />
            <TabButton
              icon={<Palette className="w-4 h-4" />}
              label="Themes"
              active={activeTab === 'themes'}
              onClick={() => setActiveTab('themes')}
            />
            <TabButton
              icon={<Key className="w-4 h-4" />}
              label="API Keys"
              active={activeTab === 'api-keys'}
              onClick={() => setActiveTab('api-keys')}
            />
            <TabButton
              icon={<Activity className="w-4 h-4" />}
              label="Health"
              active={activeTab === 'health'}
              onClick={() => setActiveTab('health')}
            />
            <TabButton
              icon={<Database className="w-4 h-4" />}
              label="Database"
              active={activeTab === 'database'}
              onClick={() => setActiveTab('database')}
            />
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6">
          {activeTab === 'user' && <UserSettings />}
          {activeTab === 'system' && <SystemSettings />}
          {activeTab === 'themes' && <ThemeSettings />}
          {activeTab === 'api-keys' && <ApiKeysSettings />}
          {activeTab === 'health' && <HealthCheckSettings />}
          {activeTab === 'database' && <DatabaseSettings />}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// TAB COMPONENTS
// ============================================================================

function TabButton({ icon, label, active, onClick }: any) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
        active
          ? 'border-blue-500 text-blue-600'
          : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
      }`}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

// ============================================================================
// USER SETTINGS
// ============================================================================

function UserSettings() {
  const { user } = useAuthStore();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const changePasswordMutation = useMutation({
    mutationFn: (data: { current_password: string; new_password: string }) =>
      api.changePassword(data),
    onSuccess: () => {
      alert('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    },
    onError: (error: any) => {
      alert(`Error: ${error.response?.data?.error || 'Failed to change password'}`);
    },
  });

  const handleChangePassword = () => {
    if (newPassword !== confirmPassword) {
      alert('New passwords do not match');
      return;
    }
    if (newPassword.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }
    changePasswordMutation.mutate({
      current_password: currentPassword,
      new_password: newPassword,
    });
  };

  return (
    <div className="space-y-6">
      {/* User Info */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">User Information</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={user?.username || ''}
              disabled
              className="w-full border border-gray-300 rounded-lg px-3 py-2 bg-gray-50"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
            <input
              type="text"
              value={user?.role || ''}
              disabled
              className="w-full border border-gray-300 rounded-lg px-3 py-2 bg-gray-50"
            />
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Change Password</h3>
        <div className="space-y-4 max-w-md">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Current Password
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Confirm New Password
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2"
            />
          </div>
          <button
            onClick={handleChangePassword}
            disabled={!currentPassword || !newPassword || !confirmPassword}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
          >
            <Save className="w-4 h-4" />
            <span>Change Password</span>
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// SYSTEM SETTINGS
// ============================================================================

function SystemSettings() {
  const { data: settings, isLoading } = useQuery({
    queryKey: ['system-settings'],
    queryFn: () => api.getSystemSettings(),
  });

  const updateSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) =>
      api.updateSystemSetting(key, value),
    onSuccess: () => {
      alert('Setting updated successfully');
    },
  });

  if (isLoading) return <div>Loading...</div>;

  const categories = ['database', 'security', 'monitoring', 'integration', 'general'];

  return (
    <div className="space-y-6">
      {categories.map((category) => {
        const categorySettings = settings?.settings?.filter(
          (s: any) => s.category === category
        );
        if (!categorySettings || categorySettings.length === 0) return null;

        return (
          <div key={category}>
            <h3 className="text-lg font-semibold text-gray-900 mb-4 capitalize">
              {category.replace('_', ' ')} Settings
            </h3>
            <div className="space-y-3">
              {categorySettings.map((setting: any) => (
                <SettingRow key={setting.id} setting={setting} onUpdate={updateSettingMutation} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SettingRow({ setting, onUpdate }: any) {
  const [value, setValue] = useState(setting.setting_value || '');
  const [editing, setEditing] = useState(false);

  const handleSave = () => {
    onUpdate.mutate({ key: setting.setting_key, value });
    setEditing(false);
  };

  return (
    <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
      <div className="flex-1">
        <div className="font-medium text-gray-900">{setting.setting_key}</div>
        <div className="text-sm text-gray-500">{setting.description}</div>
      </div>
      <div className="flex items-center space-x-2">
        {editing ? (
          <>
            {setting.setting_type === 'boolean' ? (
              <select
                value={value}
                onChange={(e) => setValue(e.target.value)}
                className="border border-gray-300 rounded px-2 py-1"
              >
                <option value="true">True</option>
                <option value="false">False</option>
              </select>
            ) : (
              <input
                type={setting.setting_type === 'number' ? 'number' : 'text'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                className="border border-gray-300 rounded px-2 py-1 w-32"
                disabled={!setting.is_editable}
              />
            )}
            <button
              onClick={handleSave}
              className="bg-green-600 text-white px-3 py-1 rounded hover:bg-green-700"
            >
              Save
            </button>
            <button
              onClick={() => {
                setValue(setting.setting_value || '');
                setEditing(false);
              }}
              className="bg-gray-300 text-gray-700 px-3 py-1 rounded hover:bg-gray-400"
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            <span className="text-gray-900 font-mono">{value}</span>
            {setting.is_editable && (
              <button
                onClick={() => setEditing(true)}
                className="text-blue-600 hover:text-blue-700"
              >
                Edit
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// THEME SETTINGS
// ============================================================================

function ThemeSettings() {
  const [selectedTheme, setSelectedTheme] = useState('dark');

  const themes = [
    { id: 'dark', name: 'Professional Dark', bg: 'bg-gray-800', description: 'Dark theme with blue accents' },
    { id: 'black', name: 'Pure Black', bg: 'bg-black', description: 'OLED-friendly black theme' },
    { id: 'slate', name: 'Slate', bg: 'bg-slate-900', description: 'Muted slate dark theme' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Choose Theme</h3>
        <div className="grid grid-cols-3 gap-4">
          {themes.map((theme) => (
            <div
              key={theme.id}
              onClick={() => setSelectedTheme(theme.id)}
              className={`cursor-pointer border-2 rounded-lg p-4 ${
                selectedTheme === theme.id ? 'border-blue-500' : 'border-gray-200'
              }`}
            >
              <div className={`${theme.bg} h-24 rounded-lg mb-3`} />
              <div className="font-semibold text-gray-900">{theme.name}</div>
              <div className="text-sm text-gray-500">{theme.description}</div>
            </div>
          ))}
        </div>
      </div>
      <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
        <Save className="w-4 h-4" />
        <span>Apply Theme</span>
      </button>
    </div>
  );
}

// ============================================================================
// API KEYS SETTINGS
// ============================================================================

function ApiKeysSettings() {
  const [showNewKeyModal, setShowNewKeyModal] = useState(false);
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);

  const { data: apiKeys, isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => api.getApiKeys(),
  });

  const generateKeyMutation = useMutation({
    mutationFn: (data: { name: string; service: string; expires_days: number }) =>
      api.generateApiKey(data),
    onSuccess: (data) => {
      setGeneratedKey(data.token);
      setShowNewKeyModal(false);
    },
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (id: number) => api.revokeApiKey(id),
    onSuccess: () => {
      alert('API key revoked');
    },
  });

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold text-gray-900">API Keys</h3>
        <button
          onClick={() => setShowNewKeyModal(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
        >
          <Plus className="w-4 h-4" />
          <span>Generate New Key</span>
        </button>
      </div>

      <div className="space-y-3">
        {apiKeys?.api_keys?.map((key: any) => (
          <div key={key.id} className="border border-gray-200 rounded-lg p-4">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="font-semibold text-gray-900">{key.name}</div>
                <div className="text-sm text-gray-500">{key.description}</div>
                <div className="mt-2 flex items-center space-x-4 text-xs text-gray-600">
                  <span className="font-mono bg-gray-100 px-2 py-1 rounded">{key.key_prefix}...</span>
                  <span>Service: {key.service || 'General'}</span>
                  <span>Created: {new Date(key.created_at).toLocaleDateString()}</span>
                  {key.expires_at && (
                    <span>Expires: {new Date(key.expires_at).toLocaleDateString()}</span>
                  )}
                </div>
              </div>
              <button
                onClick={() => revokeKeyMutation.mutate(key.id)}
                className="text-red-600 hover:text-red-700 ml-4"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Generated Key Modal */}
      {generatedKey && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-lg w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">API Key Generated</h3>
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
              <p className="text-sm text-yellow-800 mb-2">
                <strong>Important:</strong> Copy this key now. It will not be shown again.
              </p>
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  value={generatedKey}
                  readOnly
                  className="flex-1 border border-gray-300 rounded px-3 py-2 font-mono text-sm"
                />
                <button
                  onClick={() => navigator.clipboard.writeText(generatedKey)}
                  className="bg-blue-600 text-white px-3 py-2 rounded hover:bg-blue-700"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>
            <button
              onClick={() => setGeneratedKey(null)}
              className="w-full bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// HEALTH CHECK SETTINGS
// ============================================================================

function HealthCheckSettings() {
  const { data: health, isLoading, refetch } = useQuery({
    queryKey: ['health-check'],
    queryFn: () => api.getHealthCheck(),
  });

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold text-gray-900">System Health</h3>
        <button
          onClick={() => refetch()}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
        >
          <Activity className="w-4 h-4" />
          <span>Refresh</span>
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <HealthCard
          title="Database"
          status={health?.health?.database?.status}
          metrics={[
            { label: 'Response Time', value: `${health?.health?.database?.response_time_ms}ms` },
            { label: 'Pool Size', value: health?.health?.database?.connection_pool_size },
            { label: 'Idle Connections', value: health?.health?.database?.connection_pool_idle },
          ]}
        />
        <HealthCard
          title="API"
          status={health?.health?.api?.status}
          metrics={[
            { label: 'Status', value: 'Running' },
            { label: 'Uptime', value: `${health?.health?.api?.uptime_seconds}s` },
          ]}
        />
        <HealthCard
          title="Integrations"
          status="info"
          metrics={[
            { label: 'Sentinel Core', value: health?.health?.integrations?.sentinel_core },
            { label: 'FireDog', value: health?.health?.integrations?.firedog },
          ]}
        />
      </div>
    </div>
  );
}

function HealthCard({ title, status, metrics }: any) {
  const statusColors = {
    healthy: 'bg-green-100 text-green-800',
    degraded: 'bg-yellow-100 text-yellow-800',
    error: 'bg-red-100 text-red-800',
    info: 'bg-blue-100 text-blue-800',
  };

  return (
    <div className="border border-gray-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-semibold text-gray-900">{title}</h4>
        <span className={`text-xs px-2 py-1 rounded ${statusColors[status] || statusColors.info}`}>
          {status}
        </span>
      </div>
      <div className="space-y-2">
        {metrics?.map((metric: any, idx: number) => (
          <div key={idx} className="flex justify-between text-sm">
            <span className="text-gray-600">{metric.label}:</span>
            <span className="font-medium text-gray-900">{metric.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// DATABASE SETTINGS
// ============================================================================

function DatabaseSettings() {
  const [resetConfirmation, setResetConfirmation] = useState('');

  const cleanupMutation = useMutation({
    mutationFn: () => api.cleanupOldData(),
    onSuccess: (data) => {
      alert(`Cleanup complete: ${data.deleted_count} records deleted`);
    },
  });

  const resetMutation = useMutation({
    mutationFn: (confirmation: string) => api.resetDatabase(confirmation),
    onSuccess: () => {
      alert('Database reset complete');
      setResetConfirmation('');
    },
    onError: (error: any) => {
      alert(`Error: ${error.response?.data?.error || 'Reset failed'}`);
    },
  });

  return (
    <div className="space-y-6">
      {/* Cleanup */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-2">Data Cleanup</h3>
        <p className="text-sm text-gray-600 mb-4">
          Remove old resolved violations based on the retention policy
        </p>
        <button
          onClick={() => cleanupMutation.mutate()}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
        >
          <Trash2 className="w-4 h-4" />
          <span>Run Cleanup</span>
        </button>
      </div>

      {/* Hard Reset */}
      <div className="border-t border-gray-200 pt-6">
        <h3 className="text-lg font-semibold text-red-600 mb-2">⚠️ Danger Zone</h3>
        <p className="text-sm text-gray-600 mb-4">
          <strong>Hard Reset:</strong> This will delete ALL monitoring data. This action cannot be undone.
        </p>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
          <p className="text-sm text-red-800 mb-2">
            Type <code className="bg-red-100 px-2 py-1 rounded">HARD_RESET_CONFIRMED</code> to confirm
          </p>
          <input
            type="text"
            value={resetConfirmation}
            onChange={(e) => setResetConfirmation(e.target.value)}
            placeholder="Type confirmation here"
            className="w-full border border-red-300 rounded px-3 py-2 mb-3"
          />
          <button
            onClick={() => resetMutation.mutate(resetConfirmation)}
            disabled={resetConfirmation !== 'HARD_RESET_CONFIRMED'}
            className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
          >
            <AlertCircle className="w-4 h-4" />
            <span>Reset Database</span>
          </button>
        </div>
      </div>
    </div>
  );
}
