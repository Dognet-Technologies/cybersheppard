import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Package,
  Download,
  Trash2,
  Power,
  PowerOff,
  Settings as SettingsIcon,
  AlertTriangle,
  CheckCircle,
  Shield,
  Lock,
  Filter,
  Search,
  RefreshCw,
} from 'lucide-react';
import api from '../services/api';

type FilterType = 'all' | 'installed' | 'active' | 'available';

export default function Plugins() {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<FilterType>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedPlugin, setSelectedPlugin] = useState<any>(null);
  const [showWarning, setShowWarning] = useState(false);
  const [pluginToInstall, setPluginToInstall] = useState<any>(null);

  const { data: availablePlugins, isLoading: loadingAvailable } = useQuery({
    queryKey: ['plugins-available'],
    queryFn: () => api.getAvailablePlugins(),
  });

  const { data: installedPlugins, isLoading: loadingInstalled } = useQuery({
    queryKey: ['plugins-installed'],
    queryFn: () => api.getInstalledPlugins(),
  });

  const installMutation = useMutation({
    mutationFn: (registryId: number) => api.installPlugin(registryId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins-available'] });
      queryClient.invalidateQueries({ queryKey: ['plugins-installed'] });
      setShowWarning(false);
      setPluginToInstall(null);
    },
  });

  const uninstallMutation = useMutation({
    mutationFn: (pluginId: number) => api.uninstallPlugin(pluginId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins-available'] });
      queryClient.invalidateQueries({ queryKey: ['plugins-installed'] });
    },
  });

  const enableMutation = useMutation({
    mutationFn: (pluginId: number) => api.enablePlugin(pluginId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins-installed'] });
    },
  });

  const disableMutation = useMutation({
    mutationFn: (pluginId: number) => api.disablePlugin(pluginId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins-installed'] });
    },
  });

  const handleInstallClick = (plugin: any) => {
    // Show warning for community plugins
    if (plugin.trust_level === 'community') {
      setPluginToInstall(plugin);
      setShowWarning(true);
    } else {
      installMutation.mutate(plugin.id);
    }
  };

  const confirmInstall = () => {
    if (pluginToInstall) {
      installMutation.mutate(pluginToInstall.id);
    }
  };

  // Merge and filter plugins
  const allPlugins = availablePlugins?.plugins || [];
  const installed = installedPlugins?.plugins || [];

  const filteredPlugins = allPlugins.filter((plugin: any) => {
    const matchesSearch =
      plugin.plugin_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      plugin.description?.toLowerCase().includes(searchTerm.toLowerCase());

    const isInstalled = plugin.is_installed;
    const installedPlugin = installed.find(
      (p: any) => p.plugin_name === plugin.plugin_name && p.version === plugin.version
    );
    const isActive = installedPlugin?.is_enabled;

    if (filter === 'installed') return isInstalled && matchesSearch;
    if (filter === 'active') return isActive && matchesSearch;
    if (filter === 'available') return !isInstalled && matchesSearch;
    return matchesSearch;
  });

  const stats = {
    total: allPlugins.length,
    installed: allPlugins.filter((p: any) => p.is_installed).length,
    active: installed.filter((p: any) => p.is_enabled).length,
  };

  if (loadingAvailable || loadingInstalled) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading plugins...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Plugin Manager</h1>
          <p className="text-gray-500 mt-1">Extend CyberSheppard with plugins</p>
        </div>
        <button
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ['plugins-available'] });
            queryClient.invalidateQueries({ queryKey: ['plugins-installed'] });
          }}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          icon={<Package className="w-6 h-6 text-blue-600" />}
          label="Total Plugins"
          value={stats.total}
          bgColor="bg-blue-50"
        />
        <StatCard
          icon={<Download className="w-6 h-6 text-green-600" />}
          label="Installed"
          value={stats.installed}
          bgColor="bg-green-50"
        />
        <StatCard
          icon={<Power className="w-6 h-6 text-purple-600" />}
          label="Active"
          value={stats.active}
          bgColor="bg-purple-50"
        />
      </div>

      {/* Filters & Search */}
      <div className="bg-white rounded-lg shadow-sm p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-700">Filter:</span>
            </div>
            {(['all', 'installed', 'active', 'available'] as FilterType[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
                  filter === f
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-2">
            <Search className="w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search plugins..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-64"
            />
          </div>
        </div>
      </div>

      {/* Plugins Table */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Plugin
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Version
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Language
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Quality
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Source
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                  Status
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredPlugins.map((plugin: any) => {
                const installedPlugin = installed.find(
                  (p: any) =>
                    p.plugin_name === plugin.plugin_name && p.version === plugin.version
                );

                return (
                  <tr key={plugin.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div>
                        <div className="font-semibold text-gray-900">{plugin.plugin_name}</div>
                        <div className="text-sm text-gray-500">{plugin.description}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="text-sm text-gray-900">{plugin.version}</span>
                      <br />
                      <span className="text-xs text-gray-500">
                        {plugin.stability_level || 'stable'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {plugin.language}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getQualityBadge(plugin.quality)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getTrustBadge(plugin.trust_level, plugin.is_official)}
                      <br />
                      <span className="text-xs text-gray-500">{plugin.repository_name}</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getStatusBadge(plugin.is_installed, installedPlugin)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
                      <div className="flex justify-end space-x-2">
                        {!plugin.is_installed ? (
                          <button
                            onClick={() => handleInstallClick(plugin)}
                            className="text-blue-600 hover:text-blue-700 flex items-center space-x-1"
                          >
                            <Download className="w-4 h-4" />
                            <span>Install</span>
                          </button>
                        ) : (
                          <>
                            {installedPlugin?.is_enabled ? (
                              <button
                                onClick={() => disableMutation.mutate(installedPlugin.id)}
                                className="text-orange-600 hover:text-orange-700 flex items-center space-x-1"
                              >
                                <PowerOff className="w-4 h-4" />
                                <span>Disable</span>
                              </button>
                            ) : (
                              <button
                                onClick={() => enableMutation.mutate(installedPlugin.id)}
                                className="text-green-600 hover:text-green-700 flex items-center space-x-1"
                              >
                                <Power className="w-4 h-4" />
                                <span>Enable</span>
                              </button>
                            )}
                            <button
                              onClick={() => setSelectedPlugin(installedPlugin)}
                              className="text-gray-600 hover:text-gray-700"
                            >
                              <SettingsIcon className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => uninstallMutation.mutate(installedPlugin.id)}
                              className="text-red-600 hover:text-red-700"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {filteredPlugins.length === 0 && (
            <div className="text-center py-12">
              <Package className="w-12 h-12 text-gray-400 mx-auto mb-3" />
              <p className="text-gray-500">No plugins found</p>
              <p className="text-sm text-gray-400">Try adjusting your filters or search term</p>
            </div>
          )}
        </div>
      </div>

      {/* Warning Modal */}
      {showWarning && pluginToInstall && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <div className="flex items-center space-x-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-orange-600" />
              <h3 className="text-lg font-semibold text-gray-900">Security Warning</h3>
            </div>

            <div className="space-y-3 mb-6">
              <p className="text-sm text-gray-700">
                You are about to install a <strong>COMMUNITY</strong> plugin:
              </p>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="font-semibold text-gray-900">{pluginToInstall.plugin_name}</div>
                <div className="text-sm text-gray-600">{pluginToInstall.description}</div>
                <div className="text-xs text-gray-500 mt-2">
                  Version: {pluginToInstall.version} | Owner: {pluginToInstall.owner}
                </div>
              </div>

              <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                <p className="text-sm text-orange-900 font-medium mb-2">⚠️ WARNING:</p>
                <ul className="text-xs text-orange-800 space-y-1 list-disc list-inside">
                  <li>This is a COMMUNITY plugin, NOT verified by CyberSheppard</li>
                  <li>It may contain bugs or security vulnerabilities</li>
                  <li>Only install from sources you trust</li>
                  <li>Review permissions and resource requirements</li>
                </ul>
              </div>

              {pluginToInstall.permissions && pluginToInstall.permissions.length > 0 && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                  <p className="text-sm font-medium text-blue-900 mb-2">
                    This plugin requires:
                  </p>
                  <ul className="text-xs text-blue-800 space-y-1">
                    {pluginToInstall.permissions.map((perm: string, idx: number) => (
                      <li key={idx}>• {perm}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => {
                  setShowWarning(false);
                  setPluginToInstall(null);
                }}
                className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
              >
                Cancel
              </button>
              <button
                onClick={confirmInstall}
                className="px-4 py-2 text-white bg-orange-600 rounded-lg hover:bg-orange-700"
              >
                Install Anyway
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Configure Modal */}
      {selectedPlugin && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-lg w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Configure {selectedPlugin.plugin_name}
            </h3>
            <p className="text-sm text-gray-600 mb-4">
              Plugin configuration will be available in the next update.
            </p>
            <div className="flex justify-end">
              <button
                onClick={() => setSelectedPlugin(null)}
                className="px-4 py-2 text-white bg-blue-600 rounded-lg hover:bg-blue-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, bgColor }: any) {
  return (
    <div className={`${bgColor} rounded-lg p-4`}>
      <div className="flex items-center space-x-3">
        {icon}
        <div>
          <p className="text-sm text-gray-600">{label}</p>
          <p className="text-2xl font-bold text-gray-900">{value}</p>
        </div>
      </div>
    </div>
  );
}

function getTrustBadge(trustLevel: string, isOfficial: boolean) {
  if (isOfficial || trustLevel === 'official') {
    return (
      <span className="inline-flex items-center space-x-1 bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
        <CheckCircle className="w-3 h-3" />
        <span>OFFICIAL</span>
      </span>
    );
  }
  if (trustLevel === 'community') {
    return (
      <span className="inline-flex items-center space-x-1 bg-orange-100 text-orange-800 text-xs px-2 py-1 rounded">
        <AlertTriangle className="w-3 h-3" />
        <span>COMMUNITY</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center space-x-1 bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
      <Lock className="w-3 h-3" />
      <span>PRIVATE</span>
    </span>
  );
}

function getQualityBadge(quality: string) {
  const badges: any = {
    eccellente: 'bg-green-100 text-green-800',
    ottima: 'bg-blue-100 text-blue-800',
    buona: 'bg-yellow-100 text-yellow-800',
    scarsa: 'bg-red-100 text-red-800',
  };

  return (
    <span className={`${badges[quality] || 'bg-gray-100 text-gray-800'} text-xs px-2 py-1 rounded`}>
      {quality || 'N/A'}
    </span>
  );
}

function getStatusBadge(isInstalled: boolean, installedPlugin: any) {
  if (!isInstalled) {
    return (
      <span className="bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded">Not Installed</span>
    );
  }
  if (installedPlugin?.is_enabled) {
    return (
      <span className="inline-flex items-center space-x-1 bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
        <Power className="w-3 h-3" />
        <span>Active</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center space-x-1 bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded">
      <PowerOff className="w-3 h-3" />
      <span>Disabled</span>
    </span>
  );
}
