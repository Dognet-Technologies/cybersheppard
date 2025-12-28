import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Shield, RefreshCw, CheckCircle, XCircle, Activity, AlertCircle } from 'lucide-react';

export default function Integrations() {
  const { data: status, isLoading } = useQuery({
    queryKey: ['integration-status'],
    queryFn: () => api.getIntegrationStatus(),
    refetchInterval: 30000,
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Integrations</h1>
          <p className="text-gray-600 mt-1">
            External system integrations and synchronization status
          </p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-600">
          <Shield className="w-5 h-5 text-blue-600" />
          <span>Security Platform Integration</span>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <p className="text-gray-600 mt-2">Loading integration status...</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <IntegrationCard
            name="Sentinel Core"
            description="Vulnerability Management & CVE Database"
            info={status?.sentinel_core}
            integrationKey="sentinel_core"
          />
          <IntegrationCard
            name="FireDog"
            description="Firewall & Threat Detection System"
            info={status?.firedog}
            integrationKey="firedog"
          />
        </div>
      )}

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <div className="flex items-start space-x-3">
          <AlertCircle className="w-6 h-6 text-blue-600 flex-shrink-0 mt-1" />
          <div>
            <h3 className="font-semibold text-blue-900 mb-2">About Integrations</h3>
            <p className="text-sm text-blue-800 mb-2">
              CyberSheppard integrates with external security platforms to provide comprehensive security monitoring and correlation.
            </p>
            <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
              <li><strong>Sentinel Core:</strong> Provides vulnerability data and CVE information for your assets</li>
              <li><strong>FireDog:</strong> Delivers threat intelligence and network attack detection</li>
              <li><strong>Correlation Engine:</strong> Automatically correlates vulnerabilities with active threats</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

function IntegrationCard({ name, description, info, integrationKey }: any) {
  const getStatusColor = (status: string) => {
    if (status === 'success') return 'text-green-600';
    if (status === 'partial') return 'text-yellow-600';
    if (status === 'error' || status === 'failed') return 'text-red-600';
    return 'text-gray-500';
  };

  const getStatusIcon = (enabled: boolean, status: string) => {
    if (!enabled) return <XCircle className="w-5 h-5 text-gray-400" />;
    if (status === 'success') return <CheckCircle className="w-5 h-5 text-green-500" />;
    if (status === 'partial') return <Activity className="w-5 h-5 text-yellow-500" />;
    return <AlertCircle className="w-5 h-5 text-gray-500" />;
  };

  const formatLastSync = (lastSync: string | null) => {
    if (!lastSync) return 'Never';
    const date = new Date(lastSync);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  return (
    <div className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow p-6">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-xl font-semibold flex items-center space-x-2">
            <span>{name}</span>
            {getStatusIcon(info?.enabled, info?.status)}
          </h3>
          <p className="text-sm text-gray-500 mt-1">{description}</p>
        </div>
      </div>

      <div className="space-y-3 mb-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Status:</span>
          <span className={`font-medium ${info?.enabled ? 'text-green-600' : 'text-gray-500'}`}>
            {info?.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Last Sync:</span>
          <span className="font-medium text-gray-900">
            {formatLastSync(info?.last_sync)}
          </span>
        </div>

        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Sync Status:</span>
          <span className={`font-medium ${getStatusColor(info?.status)}`}>
            {info?.status || 'unknown'}
          </span>
        </div>
      </div>

      {info?.enabled && (
        <div className="pt-4 border-t flex space-x-2">
          <button
            className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            onClick={() => api.triggerSync(integrationKey)}
          >
            <RefreshCw className="w-4 h-4" />
            <span>Sync Now</span>
          </button>
        </div>
      )}

      {!info?.enabled && (
        <div className="pt-4 border-t">
          <div className="bg-gray-50 rounded p-3 text-center">
            <p className="text-sm text-gray-600">
              This integration is not configured. Contact your administrator to enable it.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
