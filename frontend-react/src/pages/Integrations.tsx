// ============================================================================
// Integrations Page - External system integrations
// ============================================================================

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { Shield, RefreshCw, CheckCircle, XCircle, Activity, AlertCircle, Link2 } from 'lucide-react';
import { PageHeader, Card, CardHeader, Button, Badge } from '../components/ui';

export default function Integrations() {
  const queryClient = useQueryClient();

  const { data: status, isLoading } = useQuery({
    queryKey: ['integration-status'],
    queryFn: () => api.getIntegrationStatus(),
    refetchInterval: 30000,
  });

  const syncMutation = useMutation({
    mutationFn: (integrationName: string) => api.triggerIntegrationSync(integrationName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integration-status'] });
    },
  });

  return (
    <div>
      <PageHeader
        title="Integrations"
        subtitle="External system integrations and synchronization"
        icon={<Link2 className="w-6 h-6" />}
      />

      {isLoading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-blue-600"></div>
          <p className="text-gray-600 mt-4">Loading integration status...</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <IntegrationCard
              name="Sentinel Core"
              description="Vulnerability Management & CVE Database"
              icon={<Shield className="w-6 h-6" />}
              info={status?.sentinel_core}
              onSync={() => syncMutation.mutate('sentinel_core')}
              syncing={syncMutation.isPending}
            />
            <IntegrationCard
              name="FireDog"
              description="Firewall & Threat Detection System"
              icon={<Shield className="w-6 h-6" />}
              info={status?.firedog}
              onSync={() => syncMutation.mutate('firedog')}
              syncing={syncMutation.isPending}
            />
          </div>

          <Card className="bg-blue-50 border-blue-200">
            <div className="flex items-start space-x-3">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <AlertCircle className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <h3 className="font-semibold text-blue-900 mb-2">About Integrations</h3>
                <p className="text-sm text-blue-800 mb-2">
                  CyberSheppard integrates with external security platforms to provide
                  comprehensive security monitoring and correlation.
                </p>
                <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
                  <li>
                    <strong>Sentinel Core:</strong> Provides vulnerability data and CVE information
                  </li>
                  <li>
                    <strong>FireDog:</strong> Delivers threat intelligence and network attack detection
                  </li>
                  <li>
                    <strong>Correlation Engine:</strong> Automatically correlates vulnerabilities with
                    threats
                  </li>
                </ul>
              </div>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}

interface IntegrationCardProps {
  name: string;
  description: string;
  icon: React.ReactNode;
  info: any;
  onSync: () => void;
  syncing: boolean;
}

function IntegrationCard({
  name,
  description,
  info,
  onSync,
  syncing,
}: IntegrationCardProps) {
  const getStatusIcon = (enabled: boolean, status: string) => {
    if (!enabled) return <XCircle className="w-5 h-5 text-gray-400" />;
    if (status === 'success') return <CheckCircle className="w-5 h-5 text-green-500" />;
    if (status === 'partial') return <Activity className="w-5 h-5 text-yellow-500" />;
    return <XCircle className="w-5 h-5 text-red-500" />;
  };

  return (
    <Card>
      <CardHeader
        title={name}
        subtitle={description}
        action={
          info?.enabled && (
            <Button
              size="sm"
              variant="ghost"
              icon={<RefreshCw className="w-4 h-4" />}
              onClick={onSync}
              loading={syncing}
            >
              Sync Now
            </Button>
          )
        }
      />

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Status</span>
          <div className="flex items-center space-x-2">
            {getStatusIcon(info?.enabled, info?.status)}
            <Badge variant={info?.enabled ? 'success' : 'default'}>
              {info?.enabled ? 'Enabled' : 'Disabled'}
            </Badge>
          </div>
        </div>

        {info?.enabled && (
          <>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Last Sync</span>
              <span className="text-sm font-medium text-gray-900">
                {info?.last_sync || 'Never'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Sync Status</span>
              <span className="text-sm font-medium text-gray-900">{info?.status || 'Unknown'}</span>
            </div>
          </>
        )}

        {!info?.enabled && (
          <div className="bg-gray-50 rounded-lg p-4 text-center">
            <p className="text-sm text-gray-600">
              This integration is currently disabled. Enable it in your configuration to start syncing
              data.
            </p>
          </div>
        )}
      </div>
    </Card>
  );
}
