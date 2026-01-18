// ============================================================================
// Security Correlations Page - Vulnerability and threat correlation
// ============================================================================

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { AlertTriangle, CheckCircle, Activity, Shield } from 'lucide-react';
import { format } from 'date-fns';
import {
  PageHeader,
  Table,
  Button,
  Badge,
  StatsGrid,
  StatCard,
  EmptyState,
} from '../components/ui';

export default function SecurityCorrelations() {
  const [, setSelectedCorrelation] = useState<any>(null);
  const queryClient = useQueryClient();

  const { data: correlations, isLoading } = useQuery({
    queryKey: ['security-correlations'],
    queryFn: () => api.getSecurityCorrelations(),
    refetchInterval: 30000,
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: number) => api.acknowledgeCorrelation(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-correlations'] });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, notes }: { id: number; notes: string }) =>
      api.resolveCorrelation(id, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-correlations'] });
      setSelectedCorrelation(null);
    },
  });

  const handleResolve = (correlation: any) => {
    const notes = prompt('Enter resolution notes:');
    if (notes) {
      resolveMutation.mutate({ id: correlation.id, notes });
    }
  };

  // Calculate statistics
  const stats = {
    total: correlations?.length || 0,
    critical: correlations?.filter((c: any) => c.risk_level === 'critical').length || 0,
    high: correlations?.filter((c: any) => c.risk_level === 'high').length || 0,
    new: correlations?.filter((c: any) => c.status === 'new').length || 0,
  };

  const columns = [
    {
      key: 'risk_level',
      label: 'Risk Level',
      sortable: true,
      render: (row: any) => {
        const variants: Record<string, 'danger' | 'warning' | 'info' | 'default'> = {
          critical: 'danger',
          high: 'warning',
          medium: 'info',
          low: 'default',
        };
        return (
          <Badge variant={variants[row.risk_level] || 'default'}>
            {row.risk_level?.toUpperCase() || 'UNKNOWN'}
          </Badge>
        );
      },
    },
    {
      key: 'target',
      label: 'Target',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">
            {row.target_hostname || `Target #${row.target_id}`}
          </div>
          <div className="text-sm text-gray-500">{row.correlation_type}</div>
        </div>
      ),
    },
    {
      key: 'vulnerability',
      label: 'Vulnerability',
      render: (row: any) => (
        <div>
          <div className="font-medium text-sm text-gray-900">{row.vulnerability_cve || 'N/A'}</div>
          <div className="text-xs text-gray-500">
            CVSS: {row.vulnerability_cvss?.toFixed(1) || 'N/A'}
          </div>
        </div>
      ),
    },
    {
      key: 'threat',
      label: 'Threat Source',
      render: (row: any) => (
        <div>
          <div className="font-medium text-sm text-gray-900">{row.threat_source_ip || 'N/A'}</div>
          <div className="text-xs text-gray-500">
            Score: {row.threat_score?.toFixed(1) || 'N/A'}
          </div>
        </div>
      ),
    },
    {
      key: 'confidence',
      label: 'Confidence',
      sortable: true,
      render: (row: any) => (
        <span className="text-sm font-mono text-gray-900">
          {(row.correlation_confidence * 100).toFixed(0)}%
        </span>
      ),
    },
    {
      key: 'created_at',
      label: 'Detected',
      sortable: true,
      render: (row: any) => (
        <div className="text-sm text-gray-600">{format(new Date(row.created_at), 'PPp')}</div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (row: any) => {
        const variants: Record<string, 'warning' | 'info' | 'success'> = {
          new: 'warning',
          acknowledged: 'info',
          resolved: 'success',
        };
        return <Badge variant={variants[row.status] || 'default'}>{row.status}</Badge>;
      },
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row: any) => (
        <div className="flex items-center gap-2">
          {row.status === 'new' && (
            <>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => acknowledgeMutation.mutate(row.id)}
                loading={acknowledgeMutation.isPending}
              >
                Acknowledge
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => handleResolve(row)}
                loading={resolveMutation.isPending}
              >
                Resolve
              </Button>
            </>
          )}
          {row.status === 'acknowledged' && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handleResolve(row)}
              loading={resolveMutation.isPending}
            >
              Resolve
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Security Correlations"
        subtitle="Automated correlation between vulnerabilities and active threats"
        icon={<Shield className="w-6 h-6" />}
        actions={
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-green-500 animate-pulse" />
            <Badge variant="success">Auto-refresh</Badge>
          </div>
        }
      />

      {/* Stats */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Total Correlations"
          value={stats.total}
          icon={<Activity className="w-6 h-6" />}
          variant="info"
        />
        <StatCard
          title="Critical Risk"
          value={stats.critical}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="danger"
        />
        <StatCard
          title="High Risk"
          value={stats.high}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="warning"
        />
        <StatCard
          title="New"
          value={stats.new}
          icon={<CheckCircle className="w-6 h-6" />}
          variant="warning"
        />
      </StatsGrid>

      {/* Table or Empty State */}
      {correlations?.length === 0 && !isLoading ? (
        <EmptyState
          icon={<CheckCircle className="w-8 h-8" />}
          title="No Active Correlations"
          description="The system has not detected any high-risk correlations between vulnerabilities and threats"
        />
      ) : (
        <Table
          data={correlations || []}
          columns={columns}
          loading={isLoading}
          emptyMessage="No correlations found"
        />
      )}
    </div>
  );
}
