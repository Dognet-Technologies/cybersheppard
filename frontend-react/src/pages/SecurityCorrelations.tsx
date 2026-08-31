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

  // Fetch correlations using new API
  const { data: response, isLoading } = useQuery({
    queryKey: ['security-correlations'],
    queryFn: () => api.getSecurityCorrelations({ hours: 24, limit: 100 }),
    refetchInterval: 30000,
  });

  // Extract data from API response
  const correlations = response?.data || [];

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

  // Calculate statistics (adapted to new EventCorrelation model)
  const stats = {
    total: correlations?.length || 0,
    critical: correlations?.filter((c: any) => c.severity === 'critical').length || 0,
    high: correlations?.filter((c: any) => c.severity === 'high').length || 0,
    active: correlations?.filter((c: any) => c.status === 'active').length || 0,
  };

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      render: (row: any) => {
        const variants: Record<string, 'danger' | 'warning' | 'info' | 'default'> = {
          critical: 'danger',
          high: 'warning',
          medium: 'info',
          low: 'default',
        };
        return (
          <Badge variant={variants[row.severity] || 'default'}>
            {row.severity?.toUpperCase() || 'UNKNOWN'}
          </Badge>
        );
      },
    },
    {
      key: 'pattern',
      label: 'Attack Pattern',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">
            {row.pattern_name || row.correlation_type?.replace('_', ' ').toUpperCase()}
          </div>
          <div className="text-sm text-gray-500">
            {row.correlation_type?.replace(/_/g, ' ') || ''}
          </div>
        </div>
      ),
    },
    {
      key: 'mitre',
      label: 'MITRE',
      render: (row: any) => {
        const tactic: string | undefined = row.attack_stage;
        const d3fend: string | undefined = row.correlation_data?.mitigating_d3fend;
        return (
          <div className="flex flex-col gap-1">
            {tactic ? (
              <span
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 border border-red-200"
                title="MITRE ATT&CK tactic"
              >
                ATT&amp;CK: {tactic.replace(/_/g, ' ')}
              </span>
            ) : (
              <span className="text-xs text-gray-400">—</span>
            )}
            {d3fend && (
              <span
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-50 text-green-700 border border-green-200"
                title="MITRE D3FEND — controllo difensivo mitigante"
              >
                D3FEND: {d3fend}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'entities',
      label: 'Involved Entities',
      render: (row: any) => (
        <div>
          <div className="font-medium text-sm text-gray-900">
            Hosts: {row.involved_hosts?.slice(0, 2).join(', ') || 'N/A'}
            {row.involved_hosts?.length > 2 && ` +${row.involved_hosts.length - 2} more`}
          </div>
          <div className="text-xs text-gray-500">
            Users: {row.involved_users?.slice(0, 2).join(', ') || 'N/A'}
            {row.involved_users?.length > 2 && ` +${row.involved_users.length - 2} more`}
          </div>
        </div>
      ),
    },
    {
      key: 'risk',
      label: 'Risk Score',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-sm text-gray-900">
            {row.risk_score?.toFixed(1) || 'N/A'} / 100
          </div>
          <div className="text-xs text-gray-500">
            Events: {row.event_count || 0}
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
          {(row.confidence * 100).toFixed(0)}%
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
          active: 'warning',
          investigating: 'info',
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
          {row.status === 'active' && (
            <>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => acknowledgeMutation.mutate(row.id)}
                loading={acknowledgeMutation.isPending}
                title="Acknowledge (legacy action)"
              >
                Acknowledge
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => handleResolve(row)}
                loading={resolveMutation.isPending}
                title="Resolve (legacy action)"
              >
                Resolve
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Security Event Correlations"
        subtitle="Advanced AI-powered attack pattern detection and threat correlation"
        icon={<Shield className="w-6 h-6" />}
        actions={
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-green-500 animate-pulse" />
            <Badge variant="success">Live Monitoring</Badge>
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
          title="Critical"
          value={stats.critical}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="danger"
        />
        <StatCard
          title="High Severity"
          value={stats.high}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="warning"
        />
        <StatCard
          title="Active"
          value={stats.active}
          icon={<CheckCircle className="w-6 h-6" />}
          variant="warning"
        />
      </StatsGrid>

      {/* Table or Empty State */}
      {correlations?.length === 0 && !isLoading ? (
        <EmptyState
          icon={<CheckCircle className="w-8 h-8" />}
          title="No Active Correlations"
          description="The advanced correlation engine has not detected any suspicious patterns or attack sequences in the last 24 hours"
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
