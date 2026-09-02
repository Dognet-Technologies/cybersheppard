// ============================================================================
// Violations Page - Compliance violations management
// ============================================================================

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { AlertTriangle, CheckCircle, XCircle, Clock, ArrowLeft } from 'lucide-react';
import { format } from 'date-fns';
import { PageHeader, Table, SeverityBadge, StatusBadge, Button, StatsGrid, StatCard } from '../components/ui';

export default function Violations() {
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');

  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['violations', statusFilter, severityFilter],
    queryFn: () => api.getViolations({
      status: statusFilter !== 'all' ? statusFilter : undefined,
      severity: severityFilter !== 'all' ? severityFilter : undefined
    }),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: number) => api.acknowledgeViolation(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['violations'] }),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, notes }: any) => api.resolveViolation(id, notes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['violations'] }),
  });

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      render: (row: any) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: 'metric_name',
      label: 'Metric',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">{row.metric_name}</div>
          {row.description && (
            <div className="text-sm text-gray-500 mt-1">{row.description}</div>
          )}
        </div>
      ),
    },
    {
      key: 'target_id',
      label: 'Target',
      sortable: true,
      render: (row: any) => (
        <div className="text-sm">
          <div className="font-medium text-gray-900">Target #{row.target_id}</div>
          {row.target_hostname && (
            <div className="text-gray-500">{row.target_hostname}</div>
          )}
        </div>
      ),
    },
    {
      key: 'detected_value',
      label: 'Value',
      render: (row: any) => (
        <span className="text-sm font-mono text-gray-900">{row.detected_value}</span>
      ),
    },
    {
      key: 'first_detected_at',
      label: 'Detected',
      sortable: true,
      render: (row: any) => (
        <div className="text-sm text-gray-600">
          {format(new Date(row.first_detected_at), 'PPp')}
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (row: any) => <StatusBadge status={row.status} />,
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row: any) => (
        <div className="flex items-center gap-2">
          {row.status === 'new' && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => acknowledgeMutation.mutate(row.id)}
              loading={acknowledgeMutation.isPending}
            >
              Acknowledge
            </Button>
          )}
          {row.status === 'acknowledged' && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => resolveMutation.mutate({ id: row.id, notes: 'Resolved' })}
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
      <Link
        to="/compliance"
        className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 mb-3"
      >
        <ArrowLeft className="w-4 h-4" />
        Torna a Compliance
      </Link>
      <PageHeader
        title="Compliance Violations"
        subtitle="Monitor and manage policy violations"
        icon={<AlertTriangle className="w-6 h-6" />}
      />

      {/* Stats Cards */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Critical"
          value={data?.summary?.critical || 0}
          icon={<XCircle className="w-6 h-6" />}
          variant="danger"
        />
        <StatCard
          title="High"
          value={data?.summary?.high || 0}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="warning"
        />
        <StatCard
          title="Medium"
          value={data?.summary?.medium || 0}
          icon={<Clock className="w-6 h-6" />}
          variant="info"
        />
        <StatCard
          title="Resolved"
          value={data?.summary?.resolved || 0}
          icon={<CheckCircle className="w-6 h-6" />}
          variant="success"
        />
      </StatsGrid>

      {/* Filters */}
      <div className="flex items-center gap-4 mb-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">All Status</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {(statusFilter !== 'all' || severityFilter !== 'all') && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setStatusFilter('all');
              setSeverityFilter('all');
            }}
            className="mt-6"
          >
            Clear Filters
          </Button>
        )}
      </div>

      {/* Table */}
      <Table
        data={data?.violations || []}
        columns={columns}
        loading={isLoading}
        emptyMessage="No violations found"
      />
    </div>
  );
}
