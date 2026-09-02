// ============================================================================
// Alert — scheda dell'hub Threat Detection. Gestione degli alert di sicurezza
// (triage: acknowledge/resolve). Vista senza PageHeader: l'intestazione la
// fornisce l'hub ThreatDetection.
// ============================================================================

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Bell, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import api from '../services/api';
import { useAuthStore } from '../stores/authStore';
import { format } from 'date-fns';
import {
  Table,
  SeverityBadge,
  StatusBadge,
  Button,
  StatsGrid,
  StatCard,
} from '../components/ui';

export default function AlertsView() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('active');

  const { data: alerts, isLoading } = useQuery({
    queryKey: ['alerts', selectedSeverity, selectedStatus],
    queryFn: () => api.getAlerts(selectedSeverity, selectedStatus),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: number) =>
      api.acknowledgeAlert(alertId, user?.username || 'admin'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({ alertId, notes }: { alertId: number; notes: string }) =>
      api.resolveAlert(alertId, user?.username || 'admin', notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  const stats = {
    total: alerts?.length || 0,
    new: alerts?.filter((a: any) => a.status === 'new').length || 0,
    acknowledged:
      alerts?.filter((a: any) => a.acknowledged && !a.resolved).length || 0,
    resolved: alerts?.filter((a: any) => a.resolved).length || 0,
    critical: alerts?.filter((a: any) => a.severity === 'critical').length || 0,
    high: alerts?.filter((a: any) => a.severity === 'high').length || 0,
    medium: alerts?.filter((a: any) => a.severity === 'medium').length || 0,
  };

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      render: (row: any) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: 'title',
      label: 'Alert',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">{row.title}</div>
          <div className="text-sm text-gray-500 mt-1">{row.message}</div>
        </div>
      ),
    },
    {
      key: 'alert_type',
      label: 'Type',
      sortable: true,
      render: (row: any) => (
        <span className="text-sm text-gray-600">{row.alert_type}</span>
      ),
    },
    {
      key: 'created_at',
      label: 'Created',
      sortable: true,
      render: (row: any) => (
        <div className="text-sm text-gray-600">
          {format(new Date(row.created_at), 'PPp')}
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (row: any) => {
        if (row.resolved) return <StatusBadge status="resolved" />;
        if (row.acknowledged) return <StatusBadge status="acknowledged" />;
        return <StatusBadge status="new" />;
      },
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row: any) => (
        <div className="flex items-center gap-2">
          {!row.acknowledged && !row.resolved && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => acknowledgeMutation.mutate(row.id)}
              loading={acknowledgeMutation.isPending}
            >
              Acknowledge
            </Button>
          )}
          {row.acknowledged && !row.resolved && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() =>
                resolveMutation.mutate({ alertId: row.id, notes: 'Resolved' })
              }
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
      {/* Stats */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Total Alerts"
          value={stats.total}
          icon={<Bell className="w-6 h-6" />}
          variant="info"
        />
        <StatCard
          title="New"
          value={stats.new}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="warning"
        />
        <StatCard
          title="Acknowledged"
          value={stats.acknowledged}
          icon={<Clock className="w-6 h-6" />}
          variant="default"
        />
        <StatCard
          title="Resolved"
          value={stats.resolved}
          icon={<CheckCircle className="w-6 h-6" />}
          variant="success"
        />
      </StatsGrid>

      {/* Filters */}
      <div className="flex items-center gap-4 mb-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Severity
          </label>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Status
          </label>
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        {(selectedSeverity !== 'all' || selectedStatus !== 'active') && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSelectedSeverity('all');
              setSelectedStatus('active');
            }}
            className="mt-6"
          >
            Clear Filters
          </Button>
        )}
      </div>

      {/* Table */}
      <Table
        data={alerts || []}
        columns={columns}
        loading={isLoading}
        emptyMessage="No alerts found"
      />
    </div>
  );
}
