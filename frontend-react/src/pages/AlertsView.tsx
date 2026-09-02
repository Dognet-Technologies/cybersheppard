// ============================================================================
// Alert — scheda dell'hub Threat Detection. CyberSheppard è MONITORAGGIO:
// niente triage (acknowledge/resolve). Gli alert sono notifiche; l'azione
// consigliata è una "remediation" verso gli altri tool della suite.
// ============================================================================

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Bell, AlertTriangle, ShieldAlert } from 'lucide-react';
import api from '../services/api';
import { format } from 'date-fns';
import {
  Table,
  SeverityBadge,
  StatsGrid,
  StatCard,
  Button,
  InfoTip,
} from '../components/ui';
import { HELP } from '../i18n/help';

export default function AlertsView() {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  const { data: alerts, isLoading } = useQuery({
    queryKey: ['alerts', selectedSeverity],
    queryFn: () => api.getAlerts(selectedSeverity, 'all'),
    refetchInterval: 30000,
  });

  const list: any[] = Array.isArray(alerts) ? alerts : [];
  const stats = {
    total: list.length,
    critical: list.filter((a) => a.severity === 'critical').length,
    high: list.filter((a) => a.severity === 'high').length,
    medium: list.filter((a) => a.severity === 'medium').length,
  };

  const remediationFor = (a: any): string =>
    (HELP.remediation as Record<string, string>)[a.alert_type] || HELP.ui.remediationDefault;

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      info: HELP.alerts.colSeverity,
      render: (row: any) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: 'title',
      label: 'Alert',
      sortable: true,
      info: HELP.alerts.colAlert,
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
      info: HELP.alerts.colType,
      render: (row: any) => (
        <span className="text-sm text-gray-600">{(row.alert_type || '').replace(/_/g, ' ')}</span>
      ),
    },
    {
      key: 'created_at',
      label: 'Created',
      sortable: true,
      info: HELP.alerts.colCreated,
      render: (row: any) => (
        <div className="text-sm text-gray-600">{format(new Date(row.created_at), 'PPp')}</div>
      ),
    },
    {
      key: 'remediation',
      label: HELP.ui.colRemediation,
      info: HELP.ui.colRemediationInfo,
      render: (row: any) => (
        <span className="text-sm text-gray-600">{remediationFor(row)}</span>
      ),
    },
  ];

  return (
    <div>
      <StatsGrid columns={4} className="mb-6">
        <StatCard title="Total Alerts" value={stats.total} icon={<Bell className="w-6 h-6" />} variant="info" info={HELP.alerts.statTotal} />
        <StatCard title="Critical" value={stats.critical} icon={<AlertTriangle className="w-6 h-6" />} variant="danger" info={HELP.severity.critical} />
        <StatCard title="High" value={stats.high} icon={<AlertTriangle className="w-6 h-6" />} variant="warning" info={HELP.severity.high} />
        <StatCard title="Medium" value={stats.medium} icon={<ShieldAlert className="w-6 h-6" />} variant="default" info={HELP.severity.medium} />
      </StatsGrid>

      {/* Filtro severità */}
      <div className="flex items-center gap-4 mb-6">
        <div>
          <label className="text-sm font-medium text-gray-700 mb-1 flex items-center gap-1">
            Severity <InfoTip content={HELP.alerts.filterSeverity} />
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
        {selectedSeverity !== 'all' && (
          <Button variant="ghost" size="sm" onClick={() => setSelectedSeverity('all')} className="mt-6">
            Clear Filters
          </Button>
        )}
      </div>

      <Table data={list} columns={columns} loading={isLoading} emptyMessage="No alerts found" />
    </div>
  );
}
