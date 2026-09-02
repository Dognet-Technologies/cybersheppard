// ============================================================================
// Events — Table view. Monitoraggio eventi di sicurezza (auditd/Laurel + eBPF)
// in tabella con filtri e statistiche. Vista "Tabella" della pagina Eventi.
// ============================================================================

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertTriangle, Activity, Eye } from 'lucide-react';
import api from '../services/api';
import { format } from 'date-fns';
import {
  Table,
  SeverityBadge,
  StatusBadge,
  Button,
  StatsGrid,
  StatCard,
} from '../components/ui';

export default function EventsTableView() {
  const navigate = useNavigate();
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  // Fetch events with real-time updates (30s refresh)
  const { data: eventsData, isLoading } = useQuery({
    queryKey: ['auditd-events', selectedTarget, selectedSeverity, selectedCategory, selectedStatus],
    queryFn: () =>
      api.getAuditdEvents({
        target_id: selectedTarget !== 'all' ? parseInt(selectedTarget) : undefined,
        severity: selectedSeverity !== 'all' ? selectedSeverity : undefined,
        category: selectedCategory !== 'all' ? selectedCategory : undefined,
        status: selectedStatus !== 'all' ? selectedStatus : undefined,
        limit: 100,
      }),
    refetchInterval: 30000, // Refresh every 30 seconds for real-time updates
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['auditd-stats'],
    queryFn: () => api.getAuditdStats(),
    refetchInterval: 30000,
  });

  // Fetch targets for filter
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  const events = eventsData?.events || [];
  const total = eventsData?.total || 0;

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      render: (row: any) => <SeverityBadge severity={row.severity || 'low'} />,
    },
    {
      key: 'category',
      label: 'Category',
      sortable: true,
      render: (row: any) => (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
          {row.category || 'unknown'}
        </span>
      ),
    },
    {
      key: 'hostname',
      label: 'Host',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">{row.hostname}</div>
          <div className="text-sm text-gray-500">{row.ip_address}</div>
        </div>
      ),
    },
    {
      key: 'description',
      label: 'Event',
      sortable: false,
      render: (row: any) => (
        <div className="max-w-md">
          <div className="text-sm text-gray-900 truncate">
            {row.description || 'No description'}
          </div>
          {row.syscall && (
            <div className="text-xs text-gray-500 mt-1">
              Syscall: {row.syscall} {row.comm && `| ${row.comm}`}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'collected_at',
      label: 'Time',
      sortable: true,
      render: (row: any) => (
        <div className="text-sm text-gray-600">
          {format(new Date(row.collected_at), 'PPp')}
        </div>
      ),
    },
    {
      key: 'correlations',
      label: 'Correlations',
      sortable: false,
      render: (row: any) => (
        <div className="flex gap-1">
          {row.correlated_with_firedog && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
              FireDog
            </span>
          )}
          {row.correlated_with_sentinel && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-100 text-orange-800">
              Sentinel
            </span>
          )}
          {row.related_events_count > 1 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
              +{row.related_events_count - 1}
            </span>
          )}
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
        <Button
          size="sm"
          variant="ghost"
          onClick={() => navigate(`/detection/events/${row.id}`)}
        >
          <Eye className="w-4 h-4 mr-1" />
          Details
        </Button>
      ),
    },
  ];

  return (
    <div>
      {/* Stats */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Total Events (24h)"
          value={stats?.total_events || 0}
          icon={<Activity className="w-6 h-6" />}
          variant="info"
        />
        <StatCard
          title="Critical"
          value={
            Array.isArray(stats?.by_severity)
              ? stats.by_severity.find((s: any) => s[0] === 'critical')?.[1] || 0
              : 0
          }
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="danger"
        />
        <StatCard
          title="High"
          value={
            Array.isArray(stats?.by_severity)
              ? stats.by_severity.find((s: any) => s[0] === 'high')?.[1] || 0
              : 0
          }
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="warning"
        />
        <StatCard
          title="New"
          value={
            Array.isArray(stats?.by_status)
              ? stats.by_status.find((s: any) => s[0] === 'new')?.[1] || 0
              : 0
          }
          icon={<Shield className="w-6 h-6" />}
          variant="info"
        />
      </StatsGrid>

      {/* Filters */}
      <div className="flex items-center gap-4 mb-6 flex-wrap">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Target
          </label>
          <select
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
            className="border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">All Targets</option>
            {targets?.map((target: any) => (
              <option key={target.id} value={target.id}>
                {target.hostname}
              </option>
            ))}
          </select>
        </div>

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
            Category
          </label>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="all">All Categories</option>
            <option value="reverse_shell">Reverse Shell</option>
            <option value="webshell">Webshell</option>
            <option value="privilege_escalation">Privilege Escalation</option>
            <option value="sensitive_file_access">Sensitive File Access</option>
            <option value="container_escape">Container Escape</option>
            <option value="persistence">Persistence</option>
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
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>

        {(selectedTarget !== 'all' ||
          selectedSeverity !== 'all' ||
          selectedCategory !== 'all' ||
          selectedStatus !== 'all') && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSelectedTarget('all');
              setSelectedSeverity('all');
              setSelectedCategory('all');
              setSelectedStatus('all');
            }}
            className="mt-6"
          >
            Clear Filters
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900">
              Events ({total})
            </h3>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Activity className="w-4 h-4 animate-pulse text-green-500" />
              Auto-refreshing every 30s
            </div>
          </div>
        </div>
        <Table
          data={events}
          columns={columns}
          loading={isLoading}
          emptyMessage="No audit events found"
        />
      </div>

      {/* Recent Critical Events */}
      {stats?.recent_critical && stats.recent_critical.length > 0 && (
        <div className="mt-6 bg-red-50 rounded-lg p-6 border border-red-200">
          <h3 className="text-lg font-semibold text-red-900 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Recent Critical Events
          </h3>
          <div className="space-y-2">
            {stats.recent_critical.slice(0, 5).map((event: any) => (
              <div
                key={event.id}
                className="flex items-center justify-between bg-white rounded-lg p-3 cursor-pointer hover:shadow-md transition-shadow"
                onClick={() => navigate(`/detection/events/${event.id}`)}
              >
                <div className="flex-1">
                  <div className="font-medium text-gray-900">
                    {event.hostname} - {event.category}
                  </div>
                  <div className="text-sm text-gray-600 mt-1">
                    {event.description}
                  </div>
                </div>
                <div className="text-sm text-gray-500">
                  {format(new Date(event.collected_at), 'p')}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
