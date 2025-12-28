import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Bell,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Filter,
  AlertCircle,
  ShieldAlert,
} from 'lucide-react';
import api from '../services/api';
import { useAuthStore } from '../stores/authStore';

interface Alert {
  id: number;
  rule_id: number | null;
  severity: string;
  title: string;
  message: string;
  alert_type: string;
  entity_type: string | null;
  entity_id: number | null;
  metadata: any;
  status: string;
  acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved: boolean;
  resolved_by: string | null;
  resolved_at: string | null;
  resolution_notes: string | null;
  created_at: string;
}

interface AlertStats {
  total: number;
  new: number;
  acknowledged: number;
  resolved: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function Alerts() {
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('active');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const { data: alerts, isLoading } = useQuery({
    queryKey: ['alerts', selectedSeverity, selectedStatus],
    queryFn: () => api.getAlerts(selectedSeverity, selectedStatus),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: number) =>
      api.acknowledgeAlert(alertId, user?.username || 'admin'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setSelectedAlert(null);
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({
      alertId,
      notes,
    }: {
      alertId: number;
      notes: string;
    }) => api.resolveAlert(alertId, user?.username || 'admin', notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setSelectedAlert(null);
    },
  });

  const stats: AlertStats = {
    total: alerts?.length || 0,
    new: alerts?.filter((a: Alert) => a.status === 'new').length || 0,
    acknowledged: alerts?.filter((a: Alert) => a.acknowledged && !a.resolved).length || 0,
    resolved: alerts?.filter((a: Alert) => a.resolved).length || 0,
    critical: alerts?.filter((a: Alert) => a.severity === 'critical').length || 0,
    high: alerts?.filter((a: Alert) => a.severity === 'high').length || 0,
    medium: alerts?.filter((a: Alert) => a.severity === 'medium').length || 0,
    low: alerts?.filter((a: Alert) => a.severity === 'low').length || 0,
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Alerts</h1>
        <p className="text-gray-500 mt-1">Monitor and respond to security alerts</p>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          icon={<Bell className="w-6 h-6 text-blue-600" />}
          label="Total Alerts"
          value={stats.total}
          bgColor="bg-blue-50"
        />
        <StatCard
          icon={<AlertCircle className="w-6 h-6 text-red-600" />}
          label="New"
          value={stats.new}
          bgColor="bg-red-50"
        />
        <StatCard
          icon={<Clock className="w-6 h-6 text-yellow-600" />}
          label="Acknowledged"
          value={stats.acknowledged}
          bgColor="bg-yellow-50"
        />
        <StatCard
          icon={<CheckCircle className="w-6 h-6 text-green-600" />}
          label="Resolved"
          value={stats.resolved}
          bgColor="bg-green-50"
        />
      </div>

      {/* Severity Distribution */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Severity Distribution</h2>
        <div className="grid grid-cols-4 gap-4">
          <SeverityCard label="Critical" count={stats.critical} color="red" />
          <SeverityCard label="High" count={stats.high} color="orange" />
          <SeverityCard label="Medium" count={stats.medium} color="yellow" />
          <SeverityCard label="Low" count={stats.low} color="blue" />
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm p-4">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Filter className="w-4 h-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">Filters:</span>
          </div>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="all">All Status</option>
            <option value="active">Active Only</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Alerts</h2>

          {alerts && alerts.length > 0 ? (
            <div className="space-y-3">
              {alerts.map((alert: Alert) => (
                <div
                  key={alert.id}
                  className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                  onClick={() => setSelectedAlert(alert)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3 flex-1">
                      {getSeverityIcon(alert.severity)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <h3 className="font-semibold text-gray-900">{alert.title}</h3>
                          {getSeverityBadge(alert.severity)}
                          {getTypeBadge(alert.alert_type)}
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{alert.message}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Created: {new Date(alert.created_at).toLocaleString()}</span>
                          {alert.entity_type && (
                            <span>
                              Entity: {alert.entity_type} #{alert.entity_id}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col items-end space-y-2">
                      {getStatusBadge(alert)}
                      {!alert.resolved && (
                        <div className="flex space-x-2">
                          {!alert.acknowledged && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                acknowledgeMutation.mutate(alert.id);
                              }}
                              className="text-xs bg-yellow-100 text-yellow-800 px-3 py-1 rounded hover:bg-yellow-200 transition-colors"
                            >
                              Acknowledge
                            </button>
                          )}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedAlert(alert);
                            }}
                            className="text-xs bg-green-100 text-green-800 px-3 py-1 rounded hover:bg-green-200 transition-colors"
                          >
                            Resolve
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  {alert.acknowledged && alert.acknowledged_by && (
                    <div className="mt-3 pt-3 border-t border-gray-200 text-xs text-gray-500">
                      Acknowledged by {alert.acknowledged_by} on{' '}
                      {new Date(alert.acknowledged_at!).toLocaleString()}
                    </div>
                  )}

                  {alert.resolved && alert.resolved_by && (
                    <div className="mt-3 pt-3 border-t border-gray-200 text-xs text-gray-500">
                      Resolved by {alert.resolved_by} on{' '}
                      {new Date(alert.resolved_at!).toLocaleString()}
                      {alert.resolution_notes && (
                        <div className="mt-1">
                          <span className="font-medium">Notes:</span> {alert.resolution_notes}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Bell className="w-12 h-12 text-gray-400 mx-auto mb-3" />
              <p className="text-gray-500">No alerts found</p>
              <p className="text-sm text-gray-400">Alerts will appear here when triggered</p>
            </div>
          )}
        </div>
      </div>

      {/* Resolve Modal */}
      {selectedAlert && !selectedAlert.resolved && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Resolve Alert</h3>
            <p className="text-sm text-gray-600 mb-4">{selectedAlert.title}</p>

            <textarea
              className="w-full border border-gray-300 rounded-lg p-3 text-sm mb-4"
              rows={4}
              placeholder="Enter resolution notes..."
              id="resolution-notes"
            />

            <div className="flex justify-end space-x-3">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const notes = (
                    document.getElementById('resolution-notes') as HTMLTextAreaElement
                  ).value;
                  resolveMutation.mutate({
                    alertId: selectedAlert.id,
                    notes: notes || 'Resolved',
                  });
                }}
                className="px-4 py-2 text-white bg-green-600 rounded-lg hover:bg-green-700 transition-colors"
              >
                Resolve
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

function SeverityCard({ label, count, color }: any) {
  const colorMap: any = {
    red: 'bg-red-100 text-red-800',
    orange: 'bg-orange-100 text-orange-800',
    yellow: 'bg-yellow-100 text-yellow-800',
    blue: 'bg-blue-100 text-blue-800',
  };

  return (
    <div className={`${colorMap[color]} rounded-lg p-4 text-center`}>
      <div className="text-3xl font-bold mb-1">{count}</div>
      <div className="text-sm font-medium">{label}</div>
    </div>
  );
}

function getSeverityIcon(severity: string) {
  switch (severity) {
    case 'critical':
      return <XCircle className="w-5 h-5 text-red-600" />;
    case 'high':
      return <AlertTriangle className="w-5 h-5 text-orange-600" />;
    case 'medium':
      return <AlertCircle className="w-5 h-5 text-yellow-600" />;
    case 'low':
      return <ShieldAlert className="w-5 h-5 text-blue-600" />;
    default:
      return <Bell className="w-5 h-5 text-gray-600" />;
  }
}

function getSeverityBadge(severity: string) {
  const badges: any = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
  };

  return (
    <span className={`${badges[severity]} text-xs px-2 py-1 rounded uppercase font-medium`}>
      {severity}
    </span>
  );
}

function getTypeBadge(type: string) {
  return (
    <span className="bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded">
      {type.replace(/_/g, ' ')}
    </span>
  );
}

function getStatusBadge(alert: Alert) {
  if (alert.resolved) {
    return (
      <span className="inline-flex items-center space-x-1 bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
        <CheckCircle className="w-3 h-3" />
        <span>Resolved</span>
      </span>
    );
  }
  if (alert.acknowledged) {
    return (
      <span className="inline-flex items-center space-x-1 bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded">
        <Clock className="w-3 h-3" />
        <span>Acknowledged</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center space-x-1 bg-red-100 text-red-800 text-xs px-2 py-1 rounded">
      <AlertCircle className="w-3 h-3" />
      <span>New</span>
    </span>
  );
}
