// ============================================================================
// Event Details Page - Comprehensive security event investigation
// ============================================================================

import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Server,
  AlertTriangle,
  CheckCircle,
  FileText,
  ArrowLeft,
  Activity,
  Database,
  Lock,
  FileCheck,
} from 'lucide-react';
import api from '../services/api';
import { format } from 'date-fns';
import {
  PageHeader,
  SeverityBadge,
  StatusBadge,
  Button,
  Table,
} from '../components/ui';

export default function EventDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [newStatus, setNewStatus] = useState<string>('');
  const [resolutionNotes, setResolutionNotes] = useState<string>('');

  const { data, isLoading } = useQuery({
    queryKey: ['auditd-event-details', id],
    queryFn: () => api.getAuditdEventDetails(parseInt(id!)),
    enabled: !!id,
  });

  const updateStatusMutation = useMutation({
    mutationFn: ({ status, notes }: { status: string; notes?: string }) =>
      api.updateAuditdEventStatus(parseInt(id!), status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auditd-event-details', id] });
      queryClient.invalidateQueries({ queryKey: ['auditd-events'] });
      setNewStatus('');
      setResolutionNotes('');
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const event = data?.event || {};
  const target = data?.target || {};
  const firedogThreats = data?.firedog_threats || [];
  const sentinelVulns = data?.sentinel_vulnerabilities || [];
  const complianceStatus = data?.compliance_status || {};
  const hardeningStatus = data?.hardening_status || {};

  const handleStatusUpdate = () => {
    if (!newStatus) return;
    updateStatusMutation.mutate({ status: newStatus, notes: resolutionNotes });
  };

  return (
    <div>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => navigate('/audit-events')}
        className="mb-4"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Events
      </Button>

      <PageHeader
        title={`Event #${event.id}`}
        subtitle={event.category || 'Security Event'}
        icon={<Shield className="w-6 h-6" />}
      />

      {/* Event Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="lg:col-span-2 bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Event Information
          </h3>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium text-gray-500">Severity</label>
              <div className="mt-1">
                <SeverityBadge severity={event.severity || 'low'} />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500">Status</label>
              <div className="mt-1">
                <StatusBadge status={event.status} />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500">Category</label>
              <div className="mt-1 text-gray-900">{event.category || 'N/A'}</div>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500">Time</label>
              <div className="mt-1 text-gray-900">
                {event.collected_at && format(new Date(event.collected_at), 'PPpp')}
              </div>
            </div>
            <div className="col-span-2">
              <label className="text-sm font-medium text-gray-500">Description</label>
              <div className="mt-1 text-gray-900">{event.description || 'No description available'}</div>
            </div>
            {event.syscall && (
              <div>
                <label className="text-sm font-medium text-gray-500">Syscall</label>
                <div className="mt-1 text-gray-900">{event.syscall}</div>
              </div>
            )}
            {event.comm && (
              <div>
                <label className="text-sm font-medium text-gray-500">Command</label>
                <div className="mt-1 text-gray-900 font-mono text-sm">{event.comm}</div>
              </div>
            )}
            {event.command_full && (
              <div className="col-span-2">
                <label className="text-sm font-medium text-gray-500">Full Command</label>
                <div className="mt-1 text-gray-900 font-mono text-xs bg-gray-50 p-3 rounded-lg overflow-x-auto">
                  {event.command_full}
                </div>
              </div>
            )}
            {event.parent_comm && (
              <div>
                <label className="text-sm font-medium text-gray-500">Parent Process</label>
                <div className="mt-1 text-gray-900 font-mono text-sm">{event.parent_comm}</div>
              </div>
            )}
            {event.container_name && (
              <div>
                <label className="text-sm font-medium text-gray-500">Container</label>
                <div className="mt-1 text-gray-900">{event.container_name}</div>
              </div>
            )}
          </div>

          {/* Raw Event Data */}
          <div className="mt-6">
            <details className="group">
              <summary className="cursor-pointer text-sm font-medium text-gray-700 flex items-center gap-2 hover:text-gray-900">
                <Database className="w-4 h-4" />
                Raw Event Data (JSON)
              </summary>
              <pre className="mt-2 text-xs bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                {JSON.stringify(event.raw_event || event, null, 2)}
              </pre>
            </details>
          </div>
        </div>

        {/* Status Update Panel */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Update Status</h3>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                New Status
              </label>
              <select
                value={newStatus}
                onChange={(e) => setNewStatus(e.target.value)}
                className="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
              >
                <option value="">Select status...</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Resolution Notes
              </label>
              <textarea
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                rows={4}
                className="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500"
                placeholder="Optional notes..."
              />
            </div>

            <Button
              onClick={handleStatusUpdate}
              disabled={!newStatus}
              loading={updateStatusMutation.isPending}
              className="w-full"
            >
              Update Status
            </Button>
          </div>
        </div>
      </div>

      {/* Target Information */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Server className="w-5 h-5" />
          Target System Information
        </h3>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <label className="text-sm font-medium text-gray-500">Hostname</label>
            <div className="mt-1 text-gray-900">{target.hostname || 'N/A'}</div>
          </div>
          <div>
            <label className="text-sm font-medium text-gray-500">IP Address</label>
            <div className="mt-1 text-gray-900">{target.ip_address || 'N/A'}</div>
          </div>
          <div>
            <label className="text-sm font-medium text-gray-500">OS</label>
            <div className="mt-1 text-gray-900">{target.os_name || 'N/A'}</div>
          </div>
          <div>
            <label className="text-sm font-medium text-gray-500">OS Version</label>
            <div className="mt-1 text-gray-900">{target.os_version || 'N/A'}</div>
          </div>
          {target.description && (
            <div className="col-span-2 md:col-span-4">
              <label className="text-sm font-medium text-gray-500">Description</label>
              <div className="mt-1 text-gray-900">{target.description}</div>
            </div>
          )}
        </div>
      </div>

      {/* FireDog Threats Correlation */}
      {event.correlated_with_firedog && firedogThreats.length > 0 && (
        <div className="bg-red-50 rounded-lg shadow p-6 mb-6 border border-red-200">
          <h3 className="text-lg font-semibold text-red-900 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Correlated FireDog Threats ({firedogThreats.length})
          </h3>

          <div className="space-y-3">
            {firedogThreats.map((threat: any, idx: number) => (
              <div key={idx} className="bg-white rounded-lg p-4 border border-red-200">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="font-medium text-gray-900">{threat.threat_type}</div>
                    <div className="text-sm text-gray-600 mt-1">{threat.description}</div>
                    {threat.source_ip && (
                      <div className="text-xs text-gray-500 mt-2">
                        Source: {threat.source_ip}:{threat.source_port} → {threat.dest_ip}:{threat.dest_port}
                      </div>
                    )}
                  </div>
                  <SeverityBadge severity={threat.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sentinel Vulnerabilities Correlation */}
      {event.correlated_with_sentinel && sentinelVulns.length > 0 && (
        <div className="bg-orange-50 rounded-lg shadow p-6 mb-6 border border-orange-200">
          <h3 className="text-lg font-semibold text-orange-900 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            Correlated Sentinel Vulnerabilities ({sentinelVulns.length})
          </h3>

          <div className="space-y-3">
            {sentinelVulns.map((vuln: any, idx: number) => (
              <div key={idx} className="bg-white rounded-lg p-4 border border-orange-200">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="font-medium text-gray-900">
                      {vuln.package_name} {vuln.current_version}
                    </div>
                    <div className="text-sm text-gray-600 mt-1">
                      {vuln.cve_id}: {vuln.description}
                    </div>
                    {vuln.fixed_version && (
                      <div className="text-xs text-green-600 mt-2">
                        Fix available: {vuln.fixed_version}
                      </div>
                    )}
                  </div>
                  <SeverityBadge severity={vuln.severity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Compliance Status */}
      {complianceStatus && Object.keys(complianceStatus).length > 0 && (
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <FileCheck className="w-5 h-5" />
            Compliance Status
          </h3>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {complianceStatus.score !== undefined && (
              <div>
                <label className="text-sm font-medium text-gray-500">Compliance Score</label>
                <div className="mt-1 text-2xl font-bold text-gray-900">
                  {complianceStatus.score}%
                </div>
              </div>
            )}
            {complianceStatus.passed !== undefined && (
              <div>
                <label className="text-sm font-medium text-gray-500">Passed</label>
                <div className="mt-1 text-2xl font-bold text-green-600">
                  {complianceStatus.passed}
                </div>
              </div>
            )}
            {complianceStatus.failed !== undefined && (
              <div>
                <label className="text-sm font-medium text-gray-500">Failed</label>
                <div className="mt-1 text-2xl font-bold text-red-600">
                  {complianceStatus.failed}
                </div>
              </div>
            )}
            {complianceStatus.frameworks && (
              <div>
                <label className="text-sm font-medium text-gray-500">Active Frameworks</label>
                <div className="mt-1 text-gray-900">
                  {Array.isArray(complianceStatus.frameworks)
                    ? complianceStatus.frameworks.join(', ')
                    : complianceStatus.frameworks}
                </div>
              </div>
            )}
          </div>

          {complianceStatus.violations && complianceStatus.violations.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Recent Violations</h4>
              <div className="space-y-2">
                {complianceStatus.violations.slice(0, 5).map((violation: any, idx: number) => (
                  <div key={idx} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                    <AlertTriangle className="w-4 h-4 text-orange-500 mt-0.5 flex-shrink-0" />
                    <div className="flex-1">
                      <div className="text-sm font-medium text-gray-900">{violation.rule}</div>
                      <div className="text-xs text-gray-600 mt-1">{violation.description}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Hardening Status */}
      {hardeningStatus && Object.keys(hardeningStatus).length > 0 && (
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Lock className="w-5 h-5" />
            Hardening Status
          </h3>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {hardeningStatus.level !== undefined && (
              <div>
                <label className="text-sm font-medium text-gray-500">Hardening Level</label>
                <div className="mt-1 text-2xl font-bold text-gray-900">
                  {hardeningStatus.level}%
                </div>
              </div>
            )}
            {hardeningStatus.applied !== undefined && (
              <div>
                <label className="text-sm font-medium text-gray-500">Applied</label>
                <div className="mt-1 text-2xl font-bold text-green-600">
                  {hardeningStatus.applied}
                </div>
              </div>
            )}
            {hardeningStatus.pending !== undefined && (
              <div>
                <label className="text-sm font-medium text-gray-500">Pending</label>
                <div className="mt-1 text-2xl font-bold text-yellow-600">
                  {hardeningStatus.pending}
                </div>
              </div>
            )}
            {hardeningStatus.last_applied && (
              <div>
                <label className="text-sm font-medium text-gray-500">Last Applied</label>
                <div className="mt-1 text-sm text-gray-900">
                  {format(new Date(hardeningStatus.last_applied), 'PPp')}
                </div>
              </div>
            )}
          </div>

          {hardeningStatus.templates && hardeningStatus.templates.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium text-gray-700 mb-2">Applied Templates</h4>
              <div className="flex flex-wrap gap-2">
                {hardeningStatus.templates.map((template: any, idx: number) => (
                  <span
                    key={idx}
                    className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800"
                  >
                    {template.name || template}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Related Events */}
      {event.related_events_count > 1 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Related Events (Same Category, Last Hour)
          </h3>
          <div className="text-gray-600">
            There are {event.related_events_count - 1} similar events from this target in the last hour.
          </div>
        </div>
      )}
    </div>
  );
}
