// ============================================================================
// Compliance Frameworks Page - Security framework compliance monitoring
// ============================================================================

import { useQuery } from '@tanstack/react-query';
import { Shield, CheckCircle, AlertTriangle, TrendingUp, FileText } from 'lucide-react';
import api from '../services/api';
import { PageHeader, Card, StatsGrid, StatCard, Button, Badge, EmptyState } from '../components/ui';

interface ComplianceFramework {
  id: number;
  name: string;
  display_name: string;
  description: string;
  version: string;
  category: string;
  enabled: boolean;
}

interface ComplianceOverview {
  target_id: number;
  hostname: string;
  ip_address: string;
  frameworks_assessed: number;
  avg_compliance_score: number;
  critical_violations: number;
  high_violations: number;
  last_assessment_date: string;
}

interface FrameworkSummary {
  framework_id: number;
  framework_name: string;
  category: string;
  targets_assessed: number;
  avg_compliance_score: number;
  total_controls: number;
  automated_controls: number;
}

export default function ComplianceFrameworks() {
  const { data: frameworks, isLoading: frameworksLoading } = useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: () => api.getComplianceFrameworks(),
  });

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['compliance-overview'],
    queryFn: () => api.getComplianceOverview(),
  });

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['framework-summary'],
    queryFn: () => api.getFrameworkSummary(),
  });

  if (frameworksLoading || overviewLoading || summaryLoading) {
    return (
      <div>
        <PageHeader
          title="Compliance Frameworks"
          subtitle="Monitor compliance across multiple security frameworks"
          icon={<Shield className="w-6 h-6" />}
        />
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-blue-600"></div>
          <p className="text-gray-600 mt-4">Loading compliance data...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Compliance Frameworks"
        subtitle="Monitor compliance across multiple security frameworks"
        icon={<Shield className="w-6 h-6" />}
        actions={
          <Button icon={<FileText className="w-4 h-4" />}>Generate Report</Button>
        }
      />

      {/* Overall Statistics */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          icon={<Shield className="w-6 h-6" />}
          title="Active Frameworks"
          value={frameworks?.filter((f: ComplianceFramework) => f.enabled).length || 0}
          variant="info"
        />
        <StatCard
          icon={<CheckCircle className="w-6 h-6" />}
          title="Avg Compliance Score"
          value={`${Math.round(
            summary?.reduce(
              (acc: number, s: FrameworkSummary) => acc + (s.avg_compliance_score || 0),
              0
            ) / (summary?.length || 1)
          )}%`}
          variant="success"
        />
        <StatCard
          icon={<TrendingUp className="w-6 h-6" />}
          title="Targets Assessed"
          value={overview?.length || 0}
          variant="info"
        />
        <StatCard
          icon={<AlertTriangle className="w-6 h-6" />}
          title="Total Violations"
          value={
            overview?.reduce(
              (acc: number, o: ComplianceOverview) =>
                acc + o.critical_violations + o.high_violations,
              0
            ) || 0
          }
          variant="danger"
        />
      </StatsGrid>

      {/* Framework Cards */}
      <Card className="mb-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Available Frameworks</h2>
            <p className="text-sm text-gray-500 mt-1">
              Security compliance frameworks and standards
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {frameworks?.map((framework: ComplianceFramework) => {
            const frameworkStats = summary?.find(
              (s: FrameworkSummary) => s.framework_id === framework.id
            );

            return (
              <div
                key={framework.id}
                className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    <Shield
                      className={`w-5 h-5 ${
                        framework.enabled ? 'text-blue-600' : 'text-gray-400'
                      }`}
                    />
                    <h3 className="font-semibold text-gray-900">{framework.display_name}</h3>
                  </div>
                  {framework.enabled && <Badge variant="success">Active</Badge>}
                </div>

                <p className="text-sm text-gray-600 mb-3">{framework.description}</p>

                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Version:</span>
                    <span className="font-medium text-gray-900">{framework.version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Category:</span>
                    <span className="font-medium text-gray-900 capitalize">
                      {framework.category.replace(/_/g, ' ')}
                    </span>
                  </div>
                  {frameworkStats && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Targets Assessed:</span>
                        <span className="font-medium text-gray-900">
                          {frameworkStats.targets_assessed}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Total Controls:</span>
                        <span className="font-medium text-gray-900">
                          {frameworkStats.total_controls}
                          <span className="text-xs text-gray-400 ml-1">
                            ({frameworkStats.automated_controls} automated)
                          </span>
                        </span>
                      </div>
                      <div className="flex justify-between items-center pt-2 border-t border-gray-200">
                        <span className="text-gray-500">Avg Score:</span>
                        <div className="flex items-center space-x-2">
                          <div className="w-24 bg-gray-200 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full ${
                                (frameworkStats.avg_compliance_score || 0) >= 80
                                  ? 'bg-green-500'
                                  : (frameworkStats.avg_compliance_score || 0) >= 60
                                  ? 'bg-yellow-500'
                                  : 'bg-red-500'
                              }`}
                              style={{ width: `${frameworkStats.avg_compliance_score || 0}%` }}
                            />
                          </div>
                          <span className="font-semibold text-sm text-gray-900">
                            {Math.round(frameworkStats.avg_compliance_score || 0)}%
                          </span>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Target Compliance Overview */}
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Target Compliance Status</h2>
            <p className="text-sm text-gray-500 mt-1">Compliance status for all monitored targets</p>
          </div>
        </div>
        {overview && overview.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead>
                <tr className="bg-gray-50">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Frameworks
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Avg Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Violations
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Assessment
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {overview.map((target: ComplianceOverview) => (
                  <tr key={target.target_id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="font-medium text-gray-900">{target.hostname}</div>
                        <div className="text-sm text-gray-500">{target.ip_address}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {target.frameworks_assessed}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <div className="w-20 bg-gray-200 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              target.avg_compliance_score >= 80
                                ? 'bg-green-500'
                                : target.avg_compliance_score >= 60
                                ? 'bg-yellow-500'
                                : 'bg-red-500'
                            }`}
                            style={{ width: `${target.avg_compliance_score}%` }}
                          />
                        </div>
                        <span className="text-sm font-medium text-gray-900">
                          {Math.round(target.avg_compliance_score)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex space-x-2">
                        {target.critical_violations > 0 && (
                          <Badge variant="danger">{target.critical_violations} Critical</Badge>
                        )}
                        {target.high_violations > 0 && (
                          <Badge variant="warning">{target.high_violations} High</Badge>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {target.last_assessment_date
                        ? new Date(target.last_assessment_date).toLocaleDateString()
                        : 'Never'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getComplianceStatusBadge(target)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon={<Shield className="w-8 h-8" />}
            title="No compliance assessments yet"
            description="Run assessments to see compliance status for your targets"
          />
        )}
      </Card>
    </div>
  );
}

function getComplianceStatusBadge(target: ComplianceOverview) {
  if (target.critical_violations > 0) {
    return <Badge variant="danger">Critical</Badge>;
  }
  if (target.high_violations > 0) {
    return <Badge variant="warning">Non-Compliant</Badge>;
  }
  if (target.avg_compliance_score >= 80) {
    return <Badge variant="success">Compliant</Badge>;
  }
  return <Badge variant="warning">Warning</Badge>;
}
