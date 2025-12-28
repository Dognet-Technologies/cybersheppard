import { useQuery } from '@tanstack/react-query';
import { Shield, CheckCircle, AlertTriangle, XCircle, TrendingUp, FileText } from 'lucide-react';
import api from '../services/api';

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
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading compliance data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Compliance Frameworks</h1>
          <p className="text-gray-500 mt-1">
            Monitor compliance across multiple security frameworks
          </p>
        </div>
        <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2">
          <FileText className="w-4 h-4" />
          <span>Generate Report</span>
        </button>
      </div>

      {/* Overall Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          icon={<Shield className="w-6 h-6 text-blue-600" />}
          label="Active Frameworks"
          value={frameworks?.filter((f: ComplianceFramework) => f.enabled).length || 0}
          bgColor="bg-blue-50"
        />
        <StatCard
          icon={<CheckCircle className="w-6 h-6 text-green-600" />}
          label="Avg Compliance Score"
          value={`${Math.round(
            summary?.reduce((acc: number, s: FrameworkSummary) => acc + (s.avg_compliance_score || 0), 0) /
            (summary?.length || 1)
          )}%`}
          bgColor="bg-green-50"
        />
        <StatCard
          icon={<TrendingUp className="w-6 h-6 text-purple-600" />}
          label="Targets Assessed"
          value={overview?.length || 0}
          bgColor="bg-purple-50"
        />
        <StatCard
          icon={<AlertTriangle className="w-6 h-6 text-red-600" />}
          label="Total Violations"
          value={
            overview?.reduce((acc: number, o: ComplianceOverview) =>
              acc + o.critical_violations + o.high_violations, 0
            ) || 0
          }
          bgColor="bg-red-50"
        />
      </div>

      {/* Framework Cards */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Available Frameworks</h2>
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
                    <Shield className={`w-5 h-5 ${framework.enabled ? 'text-blue-600' : 'text-gray-400'}`} />
                    <h3 className="font-semibold text-gray-900">{framework.display_name}</h3>
                  </div>
                  {framework.enabled && (
                    <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
                      Active
                    </span>
                  )}
                </div>

                <p className="text-sm text-gray-600 mb-3">{framework.description}</p>

                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Version:</span>
                    <span className="font-medium">{framework.version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Category:</span>
                    <span className="font-medium capitalize">
                      {framework.category.replace(/_/g, ' ')}
                    </span>
                  </div>
                  {frameworkStats && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Targets Assessed:</span>
                        <span className="font-medium">{frameworkStats.targets_assessed}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Total Controls:</span>
                        <span className="font-medium">
                          {frameworkStats.total_controls}
                          <span className="text-xs text-gray-400 ml-1">
                            ({frameworkStats.automated_controls} automated)
                          </span>
                        </span>
                      </div>
                      <div className="flex justify-between items-center pt-2 border-t">
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
                          <span className="font-semibold text-sm">
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
      </div>

      {/* Target Compliance Overview */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Target Compliance Status</h2>
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
                        <span className="text-sm font-medium">
                          {Math.round(target.avg_compliance_score)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex space-x-2">
                        {target.critical_violations > 0 && (
                          <span className="bg-red-100 text-red-800 text-xs px-2 py-1 rounded">
                            {target.critical_violations} Critical
                          </span>
                        )}
                        {target.high_violations > 0 && (
                          <span className="bg-orange-100 text-orange-800 text-xs px-2 py-1 rounded">
                            {target.high_violations} High
                          </span>
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
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-500">No compliance assessments yet</p>
            <p className="text-sm text-gray-400">Run assessments to see compliance status</p>
          </div>
        )}
      </div>
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

function getComplianceStatusBadge(target: ComplianceOverview) {
  if (target.critical_violations > 0) {
    return (
      <span className="inline-flex items-center space-x-1 bg-red-100 text-red-800 text-xs px-2 py-1 rounded">
        <XCircle className="w-3 h-3" />
        <span>Critical</span>
      </span>
    );
  }
  if (target.high_violations > 0) {
    return (
      <span className="inline-flex items-center space-x-1 bg-orange-100 text-orange-800 text-xs px-2 py-1 rounded">
        <AlertTriangle className="w-3 h-3" />
        <span>Non-Compliant</span>
      </span>
    );
  }
  if (target.avg_compliance_score >= 80) {
    return (
      <span className="inline-flex items-center space-x-1 bg-green-100 text-green-800 text-xs px-2 py-1 rounded">
        <CheckCircle className="w-3 h-3" />
        <span>Compliant</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center space-x-1 bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded">
      <AlertTriangle className="w-3 h-3" />
      <span>Warning</span>
    </span>
  );
}
