// ============================================================================
// Compliance Dashboard - Framework scoring and gap analysis
// ============================================================================

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  BarChart3,
  FileText,
  Target,
} from 'lucide-react';
import api from '../services/api';
import { PageHeader, Card, StatsGrid, StatCard, Button, Badge, Select } from '../components/ui';

interface FrameworkScore {
  framework_code: string;
  framework_name: string;
  compliance_score: number;
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  not_applicable_controls: number;
  not_checked_controls: number;
  critical_gaps: number;
  high_gaps: number;
  last_scan_at: string;
}

interface TargetCompliance {
  target_id: number;
  hostname: string;
  ip_address: string;
  frameworks: {
    nis2: number;
    nist: number;
    iso27001: number;
    mitre: number;
  };
  avg_score: number;
  status: 'compliant' | 'non_compliant' | 'warning';
}

interface ComplianceGap {
  control_id: number;
  requirement: string;
  macroarea: string;
  priority: string;
  framework_code: string;
  gap_description: string;
  target_count: number;
}

export default function ComplianceDashboard() {
  const [selectedTarget, setSelectedTarget] = useState<number | 'all'>('all');
  const [selectedFramework, setSelectedFramework] = useState<string>('all');

  const { data: overviewData, isLoading: overviewLoading } = useQuery({
    queryKey: ['compliance-dashboard', selectedTarget],
    queryFn: () =>
      api.getComplianceDashboard({
        target_id: selectedTarget !== 'all' ? selectedTarget : undefined,
      }),
  });

  const { data: targetsData } = useQuery({
    queryKey: ['compliance-targets'],
    queryFn: () => api.getComplianceTargets(),
  });

  const { data: gapsData } = useQuery({
    queryKey: ['compliance-gaps', selectedFramework],
    queryFn: () =>
      api.getComplianceGaps({
        framework: selectedFramework !== 'all' ? selectedFramework : undefined,
        priority: ['Critical', 'High'],
      }),
  });

  const frameworkScores: FrameworkScore[] = overviewData?.frameworks || [];
  const targets: TargetCompliance[] = targetsData?.targets || [];
  const gaps: ComplianceGap[] = gapsData?.gaps || [];

  const avgComplianceScore =
    frameworkScores.reduce((sum, f) => sum + f.compliance_score, 0) /
      (frameworkScores.length || 1) || 0;

  const totalGaps = gaps.length;
  const criticalGaps = gaps.filter((g) => g.priority === 'Critical').length;
  const highGaps = gaps.filter((g) => g.priority === 'High').length;

  if (overviewLoading) {
    return (
      <div>
        <PageHeader
          title="Compliance Dashboard"
          subtitle="Multi-framework compliance monitoring"
          icon={<BarChart3 className="w-6 h-6" />}
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
        title="Compliance Dashboard"
        subtitle="Real-time compliance tracking across NIS2, NIST, ISO 27001, and MITRE D3FEND"
        icon={<BarChart3 className="w-6 h-6" />}
        actions={
          <div className="flex space-x-2">
            <Select
              value={selectedTarget.toString()}
              onChange={(e) => setSelectedTarget(e.target.value === 'all' ? 'all' : Number(e.target.value))}
            >
              <option value="all">All Targets</option>
              {targets.map((target) => (
                <option key={target.target_id} value={target.target_id}>
                  {target.hostname}
                </option>
              ))}
            </Select>
            <Button variant="primary" size="sm" icon={<FileText className="w-4 h-4" />}>
              Export Report
            </Button>
          </div>
        }
      />

      {/* Overall Statistics */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          icon={<Shield className="w-6 h-6" />}
          title="Avg Compliance Score"
          value={`${Math.round(avgComplianceScore)}%`}
          variant={avgComplianceScore >= 80 ? 'success' : avgComplianceScore >= 60 ? 'warning' : 'danger'}
          trend={avgComplianceScore >= 70 ? '+5%' : undefined}
        />
        <StatCard
          icon={<CheckCircle className="w-6 h-6" />}
          title="Frameworks"
          value={frameworkScores.length}
          variant="info"
          subtitle="Active frameworks"
        />
        <StatCard
          icon={<AlertTriangle className="w-6 h-6" />}
          title="Critical Gaps"
          value={criticalGaps}
          variant="danger"
          subtitle={`${highGaps} high priority`}
        />
        <StatCard
          icon={<Target className="w-6 h-6" />}
          title="Monitored Targets"
          value={targets.length}
          variant="info"
          subtitle="Active hosts"
        />
      </StatsGrid>

      {/* Framework Scores */}
      <Card className="mb-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Framework Compliance Scores</h2>
            <p className="text-sm text-gray-500 mt-1">
              Compliance status across all frameworks
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {frameworkScores.map((framework) => (
            <FrameworkScoreCard key={framework.framework_code} framework={framework} />
          ))}
        </div>
      </Card>

      {/* Target Compliance Matrix */}
      <Card className="mb-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Target Compliance Matrix</h2>
            <p className="text-sm text-gray-500 mt-1">
              Compliance scores per target and framework
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr className="bg-gray-50">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Target
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  NIS2
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  NIST
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  ISO 27001
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  MITRE
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Avg Score
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {targets.map((target) => (
                <tr key={target.target_id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div>
                      <div className="font-medium text-gray-900">{target.hostname}</div>
                      <div className="text-sm text-gray-500">{target.ip_address}</div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-center">
                    <ScoreCell score={target.frameworks.nis2} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-center">
                    <ScoreCell score={target.frameworks.nist} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-center">
                    <ScoreCell score={target.frameworks.iso27001} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-center">
                    <ScoreCell score={target.frameworks.mitre} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-center">
                    <ScoreCell score={target.avg_score} showBar />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-center">
                    <Badge
                      variant={
                        target.status === 'compliant'
                          ? 'success'
                          : target.status === 'warning'
                          ? 'warning'
                          : 'danger'
                      }
                    >
                      {target.status}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Compliance Gaps */}
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Critical & High Priority Gaps</h2>
            <p className="text-sm text-gray-500 mt-1">
              {totalGaps} gaps requiring immediate attention
            </p>
          </div>
          <Select
            value={selectedFramework}
            onChange={(e) => setSelectedFramework(e.target.value)}
          >
            <option value="all">All Frameworks</option>
            <option value="nis2">NIS2</option>
            <option value="nist">NIST 800-53</option>
            <option value="iso27001">ISO 27001</option>
            <option value="mitre">MITRE D3FEND</option>
          </Select>
        </div>

        {gaps.length === 0 ? (
          <div className="text-center py-12">
            <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              No Critical or High Priority Gaps
            </h3>
            <p className="text-gray-500">
              All critical and high priority controls are compliant across selected frameworks
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {gaps.map((gap) => (
              <div
                key={gap.control_id}
                className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <Badge variant={gap.priority === 'Critical' ? 'danger' : 'warning'}>
                        {gap.priority}
                      </Badge>
                      <Badge variant="default" size="sm">
                        {gap.framework_code.toUpperCase()}
                      </Badge>
                      <span className="text-xs text-gray-500">{gap.macroarea}</span>
                    </div>
                    <h4 className="font-medium text-gray-900 mb-1">{gap.requirement}</h4>
                    <p className="text-sm text-gray-600">{gap.gap_description}</p>
                  </div>
                  <div className="ml-4 text-right">
                    <div className="text-2xl font-bold text-red-600">{gap.target_count}</div>
                    <div className="text-xs text-gray-500">
                      {gap.target_count === 1 ? 'target' : 'targets'}
                    </div>
                  </div>
                </div>
                <div className="flex justify-end mt-3">
                  <Button variant="outline" size="sm">
                    View Remediation
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function FrameworkScoreCard({ framework }: { framework: FrameworkScore }) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getProgressColor = (score: number) => {
    if (score >= 80) return 'bg-green-500';
    if (score >= 60) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  return (
    <div className="border border-gray-200 rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <Shield className="w-6 h-6 text-blue-600" />
          <div>
            <h3 className="font-semibold text-gray-900">{framework.framework_name}</h3>
            <p className="text-xs text-gray-500">{framework.framework_code.toUpperCase()}</p>
          </div>
        </div>
        <div className="text-right">
          <div className={`text-3xl font-bold ${getScoreColor(framework.compliance_score)}`}>
            {Math.round(framework.compliance_score)}%
          </div>
        </div>
      </div>

      <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
        <div
          className={`h-2 rounded-full transition-all ${getProgressColor(
            framework.compliance_score
          )}`}
          style={{ width: `${framework.compliance_score}%` }}
        />
      </div>

      <div className="grid grid-cols-2 gap-4 text-sm mb-4">
        <div>
          <div className="text-gray-500">Total Controls</div>
          <div className="font-semibold text-gray-900">{framework.total_controls}</div>
        </div>
        <div>
          <div className="text-gray-500">Compliant</div>
          <div className="font-semibold text-green-600">{framework.compliant_controls}</div>
        </div>
        <div>
          <div className="text-gray-500">Non-Compliant</div>
          <div className="font-semibold text-red-600">{framework.non_compliant_controls}</div>
        </div>
        <div>
          <div className="text-gray-500">Not Checked</div>
          <div className="font-semibold text-gray-600">{framework.not_checked_controls}</div>
        </div>
      </div>

      {(framework.critical_gaps > 0 || framework.high_gaps > 0) && (
        <div className="border-t border-gray-200 pt-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-600">Priority Gaps:</span>
            <div className="flex space-x-2">
              {framework.critical_gaps > 0 && (
                <Badge variant="danger" size="sm">
                  {framework.critical_gaps} Critical
                </Badge>
              )}
              {framework.high_gaps > 0 && (
                <Badge variant="warning" size="sm">
                  {framework.high_gaps} High
                </Badge>
              )}
            </div>
          </div>
        </div>
      )}

      {framework.last_scan_at && (
        <div className="text-xs text-gray-500 mt-3">
          Last scan: {new Date(framework.last_scan_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

function ScoreCell({ score, showBar }: { score: number; showBar?: boolean }) {
  const getColor = (score: number) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getBarColor = (score: number) => {
    if (score >= 80) return 'bg-green-500';
    if (score >= 60) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  if (score === null || score === undefined || score === 0) {
    return <span className="text-gray-400">-</span>;
  }

  return (
    <div className="flex flex-col items-center">
      <span className={`font-semibold ${getColor(score)}`}>{Math.round(score)}%</span>
      {showBar && (
        <div className="w-16 bg-gray-200 rounded-full h-1.5 mt-1">
          <div
            className={`h-1.5 rounded-full ${getBarColor(score)}`}
            style={{ width: `${score}%` }}
          />
        </div>
      )}
    </div>
  );
}
