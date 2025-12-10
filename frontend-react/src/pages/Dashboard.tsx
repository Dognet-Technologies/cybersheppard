import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { AlertTriangle, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

export default function Dashboard() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  const { data: violations } = useQuery({
    queryKey: ['violations'],
    queryFn: () => api.getViolations({ status: 'new' }),
  });

  const stats = {
    total: targets?.length || 0,
    compliant: targets?.filter((t: any) => t.status === 'active')?.length || 0,
    violations: violations?.total || 0,
    critical: violations?.summary?.critical || 0,
  };

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Dashboard</h1>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard
          title="Total Targets"
          value={stats.total}
          icon={<CheckCircle className="w-8 h-8 text-blue-500" />}
        />
        <StatCard
          title="Compliant"
          value={stats.compliant}
          icon={<CheckCircle className="w-8 h-8 text-green-500" />}
        />
        <StatCard
          title="Violations"
          value={stats.violations}
          icon={<AlertTriangle className="w-8 h-8 text-yellow-500" />}
        />
        <StatCard
          title="Critical"
          value={stats.critical}
          icon={<XCircle className="w-8 h-8 text-red-500" />}
        />
      </div>

      {/* Recent Violations */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Recent Violations</h2>
        {violations?.violations?.slice(0, 5).map((violation: any) => (
          <div
            key={violation.id}
            className="flex items-center justify-between py-3 border-b last:border-b-0"
          >
            <div className="flex items-center space-x-3">
              <AlertCircle className={`w-5 h-5 ${getSeverityColor(violation.severity)}`} />
              <div>
                <p className="font-medium">{violation.metric_name}</p>
                <p className="text-sm text-gray-500">Target ID: {violation.target_id}</p>
              </div>
            </div>
            <span className={`px-3 py-1 rounded-full text-sm ${getSeverityBadge(violation.severity)}`}>
              {violation.severity}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({ title, value, icon }: any) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
        </div>
        {icon}
      </div>
    </div>
  );
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-yellow-500';
    default: return 'text-gray-500';
  }
}

function getSeverityBadge(severity: string) {
  switch (severity) {
    case 'critical': return 'bg-red-100 text-red-800';
    case 'high': return 'bg-orange-100 text-orange-800';
    case 'medium': return 'bg-yellow-100 text-yellow-800';
    default: return 'bg-gray-100 text-gray-800';
  }
}
