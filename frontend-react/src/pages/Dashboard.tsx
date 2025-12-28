import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { AlertTriangle, CheckCircle, XCircle, AlertCircle, Activity, TrendingUp } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

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
    online: targets?.filter((t: any) => t.status === 'online')?.length || 0,
    offline: targets?.filter((t: any) => t.status === 'offline')?.length || 0,
    violations: violations?.total || 0,
    critical: violations?.summary?.critical || 0,
    high: violations?.summary?.high || 0,
    medium: violations?.summary?.medium || 0,
    low: violations?.summary?.low || 0,
  };

  // Sample data for charts (in real app, this would come from API)
  const violationsTrend = [
    { date: 'Mon', count: 12 },
    { date: 'Tue', count: 19 },
    { date: 'Wed', count: 15 },
    { date: 'Thu', count: 25 },
    { date: 'Fri', count: 22 },
    { date: 'Sat', count: 18 },
    { date: 'Sun', count: 20 },
  ];

  const severityData = [
    { name: 'Critical', value: stats.critical, color: '#ef4444' },
    { name: 'High', value: stats.high, color: '#f97316' },
    { name: 'Medium', value: stats.medium, color: '#eab308' },
    { name: 'Low', value: stats.low, color: '#64748b' },
  ];

  const targetStatusData = [
    { name: 'Online', value: stats.online, color: '#22c55e' },
    { name: 'Offline', value: stats.offline, color: '#ef4444' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <div className="flex items-center space-x-2 text-sm text-gray-600">
          <Activity className="w-4 h-4" />
          <span>Real-time monitoring</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard
          title="Total Targets"
          value={stats.total}
          icon={<CheckCircle className="w-8 h-8 text-blue-500" />}
          change="+2 this week"
        />
        <StatCard
          title="Online"
          value={stats.online}
          icon={<CheckCircle className="w-8 h-8 text-green-500" />}
          change={`${Math.round((stats.online / stats.total) * 100) || 0}%`}
        />
        <StatCard
          title="Violations"
          value={stats.violations}
          icon={<AlertTriangle className="w-8 h-8 text-yellow-500" />}
          change="+5 today"
        />
        <StatCard
          title="Critical"
          value={stats.critical}
          icon={<XCircle className="w-8 h-8 text-red-500" />}
          change="Requires attention"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Violations Trend */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <TrendingUp className="w-5 h-5 mr-2" />
            Violations Trend (7 days)
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={violationsTrend}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} name="Violations" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Target Status */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Target Status</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={targetStatusData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="value" fill="#3b82f6" name="Count">
                {targetStatusData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Recent Violations */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Recent Violations</h2>
          <div className="space-y-3 max-h-[250px] overflow-y-auto">
            {violations?.violations?.slice(0, 5).map((violation: any) => (
              <div
                key={violation.id}
                className="flex items-center justify-between py-2 border-b last:border-b-0"
              >
                <div className="flex items-center space-x-3">
                  <AlertCircle className={`w-5 h-5 ${getSeverityColor(violation.severity)}`} />
                  <div>
                    <p className="font-medium text-sm">{violation.metric_name}</p>
                    <p className="text-xs text-gray-500">Target ID: {violation.target_id}</p>
                  </div>
                </div>
                <span className={`px-2 py-1 rounded-full text-xs ${getSeverityBadge(violation.severity)}`}>
                  {violation.severity}
                </span>
              </div>
            )) || (
              <p className="text-gray-500 text-center py-8">No violations detected</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon, change }: any) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
          {change && (
            <p className="text-xs text-gray-500 mt-1">{change}</p>
          )}
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
