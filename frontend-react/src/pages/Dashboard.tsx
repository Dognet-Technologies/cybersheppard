// ============================================================================
// Dashboard - Main overview page
// ============================================================================

import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import {
  Server,
  AlertTriangle,
  CheckCircle,
  Activity,
  Shield,
  TrendingUp,
} from 'lucide-react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { PageHeader, StatsGrid, StatCard, Card, CardHeader } from '../components/ui';

export default function Dashboard() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  const { data: violations } = useQuery({
    queryKey: ['violations'],
    queryFn: () => api.getViolations({ status: 'new' }),
  });

  const { data: alerts } = useQuery({
    queryKey: ['alerts', 'active'],
    queryFn: () => api.getActiveAlerts(),
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
    alerts: alerts?.length || 0,
  };

  // Sample trend data
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
    { name: 'Critical', value: stats.critical || 5, color: '#ef4444' },
    { name: 'High', value: stats.high || 12, color: '#f97316' },
    { name: 'Medium', value: stats.medium || 8, color: '#eab308' },
    { name: 'Low', value: stats.low || 3, color: '#64748b' },
  ];

  const targetStatusData = [
    { name: 'Online', value: stats.online || 15, color: '#22c55e' },
    { name: 'Offline', value: stats.offline || 3, color: '#ef4444' },
  ];

  const complianceData = [
    { framework: 'CIS', score: 85 },
    { framework: 'NIST', score: 78 },
    { framework: 'PCI-DSS', score: 92 },
    { framework: 'ISO 27001', score: 88 },
  ];

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Overview of your security infrastructure"
        icon={<Activity className="w-6 h-6" />}
      />

      {/* Stats Overview */}
      <StatsGrid columns={4} className="mb-8">
        <StatCard
          title="Total Targets"
          value={stats.total}
          icon={<Server className="w-6 h-6" />}
          variant="info"
          trend={{ value: 12, label: 'vs last week' }}
        />
        <StatCard
          title="Online Targets"
          value={stats.online}
          icon={<CheckCircle className="w-6 h-6" />}
          variant="success"
        />
        <StatCard
          title="Active Violations"
          value={stats.violations}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant={stats.violations > 10 ? 'danger' : 'warning'}
        />
        <StatCard
          title="Active Alerts"
          value={stats.alerts}
          icon={<Shield className="w-6 h-6" />}
          variant={stats.alerts > 5 ? 'warning' : 'default'}
        />
      </StatsGrid>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Violations Trend */}
        <Card>
          <CardHeader
            title="Violations Trend"
            subtitle="Last 7 days"
            action={
              <select className="text-sm border-gray-300 rounded-md">
                <option>Last 7 days</option>
                <option>Last 30 days</option>
                <option>Last 90 days</option>
              </select>
            }
          />
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={violationsTrend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="date" stroke="#6b7280" />
              <YAxis stroke="#6b7280" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#fff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={{ fill: '#3b82f6', r: 4 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        {/* Severity Distribution */}
        <Card>
          <CardHeader title="Violations by Severity" subtitle="Current distribution" />
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
        </Card>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Target Status */}
        <Card>
          <CardHeader title="Target Status" subtitle="Current availability" />
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={targetStatusData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {targetStatusData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* Compliance Score */}
        <Card>
          <CardHeader title="Compliance Scores" subtitle="By framework" />
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={complianceData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="framework" stroke="#6b7280" />
              <YAxis stroke="#6b7280" domain={[0, 100]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#fff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                }}
              />
              <Bar dataKey="score" fill="#3b82f6" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader title="Recent Activity" subtitle="Last 24 hours" />
        <div className="space-y-4">
          <ActivityItem
            icon={<AlertTriangle className="w-5 h-5 text-red-600" />}
            title="Critical vulnerability detected"
            description="CVE-2024-1234 on server-prod-01"
            time="2 hours ago"
          />
          <ActivityItem
            icon={<CheckCircle className="w-5 h-5 text-green-600" />}
            title="Hardening applied successfully"
            description="CIS Level 1 on server-dev-03"
            time="4 hours ago"
          />
          <ActivityItem
            icon={<TrendingUp className="w-5 h-5 text-blue-600" />}
            title="New target added"
            description="server-prod-05 registered"
            time="6 hours ago"
          />
          <ActivityItem
            icon={<Shield className="w-5 h-5 text-yellow-600" />}
            title="Security scan completed"
            description="15 targets scanned, 3 issues found"
            time="8 hours ago"
          />
        </div>
      </Card>
    </div>
  );
}

interface ActivityItemProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  time: string;
}

function ActivityItem({ icon, title, description, time }: ActivityItemProps) {
  return (
    <div className="flex items-start space-x-4 pb-4 border-b border-gray-100 last:border-0 last:pb-0">
      <div className="flex-shrink-0 w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center">
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-900">{title}</p>
        <p className="text-sm text-gray-500">{description}</p>
      </div>
      <span className="text-xs text-gray-400 flex-shrink-0">{time}</span>
    </div>
  );
}
