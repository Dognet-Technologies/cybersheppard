// ============================================================================
// Monitoring Page - Real-time metrics and performance monitoring
// ============================================================================

import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Activity, Cpu, HardDrive, Network } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { PageHeader, Card, CardHeader, StatsGrid, StatCard, Badge } from '../components/ui';

export default function Monitoring() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  // Sample metrics data (in real app, this would come from InfluxDB via API)
  const cpuData = [
    { time: '00:00', usage: 45 },
    { time: '04:00', usage: 32 },
    { time: '08:00', usage: 68 },
    { time: '12:00', usage: 72 },
    { time: '16:00', usage: 85 },
    { time: '20:00', usage: 55 },
  ];

  const memoryData = [
    { time: '00:00', used: 4.2, available: 11.8 },
    { time: '04:00', used: 4.5, available: 11.5 },
    { time: '08:00', used: 6.8, available: 9.2 },
    { time: '12:00', used: 7.2, available: 8.8 },
    { time: '16:00', used: 8.1, available: 7.9 },
    { time: '20:00', used: 6.5, available: 9.5 },
  ];

  const networkData = [
    { time: '00:00', in: 125, out: 89 },
    { time: '04:00', in: 98, out: 67 },
    { time: '08:00', in: 256, out: 178 },
    { time: '12:00', in: 312, out: 245 },
    { time: '16:00', in: 289, out: 198 },
    { time: '20:00', in: 167, out: 123 },
  ];

  const onlineTargets = targets?.filter((t: any) => t.status === 'online').length || 0;

  return (
    <div>
      <PageHeader
        title="Real-time Monitoring"
        subtitle={`${onlineTargets} target${onlineTargets !== 1 ? 's' : ''} online`}
        icon={<Activity className="w-6 h-6" />}
        actions={
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-green-500 animate-pulse" />
            <Badge variant="success">Live updates</Badge>
          </div>
        }
      />

      {/* Quick Stats */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Avg CPU Usage"
          value="68%"
          icon={<Cpu className="w-6 h-6" />}
          variant="info"
          trend={{ value: 5, label: 'from last hour' }}
        />
        <StatCard
          title="Avg Memory"
          value="7.2 GB"
          icon={<HardDrive className="w-6 h-6" />}
          variant="success"
        />
        <StatCard
          title="Network Traffic"
          value="289 MB/s"
          icon={<Network className="w-6 h-6" />}
          variant="info"
          trend={{ value: -12, label: 'from peak' }}
        />
        <StatCard
          title="Active Connections"
          value="1,247"
          icon={<Activity className="w-6 h-6" />}
          variant="default"
        />
      </StatsGrid>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CPU Usage */}
        <Card>
          <CardHeader
            title="CPU Usage (Last 24h)"
            subtitle="Average processor utilization"
          />
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={cpuData}>
              <defs>
                <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Area
                type="monotone"
                dataKey="usage"
                stroke="#3b82f6"
                fillOpacity={1}
                fill="url(#colorCpu)"
                name="CPU %"
              />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        {/* Memory Usage */}
        <Card>
          <CardHeader
            title="Memory Usage (Last 24h)"
            subtitle="RAM utilization over time"
          />
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={memoryData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="used"
                stroke="#22c55e"
                strokeWidth={2}
                name="Used (GB)"
              />
              <Line
                type="monotone"
                dataKey="available"
                stroke="#94a3b8"
                strokeWidth={2}
                name="Available (GB)"
              />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        {/* Network Traffic */}
        <Card>
          <CardHeader
            title="Network Traffic (Last 24h)"
            subtitle="Inbound and outbound data flow"
          />
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={networkData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Area
                type="monotone"
                dataKey="in"
                stackId="1"
                stroke="#a855f7"
                fill="#a855f7"
                name="Inbound (MB/s)"
              />
              <Area
                type="monotone"
                dataKey="out"
                stackId="2"
                stroke="#ec4899"
                fill="#ec4899"
                name="Outbound (MB/s)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        {/* Target Status List */}
        <Card>
          <CardHeader title="Target Status" subtitle="Current monitoring status" />
          <div className="space-y-3 max-h-[250px] overflow-y-auto">
            {targets?.slice(0, 8).map((target: any) => (
              <div
                key={target.id}
                className="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0"
              >
                <div>
                  <p className="font-medium text-sm text-gray-900">{target.hostname}</p>
                  <p className="text-xs text-gray-500">{target.ip_address}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      target.status === 'online' ? 'bg-green-500' : 'bg-red-500'
                    }`}
                  ></span>
                  <Badge variant={target.status === 'online' ? 'success' : 'danger'}>
                    {target.status}
                  </Badge>
                </div>
              </div>
            )) || (
              <p className="text-gray-500 text-center py-8">No targets available</p>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
