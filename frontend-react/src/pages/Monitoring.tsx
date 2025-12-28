import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Activity, Cpu, HardDrive, Network } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Real-time Monitoring</h1>
          <p className="text-gray-600 mt-1">
            {onlineTargets} target{onlineTargets !== 1 ? 's' : ''} online
          </p>
        </div>
        <div className="flex items-center space-x-2 text-sm">
          <Activity className="w-4 h-4 text-green-500 animate-pulse" />
          <span className="text-gray-600">Live updates</span>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <MetricCard
          title="Avg CPU Usage"
          value="68%"
          icon={<Cpu className="w-8 h-8 text-blue-500" />}
          trend="+5% from last hour"
        />
        <MetricCard
          title="Avg Memory"
          value="7.2 GB"
          icon={<HardDrive className="w-8 h-8 text-green-500" />}
          trend="45% of total"
        />
        <MetricCard
          title="Network Traffic"
          value="289 MB/s"
          icon={<Network className="w-8 h-8 text-purple-500" />}
          trend="↓ 12% from peak"
        />
        <MetricCard
          title="Active Connections"
          value="1,247"
          icon={<Activity className="w-8 h-8 text-orange-500" />}
          trend="Normal range"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CPU Usage */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <Cpu className="w-5 h-5 mr-2 text-blue-500" />
            CPU Usage (Last 24h)
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={cpuData}>
              <defs>
                <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Area type="monotone" dataKey="usage" stroke="#3b82f6" fillOpacity={1} fill="url(#colorCpu)" name="CPU %" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Memory Usage */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <HardDrive className="w-5 h-5 mr-2 text-green-500" />
            Memory Usage (Last 24h)
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={memoryData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="used" stroke="#22c55e" strokeWidth={2} name="Used (GB)" />
              <Line type="monotone" dataKey="available" stroke="#94a3b8" strokeWidth={2} name="Available (GB)" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Network Traffic */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <Network className="w-5 h-5 mr-2 text-purple-500" />
            Network Traffic (Last 24h)
          </h2>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={networkData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Area type="monotone" dataKey="in" stackId="1" stroke="#a855f7" fill="#a855f7" name="Inbound (MB/s)" />
              <Area type="monotone" dataKey="out" stackId="2" stroke="#ec4899" fill="#ec4899" name="Outbound (MB/s)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Target Status List */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Target Status</h2>
          <div className="space-y-3 max-h-[250px] overflow-y-auto">
            {targets?.slice(0, 8).map((target: any) => (
              <div key={target.id} className="flex items-center justify-between py-2 border-b last:border-b-0">
                <div>
                  <p className="font-medium text-sm">{target.hostname}</p>
                  <p className="text-xs text-gray-500">{target.ip_address}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`w-2 h-2 rounded-full ${target.status === 'online' ? 'bg-green-500' : 'bg-red-500'}`}></span>
                  <span className="text-sm text-gray-600">{target.status}</span>
                </div>
              </div>
            )) || (
              <p className="text-gray-500 text-center py-8">No targets available</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ title, value, icon, trend }: any) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between mb-2">
        <p className="text-sm text-gray-600">{title}</p>
        {icon}
      </div>
      <p className="text-3xl font-bold mb-1">{value}</p>
      <p className="text-xs text-gray-500">{trend}</p>
    </div>
  );
}
