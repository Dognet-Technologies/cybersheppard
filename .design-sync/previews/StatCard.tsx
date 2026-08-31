import { StatCard } from 'cybersheppard-frontend';
import { AlertTriangle, Server, ShieldCheck, Activity } from 'lucide-react';

export const Metrics = () => (
  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-2xl">
    <StatCard
      title="Active Alerts"
      value={7}
      variant="danger"
      subtitle="2 critical, 5 high"
      icon={<AlertTriangle className="w-6 h-6" />}
    />
    <StatCard
      title="Hosts Online"
      value="12 / 13"
      variant="success"
      icon={<Server className="w-6 h-6" />}
    />
    <StatCard
      title="Compliance Score"
      value="86%"
      variant="info"
      icon={<ShieldCheck className="w-6 h-6" />}
    />
    <StatCard
      title="Events / min"
      value={1840}
      icon={<Activity className="w-6 h-6" />}
    />
  </div>
);

export const WithTrend = () => (
  <div className="max-w-xs">
    <StatCard
      title="Resolved this week"
      value={42}
      variant="success"
      trend={{ value: 18, label: 'vs last week' }}
      icon={<ShieldCheck className="w-6 h-6" />}
    />
  </div>
);

export const Variants = () => (
  <div className="grid grid-cols-2 gap-4 max-w-xl">
    <StatCard title="Default" value={128} />
    <StatCard title="Success" value={96} variant="success" />
    <StatCard title="Warning" value={11} variant="warning" />
    <StatCard title="Danger" value={3} variant="danger" />
  </div>
);
