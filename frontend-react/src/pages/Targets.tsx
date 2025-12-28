import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Server, CheckCircle, XCircle } from 'lucide-react';

export default function Targets() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Targets</h1>
        <button className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
          Add Target
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {targets?.map((target: any) => (
          <TargetCard key={target.id} target={target} />
        ))}
      </div>
    </div>
  );
}

function TargetCard({ target }: any) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-start justify-between">
        <div className="flex items-center space-x-3">
          <Server className="w-8 h-8 text-gray-600" />
          <div>
            <h3 className="font-semibold">{target.hostname}</h3>
            <p className="text-sm text-gray-500">{target.ip_address}</p>
          </div>
        </div>
        {target.status === 'active' ? (
          <CheckCircle className="w-5 h-5 text-green-500" />
        ) : (
          <XCircle className="w-5 h-5 text-red-500" />
        )}
      </div>

      <div className="mt-4 space-y-2">
        <div className="flex justify-between text-sm">
          <span className="text-gray-600">Environment:</span>
          <span className="font-medium">{target.environment}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-600">Monitoring:</span>
          <span className={target.monitoring_enabled ? 'text-green-600' : 'text-gray-400'}>
            {target.monitoring_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-gray-600">Hardening:</span>
          <span className={target.hardening_applied ? 'text-green-600' : 'text-gray-400'}>
            {target.hardening_applied ? 'Applied' : 'Not Applied'}
          </span>
        </div>
      </div>
    </div>
  );
}
