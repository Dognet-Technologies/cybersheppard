import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { format } from 'date-fns';

export default function Violations() {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ['violations'],
    queryFn: () => api.getViolations(),
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: number) => api.acknowledgeViolation(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['violations'] }),
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, notes }: any) => api.resolveViolation(id, notes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['violations'] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Compliance Violations</h1>
        <div className="flex space-x-4 text-sm">
          <span>Critical: <strong className="text-red-600">{data?.summary?.critical || 0}</strong></span>
          <span>High: <strong className="text-orange-600">{data?.summary?.high || 0}</strong></span>
          <span>Medium: <strong className="text-yellow-600">{data?.summary?.medium || 0}</strong></span>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Metric</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detected</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {data?.violations?.map((v: any) => (
              <tr key={v.id}>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 text-xs rounded-full ${getSeverityClass(v.severity)}`}>
                    {v.severity}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">{v.metric_name}</td>
                <td className="px-6 py-4 text-sm">{v.target_id}</td>
                <td className="px-6 py-4 text-sm">{format(new Date(v.first_detected_at), 'PP')}</td>
                <td className="px-6 py-4 text-sm">{v.status}</td>
                <td className="px-6 py-4 text-sm space-x-2">
                  {v.status === 'new' && (
                    <button
                      onClick={() => acknowledgeMutation.mutate(v.id)}
                      className="text-blue-600 hover:text-blue-800"
                    >
                      Acknowledge
                    </button>
                  )}
                  {v.status === 'acknowledged' && (
                    <button
                      onClick={() => resolveMutation.mutate({ id: v.id, notes: 'Resolved' })}
                      className="text-green-600 hover:text-green-800"
                    >
                      Resolve
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function getSeverityClass(severity: string) {
  switch (severity) {
    case 'critical': return 'bg-red-100 text-red-800';
    case 'high': return 'bg-orange-100 text-orange-800';
    case 'medium': return 'bg-yellow-100 text-yellow-800';
    default: return 'bg-gray-100 text-gray-800';
  }
}
