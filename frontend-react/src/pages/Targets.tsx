import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { Server, CheckCircle, XCircle, Trash2, Edit, Activity } from 'lucide-react';
import AddTargetModal from '../components/AddTargetModal';

export default function Targets() {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const queryClient = useQueryClient();

  const { data: targets, isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.deleteTarget(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    },
  });

  const handleDelete = async (id: number, hostname: string) => {
    if (confirm(`Are you sure you want to delete target "${hostname}"?`)) {
      deleteMutation.mutate(id);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Targets</h1>
          <p className="text-gray-600 mt-1">
            {targets?.length || 0} target{(targets?.length || 0) !== 1 ? 's' : ''} monitored
          </p>
        </div>
        <button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center space-x-2"
        >
          <Server className="w-4 h-4" />
          <span>Add Target</span>
        </button>
      </div>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <p className="text-gray-600 mt-2">Loading targets...</p>
        </div>
      ) : targets?.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-12 text-center">
          <Server className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No targets yet</h3>
          <p className="text-gray-600 mb-4">Get started by adding your first target system</p>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700"
          >
            Add Your First Target
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {targets?.map((target: any) => (
            <TargetCard key={target.id} target={target} onDelete={handleDelete} />
          ))}
        </div>
      )}

      <AddTargetModal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} />
    </div>
  );
}

function TargetCard({ target, onDelete }: any) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-500';
      case 'offline': return 'text-red-500';
      case 'error': return 'text-orange-500';
      default: return 'text-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online': return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'offline': return <XCircle className="w-5 h-5 text-red-500" />;
      case 'error': return <Activity className="w-5 h-5 text-orange-500" />;
      default: return <XCircle className="w-5 h-5 text-gray-500" />;
    }
  };

  const getEnvironmentColor = (env: string) => {
    switch (env) {
      case 'production': return 'bg-red-100 text-red-800';
      case 'staging': return 'bg-yellow-100 text-yellow-800';
      case 'development': return 'bg-blue-100 text-blue-800';
      case 'testing': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <Server className="w-8 h-8 text-gray-600" />
          <div>
            <h3 className="font-semibold">{target.hostname}</h3>
            <p className="text-sm text-gray-500">{target.ip_address}</p>
          </div>
        </div>
        {getStatusIcon(target.status)}
      </div>

      <div className="space-y-2 mb-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Status:</span>
          <span className={`font-medium ${getStatusColor(target.status)}`}>
            {target.status || 'unknown'}
          </span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Environment:</span>
          <span className={`px-2 py-1 rounded text-xs font-medium ${getEnvironmentColor(target.environment)}`}>
            {target.environment}
          </span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Monitoring:</span>
          <span className={target.monitoring_enabled ? 'text-green-600 font-medium' : 'text-gray-400'}>
            {target.monitoring_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">Hardening:</span>
          <span className={target.hardening_applied ? 'text-green-600 font-medium' : 'text-gray-400'}>
            {target.hardening_applied ? 'Applied' : 'Not Applied'}
          </span>
        </div>
        {target.gruppo && (
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-600">Group:</span>
            <span className="text-gray-900 font-medium">{target.gruppo}</span>
          </div>
        )}
      </div>

      <div className="flex items-center space-x-2 pt-4 border-t">
        <button
          className="flex-1 flex items-center justify-center space-x-2 px-3 py-2 text-sm text-blue-600 border border-blue-600 rounded hover:bg-blue-50"
        >
          <Edit className="w-4 h-4" />
          <span>Edit</span>
        </button>
        <button
          onClick={() => onDelete(target.id, target.hostname)}
          className="flex-1 flex items-center justify-center space-x-2 px-3 py-2 text-sm text-red-600 border border-red-600 rounded hover:bg-red-50"
        >
          <Trash2 className="w-4 h-4" />
          <span>Delete</span>
        </button>
      </div>
    </div>
  );
}
