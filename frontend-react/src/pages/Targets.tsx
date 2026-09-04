// ============================================================================
// Targets Page - Manage monitored systems
// ============================================================================

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { Server, CheckCircle, XCircle, Trash2, Edit, Activity, Plus, Link2 } from 'lucide-react';
import AddTargetModal from '../components/AddTargetModal';
import EditTargetModal from '../components/EditTargetModal';
import PairingModal from '../components/PairingModal';
import { PageHeader, Button, Card, EmptyState, StatusBadge, Badge } from '../components/ui';
import { HELP } from '../i18n/help';

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

  if (isLoading) {
    return (
      <div>
        <PageHeader
          title="Targets"
          subtitle="Manage monitored systems"
          icon={<Server className="w-6 h-6" />}
        />
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-blue-600"></div>
          <p className="text-gray-600 mt-4">Loading targets...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Targets"
        subtitle={`${targets?.length || 0} target${(targets?.length || 0) !== 1 ? 's' : ''} monitored`}
        icon={<Server className="w-6 h-6" />}
        info={HELP.page.targets}
        actions={
          <Button onClick={() => setIsAddModalOpen(true)} icon={<Plus className="w-4 h-4" />}>
            Add Target
          </Button>
        }
      />

      {targets?.length === 0 ? (
        <EmptyState
          icon={<Server className="w-8 h-8" />}
          title="No targets yet"
          description="Get started by adding your first target system to monitor"
          action={{
            label: 'Add Your First Target',
            onClick: () => setIsAddModalOpen(true),
            icon: <Plus className="w-4 h-4" />,
          }}
        />
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
  const [isPairingOpen, setIsPairingOpen] = useState(false);
  const [isEditOpen, setIsEditOpen] = useState(false);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'offline':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'error':
        return <Activity className="w-5 h-5 text-orange-500" />;
      default:
        return <XCircle className="w-5 h-5 text-gray-500" />;
    }
  };

  const getEnvironmentBadge = (env: string) => {
    const variants: Record<string, 'danger' | 'warning' | 'info' | 'success' | 'default'> = {
      production: 'danger',
      staging: 'warning',
      development: 'info',
      testing: 'success',
    };
    return variants[env] || 'default';
  };

  return (
    <Card hover className="h-full">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
            <Server className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900">{target.hostname}</h3>
            <p className="text-sm text-gray-500">{target.ip_address}</p>
          </div>
        </div>
        {getStatusIcon(target.status)}
      </div>

      <div className="space-y-3 mb-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Status</span>
          <StatusBadge status={target.status} />
        </div>

        {target.environment && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600">Environment</span>
            <Badge variant={getEnvironmentBadge(target.environment)}>
              {target.environment}
            </Badge>
          </div>
        )}

        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Monitoring</span>
          <span
            className={`text-sm font-medium ${
              target.monitoring_enabled ? 'text-green-600' : 'text-gray-400'
            }`}
          >
            {target.monitoring_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-600">Hardening</span>
          <span
            className={`text-sm font-medium ${
              target.hardening_applied ? 'text-green-600' : 'text-gray-400'
            }`}
          >
            {target.hardening_applied ? 'Applied' : 'Not Applied'}
          </span>
        </div>

        {target.gruppo && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600">Group</span>
            <span className="text-sm font-medium text-gray-900">{target.gruppo}</span>
          </div>
        )}
      </div>

      <div className="pt-4 border-t border-gray-200 space-y-2">
        <Button
          variant="primary"
          size="sm"
          className="w-full"
          icon={<Link2 className="w-4 h-4" />}
          onClick={() => setIsPairingOpen(true)}
        >
          Agent pairing
        </Button>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" className="flex-1" icon={<Edit className="w-4 h-4" />} onClick={() => setIsEditOpen(true)}>
            Edit
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="flex-1 text-red-600 hover:text-red-700 hover:bg-red-50"
            icon={<Trash2 className="w-4 h-4" />}
            onClick={() => onDelete(target.id, target.hostname)}
          >
            Delete
          </Button>
        </div>
      </div>

      <PairingModal isOpen={isPairingOpen} onClose={() => setIsPairingOpen(false)} target={target} />
      <EditTargetModal isOpen={isEditOpen} onClose={() => setIsEditOpen(false)} target={target} />
    </Card>
  );
}
