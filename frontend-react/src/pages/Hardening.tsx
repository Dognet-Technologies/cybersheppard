// ============================================================================
// Hardening Page - Apply security hardening models to targets
// ============================================================================

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Shield, CheckCircle, AlertCircle, Info, PlayCircle } from 'lucide-react';
import ApplyHardeningModal from '../components/ApplyHardeningModal';
import { PageHeader, Card, EmptyState, Button, Badge } from '../components/ui';

export default function Hardening() {
  const [selectedModel, setSelectedModel] = useState<any>(null);
  const [isApplyModalOpen, setIsApplyModalOpen] = useState(false);

  const { data: modelsData, isLoading } = useQuery({
    queryKey: ['hardening-models'],
    queryFn: () => api.getHardeningModels(),
  });

  const handleApplyClick = (model: any) => {
    setSelectedModel(model);
    setIsApplyModalOpen(true);
  };

  const models = modelsData?.models || [];

  if (isLoading) {
    return (
      <div>
        <PageHeader
          title="Hardening Models"
          subtitle="Security configuration management"
          icon={<Shield className="w-6 h-6" />}
        />
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-blue-600"></div>
          <p className="text-gray-600 mt-4">Loading hardening models...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Hardening Models"
        subtitle={`${models.length} hardening ${models.length !== 1 ? 'models' : 'model'} available`}
        icon={<Shield className="w-6 h-6" />}
      />

      {models.length === 0 ? (
        <EmptyState
          icon={<Shield className="w-8 h-8" />}
          title="No hardening models found"
          description="Check the hardening models directory on the server to add security configuration templates"
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {models.map((model: any, index: number) => (
            <ModelCard key={index} model={model} onApplyClick={handleApplyClick} />
          ))}
        </div>
      )}

      <ApplyHardeningModal
        isOpen={isApplyModalOpen}
        onClose={() => setIsApplyModalOpen(false)}
        model={selectedModel}
      />
    </div>
  );
}

function ModelCard({ model, onApplyClick }: any) {
  const [showDetails, setShowDetails] = useState(false);

  const getModelTypeBadge = (path: string) => {
    if (path.includes('base')) return { variant: 'info' as const, label: 'Base' };
    if (path.includes('advanced')) return { variant: 'warning' as const, label: 'Advanced' };
    if (path.includes('custom')) return { variant: 'success' as const, label: 'Custom' };
    return { variant: 'default' as const, label: 'Standard' };
  };

  const badgeInfo = getModelTypeBadge(model.path);

  return (
    <Card hover className="h-full">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3 flex-1">
          <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
            <Shield className="w-6 h-6 text-blue-600" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="font-semibold text-lg text-gray-900 truncate">{model.name}</h3>
            <p className="text-sm text-gray-500 truncate">{model.path}</p>
          </div>
        </div>
        <Badge variant={badgeInfo.variant}>{badgeInfo.label}</Badge>
      </div>

      <p className="text-gray-600 text-sm mb-4 line-clamp-2">{model.description}</p>

      <div className="flex items-center justify-between text-sm mb-4">
        <div className="flex items-center space-x-4">
          <div className="flex items-center text-gray-600">
            <CheckCircle className="w-4 h-4 mr-1" />
            <span>v{model.version}</span>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          icon={<Info className="w-4 h-4" />}
          onClick={() => setShowDetails(!showDetails)}
        >
          {showDetails ? 'Hide' : 'Show'} Details
        </Button>
      </div>

      {showDetails && (
        <div className="border-t border-gray-200 pt-4 mb-4 space-y-3">
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">OS Compatibility</h4>
            <div className="flex flex-wrap gap-2">
              {model.os_compatibility?.map((os: string, idx: number) => (
                <Badge key={idx} variant="default">
                  {os}
                </Badge>
              )) || <span className="text-sm text-gray-500">No OS compatibility info</span>}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 text-center">
            <div className="bg-gray-50 rounded p-2">
              <div className="text-xs text-gray-500">Files</div>
              <div className="text-lg font-semibold text-gray-900">{model.files_count || 0}</div>
            </div>
            <div className="bg-gray-50 rounded p-2">
              <div className="text-xs text-gray-500">Packages</div>
              <div className="text-lg font-semibold text-gray-900">{model.packages_count || 0}</div>
            </div>
            <div className="bg-gray-50 rounded p-2">
              <div className="text-xs text-gray-500">Services</div>
              <div className="text-lg font-semibold text-gray-900">{model.services_count || 0}</div>
            </div>
          </div>
        </div>
      )}

      <Button
        variant="primary"
        className="w-full mb-4"
        icon={<PlayCircle className="w-4 h-4" />}
        onClick={() => onApplyClick(model)}
      >
        Apply to Target
      </Button>

      <div className="bg-gray-50 -mx-6 -mb-6 px-6 py-3 rounded-b-lg border-t border-gray-200">
        <div className="flex items-center justify-between text-xs text-gray-600">
          <div className="flex items-center space-x-1">
            <AlertCircle className="w-3 h-3" />
            <span>Creates backup before applying</span>
          </div>
          <div className="flex items-center space-x-1">
            <CheckCircle className="w-3 h-3 text-green-500" />
            <span>Rollback supported</span>
          </div>
        </div>
      </div>
    </Card>
  );
}
