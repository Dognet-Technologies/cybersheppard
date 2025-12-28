import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { Shield, CheckCircle, AlertCircle, Info, PlayCircle } from 'lucide-react';
import ApplyHardeningModal from '../components/ApplyHardeningModal';

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

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Hardening Models</h1>
          <p className="text-gray-600 mt-1">
            {models.length} hardening {models.length !== 1 ? 'models' : 'model'} available
          </p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-600">
          <Shield className="w-5 h-5 text-blue-600" />
          <span>Security Configuration Management</span>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <p className="text-gray-600 mt-2">Loading hardening models...</p>
        </div>
      ) : models.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-12 text-center">
          <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No hardening models found</h3>
          <p className="text-gray-600">Check the hardening models directory on the server</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {models.map((model: any, index: number) => (
            <ModelCard
              key={index}
              model={model}
              onApplyClick={handleApplyClick}
            />
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

  const getModelTypeColor = (path: string) => {
    if (path.includes('base')) return 'bg-blue-100 text-blue-800';
    if (path.includes('advanced')) return 'bg-purple-100 text-purple-800';
    if (path.includes('custom')) return 'bg-green-100 text-green-800';
    return 'bg-gray-100 text-gray-800';
  };

  const getModelTypeLabel = (path: string) => {
    if (path.includes('base')) return 'Base';
    if (path.includes('advanced')) return 'Advanced';
    if (path.includes('custom')) return 'Custom';
    return 'Standard';
  };

  return (
    <div className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow">
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center space-x-3 flex-1">
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
              <Shield className="w-6 h-6 text-blue-600" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-lg truncate">{model.name}</h3>
              <p className="text-sm text-gray-500 truncate">{model.path}</p>
            </div>
          </div>
          <span className={`px-2 py-1 rounded text-xs font-medium ${getModelTypeColor(model.path)}`}>
            {getModelTypeLabel(model.path)}
          </span>
        </div>

        <p className="text-gray-600 text-sm mb-4 line-clamp-2">
          {model.description}
        </p>

        <div className="flex items-center justify-between text-sm mb-4">
          <div className="flex items-center space-x-4">
            <div className="flex items-center text-gray-600">
              <CheckCircle className="w-4 h-4 mr-1" />
              <span>v{model.version}</span>
            </div>
          </div>
          <button
            onClick={() => setShowDetails(!showDetails)}
            className="text-blue-600 hover:text-blue-700 flex items-center space-x-1"
          >
            <Info className="w-4 h-4" />
            <span>{showDetails ? 'Hide' : 'Show'} Details</span>
          </button>
        </div>

        {showDetails && (
          <div className="border-t pt-4 mb-4 space-y-3">
            <div>
              <h4 className="text-sm font-medium text-gray-700 mb-2">OS Compatibility</h4>
              <div className="flex flex-wrap gap-2">
                {model.os_compatibility?.map((os: string, idx: number) => (
                  <span
                    key={idx}
                    className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs"
                  >
                    {os}
                  </span>
                )) || (
                  <span className="text-sm text-gray-500">No OS compatibility info</span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4 text-center">
              <div className="bg-gray-50 rounded p-2">
                <div className="text-xs text-gray-500">Files</div>
                <div className="text-lg font-semibold">{model.files_count || 0}</div>
              </div>
              <div className="bg-gray-50 rounded p-2">
                <div className="text-xs text-gray-500">Packages</div>
                <div className="text-lg font-semibold">{model.packages_count || 0}</div>
              </div>
              <div className="bg-gray-50 rounded p-2">
                <div className="text-xs text-gray-500">Services</div>
                <div className="text-lg font-semibold">{model.services_count || 0}</div>
              </div>
            </div>
          </div>
        )}

        <div className="flex items-center space-x-2">
          <button
            onClick={() => onApplyClick(model)}
            className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <PlayCircle className="w-4 h-4" />
            <span>Apply to Target</span>
          </button>
        </div>
      </div>

      <div className="bg-gray-50 px-6 py-3 rounded-b-lg border-t">
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
    </div>
  );
}
