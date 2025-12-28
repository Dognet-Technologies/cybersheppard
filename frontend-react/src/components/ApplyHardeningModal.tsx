import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { X, Shield, Server, CheckCircle, XCircle, Loader, AlertTriangle } from 'lucide-react';

interface ApplyHardeningModalProps {
  isOpen: boolean;
  onClose: () => void;
  model: any;
}

export default function ApplyHardeningModal({ isOpen, onClose, model }: ApplyHardeningModalProps) {
  const queryClient = useQueryClient();
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);
  const [applicationResult, setApplicationResult] = useState<any>(null);
  const [error, setError] = useState('');

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
    enabled: isOpen,
  });

  const applyMutation = useMutation({
    mutationFn: ({ targetId, modelPath }: { targetId: number; modelPath: string }) =>
      api.applyHardeningToTarget(targetId, modelPath),
    onSuccess: (data) => {
      setApplicationResult(data);
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      queryClient.invalidateQueries({ queryKey: ['hardening-applications'] });
    },
    onError: (err: any) => {
      setError(err.response?.data?.error || 'Failed to apply hardening model');
      setApplicationResult(null);
    },
  });

  const handleApply = () => {
    if (!selectedTargetId || !model) {
      setError('Please select a target system');
      return;
    }

    setError('');
    setApplicationResult(null);
    applyMutation.mutate({
      targetId: selectedTargetId,
      modelPath: model.path,
    });
  };

  const handleClose = () => {
    setSelectedTargetId(null);
    setApplicationResult(null);
    setError('');
    onClose();
  };

  if (!isOpen) return null;

  const onlineTargets = targets?.filter((t: any) => t.status === 'online') || [];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b p-6 z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <h2 className="text-2xl font-bold">Apply Hardening Model</h2>
                <p className="text-sm text-gray-500">{model?.name}</p>
              </div>
            </div>
            <button
              onClick={handleClose}
              className="text-gray-500 hover:text-gray-700"
              disabled={applyMutation.isPending}
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Model Info */}
          {model && (
            <div className="bg-gray-50 rounded-lg p-4">
              <h3 className="font-medium text-gray-900 mb-2">Model Details</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Version:</span>
                  <span className="font-medium">{model.version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Path:</span>
                  <span className="font-mono text-xs">{model.path}</span>
                </div>
                <div>
                  <span className="text-gray-600">Description:</span>
                  <p className="text-gray-900 mt-1">{model.description}</p>
                </div>
              </div>
            </div>
          )}

          {/* Target Selection */}
          {!applicationResult && !applyMutation.isPending && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Select Target System *
              </label>
              {onlineTargets.length === 0 ? (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 text-center">
                  <AlertTriangle className="w-8 h-8 text-yellow-600 mx-auto mb-2" />
                  <p className="text-sm text-yellow-800">No online targets available</p>
                  <p className="text-xs text-yellow-700 mt-1">
                    Targets must be online to apply hardening
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3">
                  {onlineTargets.map((target: any) => (
                    <div
                      key={target.id}
                      onClick={() => setSelectedTargetId(target.id)}
                      className={`border rounded-lg p-4 cursor-pointer transition-all ${
                        selectedTargetId === target.id
                          ? 'border-blue-500 bg-blue-50 ring-2 ring-blue-200'
                          : 'border-gray-200 hover:border-blue-300 hover:bg-gray-50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <Server className="w-5 h-5 text-gray-600" />
                          <div>
                            <p className="font-medium">{target.hostname}</p>
                            <p className="text-sm text-gray-500">{target.ip_address}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-medium">
                            {target.environment}
                          </span>
                          {selectedTargetId === target.id && (
                            <CheckCircle className="w-5 h-5 text-blue-600" />
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Progress Indicator */}
          {applyMutation.isPending && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 text-center">
              <Loader className="w-12 h-12 text-blue-600 mx-auto mb-4 animate-spin" />
              <h3 className="text-lg font-semibold text-blue-900 mb-2">
                Applying Hardening Model
              </h3>
              <p className="text-sm text-blue-700">
                This may take several minutes. Please do not close this window.
              </p>
              <div className="mt-4 space-y-2 text-sm text-left bg-white rounded p-4">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse"></div>
                  <span>Validating model...</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse"></div>
                  <span>Connecting to target...</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse"></div>
                  <span>Creating backup...</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse"></div>
                  <span>Deploying configurations...</span>
                </div>
              </div>
            </div>
          )}

          {/* Success Result */}
          {applicationResult && applicationResult.success && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-6">
              <div className="flex items-center space-x-3 mb-4">
                <CheckCircle className="w-8 h-8 text-green-600" />
                <div>
                  <h3 className="text-lg font-semibold text-green-900">
                    Hardening Applied Successfully
                  </h3>
                  <p className="text-sm text-green-700">
                    Model applied in {applicationResult.duration_seconds?.toFixed(2)}s
                  </p>
                </div>
              </div>

              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="bg-white rounded p-3">
                    <div className="text-gray-600">Steps Completed</div>
                    <div className="text-2xl font-bold text-green-600">
                      {applicationResult.steps_completed}
                    </div>
                  </div>
                  <div className="bg-white rounded p-3">
                    <div className="text-gray-600">Backup Created</div>
                    <div className="text-sm font-medium text-gray-900 truncate">
                      {applicationResult.backup_path ? '✓ Yes' : '✗ No'}
                    </div>
                  </div>
                </div>

                {applicationResult.log && applicationResult.log.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 mb-2">Execution Log</h4>
                    <div className="bg-white rounded p-3 max-h-40 overflow-y-auto">
                      <pre className="text-xs font-mono text-gray-800 whitespace-pre-wrap">
                        {applicationResult.log.join('\n')}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Error Result */}
          {applicationResult && !applicationResult.success && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-6">
              <div className="flex items-center space-x-3 mb-4">
                <XCircle className="w-8 h-8 text-red-600" />
                <div>
                  <h3 className="text-lg font-semibold text-red-900">
                    Hardening Failed
                  </h3>
                  <p className="text-sm text-red-700">
                    {applicationResult.error || 'An error occurred during hardening'}
                  </p>
                </div>
              </div>

              {applicationResult.log && applicationResult.log.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-gray-700 mb-2">Execution Log</h4>
                  <div className="bg-white rounded p-3 max-h-40 overflow-y-auto">
                    <pre className="text-xs font-mono text-gray-800 whitespace-pre-wrap">
                      {applicationResult.log.join('\n')}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-gray-50 px-6 py-4 border-t flex justify-end space-x-3">
          {applicationResult ? (
            <button
              onClick={handleClose}
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
            >
              Close
            </button>
          ) : (
            <>
              <button
                onClick={handleClose}
                disabled={applyMutation.isPending}
                className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleApply}
                disabled={applyMutation.isPending || !selectedTargetId || onlineTargets.length === 0}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
              >
                {applyMutation.isPending ? (
                  <>
                    <Loader className="w-4 h-4 animate-spin" />
                    <span>Applying...</span>
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4" />
                    <span>Apply Hardening</span>
                  </>
                )}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
