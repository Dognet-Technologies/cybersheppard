import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { Shield, AlertTriangle, CheckCircle, XCircle, Activity } from 'lucide-react';

export default function SecurityCorrelations() {
  const [selectedCorrelation, setSelectedCorrelation] = useState<any>(null);
  const queryClient = useQueryClient();

  const { data: correlations, isLoading } = useQuery({
    queryKey: ['security-correlations'],
    queryFn: () => api.getSecurityCorrelations(),
    refetchInterval: 30000,
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: number) => api.acknowledgeCorrelation(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-correlations'] });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({ id, notes }: { id: number; notes: string }) =>
      api.resolveCorrelation(id, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-correlations'] });
      setSelectedCorrelation(null);
    },
  });

  const handleResolve = (correlation: any) => {
    const notes = prompt('Enter resolution notes:');
    if (notes) {
      resolveMutation.mutate({ id: correlation.id, notes });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Security Correlations</h1>
          <p className="text-gray-600 mt-1">
            Automated correlation between vulnerabilities and active threats
          </p>
        </div>
        <div className="flex items-center space-x-2 px-4 py-2 bg-blue-50 rounded-lg">
          <Activity className="w-5 h-5 text-blue-600" />
          <span className="text-sm font-medium text-blue-900">
            {correlations?.length || 0} Active Correlations
          </span>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <p className="text-gray-600 mt-2">Loading correlations...</p>
        </div>
      ) : correlations?.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-12 text-center">
          <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Active Correlations</h3>
          <p className="text-gray-600">
            The system has not detected any high-risk correlations between vulnerabilities and threats.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {correlations?.map((correlation: any) => (
            <CorrelationCard
              key={correlation.id}
              correlation={correlation}
              onAcknowledge={() => acknowledgeMutation.mutate(correlation.id)}
              onResolve={() => handleResolve(correlation)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function CorrelationCard({ correlation, onAcknowledge, onResolve }: any) {
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="w-5 h-5" />;
      default:
        return <Activity className="w-5 h-5" />;
    }
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleString();
  };

  return (
    <div className="bg-white rounded-lg shadow hover:shadow-lg transition-shadow border-l-4 border-red-500">
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2">
              <span className={`px-3 py-1 rounded-full text-xs font-semibold uppercase ${getRiskColor(correlation.risk_level)} border flex items-center space-x-1`}>
                {getRiskIcon(correlation.risk_level)}
                <span>{correlation.risk_level} Risk</span>
              </span>
              <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-medium">
                {correlation.correlation_type}
              </span>
            </div>
            <h3 className="text-lg font-semibold text-gray-900">
              Target: {correlation.target_hostname || `ID ${correlation.target_id}`}
            </h3>
            <p className="text-sm text-gray-600 mt-1">
              Confidence: {(correlation.correlation_confidence * 100).toFixed(0)}%
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="bg-red-50 rounded p-3">
            <p className="text-xs text-gray-600 mb-1">Vulnerability</p>
            <p className="font-semibold text-sm">{correlation.vulnerability_cve || 'N/A'}</p>
            <p className="text-xs text-gray-600">
              CVSS: {correlation.vulnerability_cvss?.toFixed(1) || 'N/A'}
            </p>
          </div>

          <div className="bg-orange-50 rounded p-3">
            <p className="text-xs text-gray-600 mb-1">Threat Source</p>
            <p className="font-semibold text-sm">{correlation.threat_source_ip || 'N/A'}</p>
            <p className="text-xs text-gray-600">
              Score: {correlation.threat_score?.toFixed(1) || 'N/A'}
            </p>
          </div>
        </div>

        <div className="bg-yellow-50 border border-yellow-200 rounded p-4 mb-4">
          <p className="text-sm font-medium text-yellow-900 mb-1">Recommended Action:</p>
          <p className="text-sm text-yellow-800">{correlation.recommended_action}</p>
        </div>

        <div className="flex items-center justify-between text-xs text-gray-500 mb-4">
          <span>Detected: {formatDate(correlation.created_at)}</span>
          <span>Status: {correlation.status}</span>
        </div>

        {correlation.status === 'new' && (
          <div className="flex space-x-2 pt-4 border-t">
            <button
              onClick={onAcknowledge}
              className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <CheckCircle className="w-4 h-4" />
              <span>Acknowledge</span>
            </button>
            <button
              onClick={onResolve}
              className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              <XCircle className="w-4 h-4" />
              <span>Resolve</span>
            </button>
          </div>
        )}

        {correlation.status === 'acknowledged' && (
          <div className="flex space-x-2 pt-4 border-t">
            <button
              onClick={onResolve}
              className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              <CheckCircle className="w-4 h-4" />
              <span>Mark as Resolved</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
