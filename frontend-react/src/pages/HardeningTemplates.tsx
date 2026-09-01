// ============================================================================
// Hardening Templates - Browse and execute YAML hardening templates
// ============================================================================

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  PlayCircle,
  FileCode,
  AlertTriangle,
  CheckCircle,
  Clock,
  Server,
  Info,
  Download,
  Eye,
  Settings,
} from 'lucide-react';
import api from '../services/api';
import { PageHeader, Card, Button, Badge, EmptyState, Select } from '../components/ui';

interface HardeningTemplate {
  id: number;
  name: string;
  version: string;
  description: string;
  framework_code: string[];
  compliance_level: string;
  target_os: string[];
  target_role: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  estimated_minutes: number;
  requires_reboot: boolean;
  risk_level: string;
  rollback_supported: boolean;
  controls_implemented: number;
  compliance_improvement: {
    nis2: string;
    nist: string;
    iso27001: string;
    mitre: string;
  };
  tags: string[];
  file_path: string;
}

export default function HardeningTemplates() {
  const [selectedTemplate, setSelectedTemplate] = useState<HardeningTemplate | null>(null);
  const [filterFramework, setFilterFramework] = useState<string>('all');
  const [filterOS, setFilterOS] = useState<string>('all');
  const [filterPriority, setFilterPriority] = useState<string>('all');
  const [showExecutionModal, setShowExecutionModal] = useState(false);

  const { data: templatesData, isLoading } = useQuery({
    queryKey: ['hardening-templates', filterFramework, filterOS, filterPriority],
    queryFn: () =>
      api.getHardeningTemplates({
        framework: filterFramework !== 'all' ? filterFramework : undefined,
        os: filterOS !== 'all' ? filterOS : undefined,
        priority: filterPriority !== 'all' ? filterPriority : undefined,
      }),
  });

  const templates: HardeningTemplate[] = templatesData?.templates || [];

  const totalControls = templates.reduce((sum, t) => sum + t.controls_implemented, 0);
  const criticalTemplates = templates.filter((t) => t.priority === 'critical').length;
  const avgExecutionTime =
    templates.reduce((sum, t) => sum + t.estimated_minutes, 0) / (templates.length || 1);

  if (isLoading) {
    return (
      <div>
        <PageHeader
          title="Hardening Templates"
          subtitle="Production-ready YAML hardening configurations"
          icon={<Shield className="w-6 h-6" />}
        />
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-blue-600"></div>
          <p className="text-gray-600 mt-4">Loading hardening templates...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Hardening Templates"
        subtitle={`${templates.length} production-ready templates covering ${totalControls} controls`}
        icon={<Shield className="w-6 h-6" />}
      />

      {/* Statistics */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Templates</p>
              <p className="text-2xl font-bold text-gray-900">{templates.length}</p>
            </div>
            <FileCode className="w-8 h-8 text-blue-500" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Controls Covered</p>
              <p className="text-2xl font-bold text-green-600">{totalControls}</p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-500" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Critical Priority</p>
              <p className="text-2xl font-bold text-red-600">{criticalTemplates}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-500" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Avg Exec Time</p>
              <p className="text-2xl font-bold text-gray-900">{Math.round(avgExecutionTime)}m</p>
            </div>
            <Clock className="w-8 h-8 text-gray-500" />
          </div>
        </Card>
      </div>

      {/* Filters */}
      <Card className="mb-6 p-4">
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Framework</label>
            <Select
              value={filterFramework}
              onChange={(e) => setFilterFramework(e.target.value)}
            >
              <option value="all">All Frameworks</option>
              <option value="nis2">NIS2</option>
              <option value="nist">NIST 800-53</option>
              <option value="iso27001">ISO 27001</option>
              <option value="mitre">MITRE D3FEND</option>
            </Select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Operating System</label>
            <Select value={filterOS} onChange={(e) => setFilterOS(e.target.value)}>
              <option value="all">All OS</option>
              <option value="debian">Debian</option>
              <option value="ubuntu">Ubuntu</option>
              <option value="rhel">RHEL</option>
              <option value="centos">CentOS</option>
              <option value="rocky">Rocky Linux</option>
              <option value="alma">Alma Linux</option>
            </Select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Priority</label>
            <Select value={filterPriority} onChange={(e) => setFilterPriority(e.target.value)}>
              <option value="all">All Priorities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </Select>
          </div>
        </div>
      </Card>

      {/* Templates Grid */}
      {templates.length === 0 ? (
        <EmptyState
          icon={<Shield className="w-12 h-12" />}
          title="No templates found"
          description="No hardening templates match your current filters"
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {templates.map((template) => (
            <TemplateCard
              key={template.id}
              template={template}
              onViewDetails={() => setSelectedTemplate(template)}
              onExecute={() => {
                setSelectedTemplate(template);
                setShowExecutionModal(true);
              }}
            />
          ))}
        </div>
      )}

      {/* Template Detail Modal */}
      {selectedTemplate && !showExecutionModal && (
        <TemplateDetailModal
          template={selectedTemplate}
          onClose={() => setSelectedTemplate(null)}
          onExecute={() => setShowExecutionModal(true)}
        />
      )}

      {/* Execution Modal */}
      {showExecutionModal && selectedTemplate && (
        <ExecutionModal
          template={selectedTemplate}
          onClose={() => {
            setShowExecutionModal(false);
            setSelectedTemplate(null);
          }}
        />
      )}
    </div>
  );
}

function TemplateCard({
  template,
  onViewDetails,
  onExecute,
}: {
  template: HardeningTemplate;
  onViewDetails: () => void;
  onExecute: () => void;
}) {
  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'text-red-600 bg-red-100';
      case 'high':
        return 'text-orange-600 bg-orange-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high':
        return 'bg-red-100 text-red-700';
      case 'medium':
        return 'bg-yellow-100 text-yellow-700';
      case 'low':
        return 'bg-green-100 text-green-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  return (
    <Card className="hover:shadow-lg transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3 flex-1">
          <div
            className={`w-12 h-12 rounded-lg flex items-center justify-center ${getPriorityColor(
              template.priority
            )}`}
          >
            <Shield className="w-6 h-6" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="font-semibold text-lg text-gray-900 truncate">{template.name}</h3>
            <p className="text-sm text-gray-500">v{template.version}</p>
          </div>
        </div>
        <Badge variant={template.priority === 'critical' ? 'danger' : 'warning'}>
          {template.priority}
        </Badge>
      </div>

      <p className="text-gray-600 text-sm mb-4 line-clamp-2">{template.description}</p>

      {/* Quick Stats */}
      <div className="grid grid-cols-3 gap-2 mb-4">
        <div className="bg-gray-50 rounded-lg p-2 text-center">
          <div className="text-xs text-gray-500">Controls</div>
          <div className="text-lg font-semibold text-gray-900">{template.controls_implemented}</div>
        </div>
        <div className="bg-gray-50 rounded-lg p-2 text-center">
          <div className="text-xs text-gray-500">Time</div>
          <div className="text-lg font-semibold text-gray-900">{template.estimated_minutes}m</div>
        </div>
        <div className="bg-gray-50 rounded-lg p-2 text-center">
          <div className="text-xs text-gray-500">Risk</div>
          <div className={`text-sm font-semibold ${getRiskColor(template.risk_level)} rounded px-1`}>
            {template.risk_level}
          </div>
        </div>
      </div>

      {/* Frameworks */}
      <div className="flex flex-wrap gap-1 mb-4">
        {template.framework_code.map((framework, idx) => (
          <Badge key={idx} variant="default" size="sm">
            {framework.toUpperCase()}
          </Badge>
        ))}
      </div>

      {/* OS Support */}
      <div className="flex items-center space-x-2 mb-4">
        <Server className="w-3 h-3 text-gray-400" />
        <div className="flex flex-wrap gap-1">
          {template.target_os.slice(0, 3).map((os, idx) => (
            <span key={idx} className="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded">
              {os}
            </span>
          ))}
          {template.target_os.length > 3 && (
            <span className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded">
              +{template.target_os.length - 3} more
            </span>
          )}
        </div>
      </div>

      {/* Compliance Improvement */}
      <div className="border-t border-gray-200 pt-4 mb-4">
        <div className="text-xs font-medium text-gray-700 mb-2">Compliance Improvement</div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="flex justify-between">
            <span className="text-gray-500">NIS2:</span>
            <span className="font-medium text-green-600">
              {template.compliance_improvement.nis2}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">NIST:</span>
            <span className="font-medium text-green-600">
              {template.compliance_improvement.nist}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">ISO:</span>
            <span className="font-medium text-green-600">
              {template.compliance_improvement.iso27001}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">MITRE:</span>
            <span className="font-medium text-green-600">
              {template.compliance_improvement.mitre}
            </span>
          </div>
        </div>
      </div>

      {/* Features */}
      <div className="flex items-center justify-between text-xs text-gray-600 mb-4">
        <div className="flex items-center space-x-1">
          {template.rollback_supported ? (
            <CheckCircle className="w-3 h-3 text-green-500" />
          ) : (
            <AlertTriangle className="w-3 h-3 text-yellow-500" />
          )}
          <span>Rollback {template.rollback_supported ? 'supported' : 'not supported'}</span>
        </div>
        {template.requires_reboot && (
          <div className="flex items-center space-x-1">
            <AlertTriangle className="w-3 h-3 text-orange-500" />
            <span>Requires reboot</span>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex space-x-2">
        <Button variant="outline" className="flex-1" size="sm" onClick={onViewDetails}>
          <Eye className="w-4 h-4 mr-1" />
          Details
        </Button>
        <Button variant="primary" className="flex-1" size="sm" onClick={onExecute}>
          <PlayCircle className="w-4 h-4 mr-1" />
          Execute
        </Button>
      </div>
    </Card>
  );
}

function TemplateDetailModal({
  template,
  onClose,
  onExecute,
}: {
  template: HardeningTemplate;
  onClose: () => void;
  onExecute: () => void;
}) {
  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-6 h-6 text-blue-600" />
            <div>
              <h2 className="text-xl font-semibold text-gray-900">{template.name}</h2>
              <p className="text-sm text-gray-500">Version {template.version}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-2">Description</h3>
            <p className="text-sm text-gray-600">{template.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Template Information</h3>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-500">Priority:</dt>
                  <dd>
                    <Badge variant={template.priority === 'critical' ? 'danger' : 'warning'}>
                      {template.priority}
                    </Badge>
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Compliance Level:</dt>
                  <dd className="font-medium">{template.compliance_level}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Risk Level:</dt>
                  <dd>
                    <Badge variant={template.risk_level === 'high' ? 'danger' : 'warning'}>
                      {template.risk_level}
                    </Badge>
                  </dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Execution Time:</dt>
                  <dd className="font-medium">{template.estimated_minutes} minutes</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Requires Reboot:</dt>
                  <dd className="font-medium">{template.requires_reboot ? 'Yes' : 'No'}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-500">Rollback Supported:</dt>
                  <dd className="font-medium">{template.rollback_supported ? 'Yes' : 'No'}</dd>
                </div>
              </dl>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Compliance Coverage</h3>
              <div className="space-y-3">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-600">Controls Implemented:</span>
                    <span className="font-semibold text-gray-900">
                      {template.controls_implemented}
                    </span>
                  </div>
                </div>
                <div className="border-t pt-3">
                  <div className="text-xs font-medium text-gray-700 mb-2">
                    Expected Improvement
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-500">NIS2:</span>
                      <span className="font-medium text-green-600">
                        {template.compliance_improvement.nis2}
                      </span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-500">NIST 800-53:</span>
                      <span className="font-medium text-green-600">
                        {template.compliance_improvement.nist}
                      </span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-500">ISO 27001:</span>
                      <span className="font-medium text-green-600">
                        {template.compliance_improvement.iso27001}
                      </span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-500">MITRE D3FEND:</span>
                      <span className="font-medium text-green-600">
                        {template.compliance_improvement.mitre}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-2">Framework Coverage</h3>
            <div className="flex flex-wrap gap-2">
              {template.framework_code.map((framework, idx) => (
                <Badge key={idx} variant="info">
                  {framework.toUpperCase()}
                </Badge>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-2">Supported Operating Systems</h3>
            <div className="flex flex-wrap gap-2">
              {template.target_os.map((os, idx) => (
                <Badge key={idx} variant="default">
                  {os}
                </Badge>
              ))}
            </div>
          </div>

          {template.tags && template.tags.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Tags</h3>
              <div className="flex flex-wrap gap-2">
                {template.tags.map((tag, idx) => (
                  <span
                    key={idx}
                    className="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded-full"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-gray-50 px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button variant="outline" icon={<Download className="w-4 h-4" />}>
            Download YAML
          </Button>
          <Button variant="primary" icon={<PlayCircle className="w-4 h-4" />} onClick={onExecute}>
            Execute Template
          </Button>
        </div>
      </div>
    </div>
  );
}

function ExecutionModal({
  template,
  onClose,
}: {
  template: HardeningTemplate;
  onClose: () => void;
}) {
  const [selectedTargets, setSelectedTargets] = useState<number[]>([]);
  const [executionMode, setExecutionMode] = useState<'dry_run' | 'apply'>('dry_run');

  const { data: targetsData } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.getTargets(),
  });

  const targets = Array.isArray(targetsData) ? targetsData : (targetsData?.targets || []);

  const handleExecute = () => {
    // TODO: Implement execution API call
    console.log('Executing template:', template.name, 'on targets:', selectedTargets);
    alert('Execution started! (Not yet implemented in backend)');
  };

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-xl max-w-2xl w-full"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Settings className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-semibold text-gray-900">Execute Hardening Template</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <Info className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <h4 className="text-sm font-medium text-blue-900 mb-1">
                  {template.name} v{template.version}
                </h4>
                <p className="text-sm text-blue-700">{template.description}</p>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Execution Mode</label>
            <div className="grid grid-cols-2 gap-4">
              <button
                className={`border-2 rounded-lg p-4 text-left transition-all ${
                  executionMode === 'dry_run'
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
                onClick={() => setExecutionMode('dry_run')}
              >
                <div className="font-medium text-gray-900 mb-1">Dry Run (Recommended)</div>
                <div className="text-sm text-gray-600">
                  Test execution without making changes. View what would be modified.
                </div>
              </button>
              <button
                className={`border-2 rounded-lg p-4 text-left transition-all ${
                  executionMode === 'apply'
                    ? 'border-red-500 bg-red-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
                onClick={() => setExecutionMode('apply')}
              >
                <div className="font-medium text-gray-900 mb-1">Apply Changes</div>
                <div className="text-sm text-gray-600">
                  Execute hardening and apply all changes. Creates automatic backups.
                </div>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Select Target Hosts
            </label>
            <div className="border border-gray-300 rounded-lg max-h-48 overflow-y-auto">
              {targets.map((target: any) => (
                <label
                  key={target.id}
                  className="flex items-center p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-200 last:border-b-0"
                >
                  <input
                    type="checkbox"
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 mr-3"
                    checked={selectedTargets.includes(target.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedTargets([...selectedTargets, target.id]);
                      } else {
                        setSelectedTargets(selectedTargets.filter((id) => id !== target.id));
                      }
                    }}
                  />
                  <div className="flex-1">
                    <div className="font-medium text-gray-900">{target.hostname}</div>
                    <div className="text-sm text-gray-500">{target.ip_address}</div>
                  </div>
                  <Badge variant={target.status === 'active' ? 'success' : 'default'}>
                    {target.status}
                  </Badge>
                </label>
              ))}
            </div>
          </div>

          {executionMode === 'apply' && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h4 className="text-sm font-medium text-yellow-900 mb-1">Warning</h4>
                  <ul className="text-sm text-yellow-700 space-y-1 list-disc list-inside">
                    <li>This will apply real changes to the selected hosts</li>
                    <li>Automatic backups will be created before modifications</li>
                    <li>Rollback is available if issues occur</li>
                    {template.requires_reboot && <li>System reboot will be required</li>}
                    <li>Estimated execution time: {template.estimated_minutes} minutes per host</li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="bg-gray-50 px-6 py-4 border-t border-gray-200 flex justify-between items-center">
          <div className="text-sm text-gray-600">
            {selectedTargets.length} {selectedTargets.length === 1 ? 'target' : 'targets'} selected
          </div>
          <div className="flex space-x-3">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant={executionMode === 'dry_run' ? 'primary' : 'danger'}
              icon={<PlayCircle className="w-4 h-4" />}
              onClick={handleExecute}
              disabled={selectedTargets.length === 0}
            >
              {executionMode === 'dry_run' ? 'Run Dry Run' : 'Execute Hardening'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
