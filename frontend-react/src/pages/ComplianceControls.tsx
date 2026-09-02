// ============================================================================
// Compliance Controls Browser - Navigate and search 113 compliance controls
// ============================================================================

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Shield,
  Search,
  Filter,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  FileText,
  Server,
  Info,
  ArrowLeft,
} from 'lucide-react';
import api from '../services/api';
import { PageHeader, Card, Button, Badge, Input, Select } from '../components/ui';

interface ComplianceControl {
  id: number;
  macroarea_id: number;
  macroarea_name: string;
  sub_control: string;
  sub_sub_control: string;
  requirement: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  implementation_complexity: string;
  implementation_notes: string;
  nis2_references: string[];
  nist_references: string[];
  iso_references: string[];
  mitre_references: string[];
  applies_to_nis2: boolean;
  applies_to_nist: boolean;
  applies_to_iso: boolean;
  applies_to_mitre: boolean;
  supports_debian_ubuntu: boolean;
  supports_rhel_oracle: boolean;
  supports_sles: boolean;
  supports_windows_2019: boolean;
  supports_windows_2022: boolean;
  supports_docker: boolean;
  supports_lxc: boolean;
}

interface Macroarea {
  id: number;
  name: string;
  description: string;
  controls_count: number;
}

export default function ComplianceControls() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFramework, setSelectedFramework] = useState<string>('all');
  const [selectedPriority, setSelectedPriority] = useState<string>('all');
  const [selectedOS, setSelectedOS] = useState<string>('all');
  const [expandedMacroareas, setExpandedMacroareas] = useState<Set<number>>(new Set());
  const [selectedControl, setSelectedControl] = useState<ComplianceControl | null>(null);

  const { data: macroareasData, isLoading: macroareasLoading } = useQuery({
    queryKey: ['compliance-macroareas'],
    queryFn: () => api.getComplianceMacroareas(),
  });

  const { data: controlsData, isLoading: controlsLoading } = useQuery({
    queryKey: ['compliance-controls', selectedFramework, selectedPriority, selectedOS],
    queryFn: () =>
      api.getComplianceControls({
        framework: selectedFramework !== 'all' ? selectedFramework : undefined,
        priority: selectedPriority !== 'all' ? selectedPriority : undefined,
        os: selectedOS !== 'all' ? selectedOS : undefined,
      }),
  });

  const macroareas: Macroarea[] = macroareasData?.macroareas || [];
  const controls: ComplianceControl[] = controlsData?.controls || [];

  const toggleMacroarea = (id: number) => {
    const newExpanded = new Set(expandedMacroareas);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedMacroareas(newExpanded);
  };

  const expandAll = () => {
    setExpandedMacroareas(new Set(macroareas.map((m) => m.id)));
  };

  const collapseAll = () => {
    setExpandedMacroareas(new Set());
  };

  // Filter controls by search query
  const filteredControls = controls.filter((control) => {
    const searchLower = searchQuery.toLowerCase();
    return (
      control.requirement.toLowerCase().includes(searchLower) ||
      control.sub_control?.toLowerCase().includes(searchLower) ||
      control.macroarea_name.toLowerCase().includes(searchLower) ||
      control.implementation_notes?.toLowerCase().includes(searchLower)
    );
  });

  // Group controls by macroarea
  const controlsByMacroarea = macroareas.map((macroarea) => ({
    ...macroarea,
    controls: filteredControls.filter((c) => c.macroarea_id === macroarea.id),
  }));

  const totalControls = filteredControls.length;
  const criticalControls = filteredControls.filter((c) => c.priority === 'Critical').length;
  const highControls = filteredControls.filter((c) => c.priority === 'High').length;

  if (macroareasLoading || controlsLoading) {
    return (
      <div>
        <PageHeader
          title="Compliance Controls"
          subtitle="Browse and search 113 compliance controls"
          icon={<Shield className="w-6 h-6" />}
        />
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-blue-600"></div>
          <p className="text-gray-600 mt-4">Loading compliance controls...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <Link
        to="/compliance"
        className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 mb-3"
      >
        <ArrowLeft className="w-4 h-4" />
        Torna a Compliance
      </Link>
      <PageHeader
        title="Compliance Controls"
        subtitle={`${totalControls} controls across 12 macroareas`}
        icon={<Shield className="w-6 h-6" />}
        actions={
          <div className="flex space-x-2">
            <Button variant="outline" size="sm" onClick={expandAll}>
              Expand All
            </Button>
            <Button variant="outline" size="sm" onClick={collapseAll}>
              Collapse All
            </Button>
            <Button variant="primary" size="sm" icon={<FileText className="w-4 h-4" />}>
              Export
            </Button>
          </div>
        }
      />

      {/* Statistics */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Controls</p>
              <p className="text-2xl font-bold text-gray-900">{totalControls}</p>
            </div>
            <Shield className="w-8 h-8 text-blue-500" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Critical Priority</p>
              <p className="text-2xl font-bold text-red-600">{criticalControls}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-500" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">High Priority</p>
              <p className="text-2xl font-bold text-orange-600">{highControls}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-orange-500" />
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Macroareas</p>
              <p className="text-2xl font-bold text-gray-900">{macroareas.length}</p>
            </div>
            <Filter className="w-8 h-8 text-gray-500" />
          </div>
        </Card>
      </div>

      {/* Filters */}
      <Card className="mb-6 p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Search</label>
            <Input
              type="text"
              placeholder="Search controls..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              icon={<Search className="w-4 h-4" />}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Framework</label>
            <Select
              value={selectedFramework}
              onChange={(e) => setSelectedFramework(e.target.value)}
            >
              <option value="all">All Frameworks</option>
              <option value="nis2">NIS2 Directive 2022/2555</option>
              <option value="nist">NIST 800-53 Rev5</option>
              <option value="iso27001">ISO 27001:2022</option>
              <option value="mitre">MITRE D3FEND</option>
            </Select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Priority</label>
            <Select
              value={selectedPriority}
              onChange={(e) => setSelectedPriority(e.target.value)}
            >
              <option value="all">All Priorities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </Select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Operating System</label>
            <Select value={selectedOS} onChange={(e) => setSelectedOS(e.target.value)}>
              <option value="all">All OS</option>
              <option value="debian_ubuntu">Debian/Ubuntu</option>
              <option value="rhel_oracle">RHEL/Oracle</option>
              <option value="sles">SLES</option>
              <option value="windows_2019">Windows 2019</option>
              <option value="windows_2022">Windows 2022</option>
              <option value="docker">Docker</option>
              <option value="lxc">LXC</option>
            </Select>
          </div>
        </div>
      </Card>

      {/* Controls by Macroarea */}
      <div className="space-y-4">
        {controlsByMacroarea.map((macroarea) => (
          <Card key={macroarea.id} className="overflow-hidden">
            <div
              className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50 transition-colors"
              onClick={() => toggleMacroarea(macroarea.id)}
            >
              <div className="flex items-center space-x-3">
                {expandedMacroareas.has(macroarea.id) ? (
                  <ChevronDown className="w-5 h-5 text-gray-400" />
                ) : (
                  <ChevronRight className="w-5 h-5 text-gray-400" />
                )}
                <Shield className="w-5 h-5 text-blue-600" />
                <div>
                  <h3 className="font-semibold text-gray-900">{macroarea.name}</h3>
                  <p className="text-sm text-gray-500">{macroarea.description}</p>
                </div>
              </div>
              <Badge variant="info">{macroarea.controls.length} controls</Badge>
            </div>

            {expandedMacroareas.has(macroarea.id) && (
              <div className="border-t border-gray-200">
                {macroarea.controls.length === 0 ? (
                  <div className="p-8 text-center">
                    <Info className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                    <p className="text-gray-500">
                      No controls match the current filters for this macroarea
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-gray-200">
                    {macroarea.controls.map((control) => (
                      <div
                        key={control.id}
                        className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
                        onClick={() => setSelectedControl(control)}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-1">
                              {control.sub_control && (
                                <span className="text-xs font-medium text-gray-500 uppercase">
                                  {control.sub_control}
                                  {control.sub_sub_control && ` > ${control.sub_sub_control}`}
                                </span>
                              )}
                            </div>
                            <p className="text-sm font-medium text-gray-900 mb-2">
                              {control.requirement}
                            </p>
                            {control.implementation_notes && (
                              <p className="text-xs text-gray-600 line-clamp-2">
                                {control.implementation_notes}
                              </p>
                            )}
                          </div>
                          <div className="ml-4 flex flex-col items-end space-y-2">
                            <Badge
                              variant={
                                control.priority === 'Critical'
                                  ? 'danger'
                                  : control.priority === 'High'
                                  ? 'warning'
                                  : control.priority === 'Medium'
                                  ? 'info'
                                  : 'default'
                              }
                            >
                              {control.priority}
                            </Badge>
                            {control.implementation_complexity && (
                              <span className="text-xs text-gray-500">
                                {control.implementation_complexity}
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Framework References */}
                        <div className="flex flex-wrap gap-2 mt-3">
                          {control.applies_to_nis2 && (
                            <Badge variant="default" size="sm">
                              NIS2: {(control.nis2_references || []).join(', ')}
                            </Badge>
                          )}
                          {control.applies_to_nist && (
                            <Badge variant="default" size="sm">
                              NIST: {(control.nist_references || []).join(', ')}
                            </Badge>
                          )}
                          {control.applies_to_iso && (
                            <Badge variant="default" size="sm">
                              ISO: {(control.iso_references || []).join(', ')}
                            </Badge>
                          )}
                          {control.applies_to_mitre && (
                            <Badge variant="default" size="sm">
                              MITRE: {(control.mitre_references || []).join(', ')}
                            </Badge>
                          )}
                        </div>

                        {/* OS Support */}
                        <div className="flex items-center space-x-2 mt-3">
                          <Server className="w-3 h-3 text-gray-400" />
                          <div className="flex flex-wrap gap-1">
                            {control.supports_debian_ubuntu && (
                              <span className="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded">
                                Debian/Ubuntu
                              </span>
                            )}
                            {control.supports_rhel_oracle && (
                              <span className="text-xs px-2 py-0.5 bg-red-100 text-red-700 rounded">
                                RHEL/Oracle
                              </span>
                            )}
                            {control.supports_sles && (
                              <span className="text-xs px-2 py-0.5 bg-green-100 text-green-700 rounded">
                                SLES
                              </span>
                            )}
                            {control.supports_windows_2019 && (
                              <span className="text-xs px-2 py-0.5 bg-blue-100 text-blue-700 rounded">
                                Win2019
                              </span>
                            )}
                            {control.supports_windows_2022 && (
                              <span className="text-xs px-2 py-0.5 bg-blue-100 text-blue-700 rounded">
                                Win2022
                              </span>
                            )}
                            {control.supports_docker && (
                              <span className="text-xs px-2 py-0.5 bg-cyan-100 text-cyan-700 rounded">
                                Docker
                              </span>
                            )}
                            {control.supports_lxc && (
                              <span className="text-xs px-2 py-0.5 bg-cyan-100 text-cyan-700 rounded">
                                LXC
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </Card>
        ))}
      </div>

      {/* Control Detail Modal */}
      {selectedControl && (
        <ControlDetailModal control={selectedControl} onClose={() => setSelectedControl(null)} />
      )}
    </div>
  );
}

function ControlDetailModal({
  control,
  onClose,
}: {
  control: ComplianceControl;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-6 h-6 text-blue-600" />
            <h2 className="text-xl font-semibold text-gray-900">Control Details</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <XCircle className="w-6 h-6" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Header */}
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Badge
                variant={
                  control.priority === 'Critical'
                    ? 'danger'
                    : control.priority === 'High'
                    ? 'warning'
                    : 'info'
                }
              >
                {control.priority}
              </Badge>
              {control.sub_control && (
                <span className="text-sm text-gray-500">
                  {control.sub_control}
                  {control.sub_sub_control && ` > ${control.sub_sub_control}`}
                </span>
              )}
            </div>
            <h3 className="text-lg font-semibold text-gray-900 mb-2">{control.requirement}</h3>
            <p className="text-sm text-gray-600">{control.macroarea_name}</p>
          </div>

          {/* Implementation Notes */}
          {control.implementation_notes && (
            <div>
              <h4 className="text-sm font-semibold text-gray-700 mb-2">Implementation Notes</h4>
              <p className="text-sm text-gray-600">{control.implementation_notes}</p>
              {control.implementation_complexity && (
                <p className="text-sm text-gray-500 mt-2">
                  Complexity: {control.implementation_complexity}
                </p>
              )}
            </div>
          )}

          {/* Framework References */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-3">Framework References</h4>
            <div className="grid grid-cols-2 gap-4">
              {control.applies_to_nis2 && (
                <div className="border border-gray-200 rounded-lg p-3">
                  <div className="font-medium text-sm text-gray-900 mb-1">NIS2 Directive</div>
                  <div className="flex flex-wrap gap-1">
                    {(control.nis2_references || []).map((ref, idx) => (
                      <Badge key={idx} variant="default" size="sm">
                        {ref}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {control.applies_to_nist && (
                <div className="border border-gray-200 rounded-lg p-3">
                  <div className="font-medium text-sm text-gray-900 mb-1">NIST 800-53 Rev5</div>
                  <div className="flex flex-wrap gap-1">
                    {(control.nist_references || []).map((ref, idx) => (
                      <Badge key={idx} variant="default" size="sm">
                        {ref}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {control.applies_to_iso && (
                <div className="border border-gray-200 rounded-lg p-3">
                  <div className="font-medium text-sm text-gray-900 mb-1">ISO 27001:2022</div>
                  <div className="flex flex-wrap gap-1">
                    {(control.iso_references || []).map((ref, idx) => (
                      <Badge key={idx} variant="default" size="sm">
                        {ref}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {control.applies_to_mitre && (
                <div className="border border-gray-200 rounded-lg p-3">
                  <div className="font-medium text-sm text-gray-900 mb-1">MITRE D3FEND</div>
                  <div className="flex flex-wrap gap-1">
                    {(control.mitre_references || []).map((ref, idx) => (
                      <Badge key={idx} variant="default" size="sm">
                        {ref}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* OS Support */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 mb-3">Operating System Support</h4>
            <div className="flex flex-wrap gap-2">
              {control.supports_debian_ubuntu && (
                <Badge variant="success">Debian/Ubuntu</Badge>
              )}
              {control.supports_rhel_oracle && <Badge variant="success">RHEL/Oracle</Badge>}
              {control.supports_sles && <Badge variant="success">SLES</Badge>}
              {control.supports_windows_2019 && <Badge variant="success">Windows 2019</Badge>}
              {control.supports_windows_2022 && <Badge variant="success">Windows 2022</Badge>}
              {control.supports_docker && <Badge variant="success">Docker</Badge>}
              {control.supports_lxc && <Badge variant="success">LXC</Badge>}
            </div>
          </div>
        </div>

        <div className="sticky bottom-0 bg-gray-50 px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button variant="primary" icon={<CheckCircle className="w-4 h-4" />}>
            View Implementation
          </Button>
        </div>
      </div>
    </div>
  );
}
