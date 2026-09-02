// ============================================================================
// Correlazioni — vista "Lista". Rilevamento pattern d'attacco e correlazione
// eventi con mappatura MITRE ATT&CK/D3FEND. Sotto-vista "Lista" della scheda
// Correlazioni dell'hub Threat Detection (il toggle Lista/Matrice sta in
// CorrelationsTab).
// ============================================================================

import { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { AlertTriangle, CheckCircle, Activity, Cpu, X } from 'lucide-react';
import { format } from 'date-fns';
import {
  Table,
  Button,
  Badge,
  StatsGrid,
  StatCard,
  EmptyState,
  Select,
} from '../components/ui';

// Un evento proviene dal sensore eBPF (kernel) o dal canale auditd/Laurel?
function sensorOf(row: any): 'ebpf' | 'auditd' {
  return row?.correlation_data?.sensor === 'ebpf' ? 'ebpf' : 'auditd';
}

const TACTIC_OPTIONS = [
  'initial_access', 'execution', 'persistence', 'privilege_escalation',
  'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
  'command_and_control', 'exfiltration', 'impact',
];

export default function CorrelationsList() {
  const [, setSelectedCorrelation] = useState<any>(null);
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  // Filtri (tattica inizializzata da URL, es. click dalla matrice ATT&CK)
  const [tactic, setTactic] = useState<string>(searchParams.get('tactic') || 'all');
  const [severity, setSeverity] = useState<string>('all');
  const [sensor, setSensor] = useState<string>('all');
  const technique = searchParams.get('technique') || '';

  // Fetch correlations using new API
  const { data: response, isLoading } = useQuery({
    queryKey: ['security-correlations'],
    queryFn: () => api.getSecurityCorrelations({ hours: 24, limit: 200 }),
    refetchInterval: 30000,
  });

  // Extract data from API response
  const allCorrelations = response?.data || [];

  // Applica i filtri lato client
  const correlations = useMemo(() => {
    return allCorrelations.filter((c: any) => {
      if (tactic !== 'all' && c.attack_stage !== tactic) return false;
      if (severity !== 'all' && c.severity !== severity) return false;
      if (sensor !== 'all' && sensorOf(c) !== sensor) return false;
      if (technique && c.correlation_data?.mitre_technique !== technique) return false;
      return true;
    });
  }, [allCorrelations, tactic, severity, sensor, technique]);

  const clearTechnique = () => {
    const p = new URLSearchParams(searchParams);
    p.delete('technique');
    setSearchParams(p, { replace: true });
  };

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

  // Calculate statistics (adapted to new EventCorrelation model)
  const stats = {
    total: correlations?.length || 0,
    critical: correlations?.filter((c: any) => c.severity === 'critical').length || 0,
    high: correlations?.filter((c: any) => c.severity === 'high').length || 0,
    active: correlations?.filter((c: any) => c.status === 'active').length || 0,
  };

  const columns = [
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      render: (row: any) => {
        const variants: Record<string, 'danger' | 'warning' | 'info' | 'default'> = {
          critical: 'danger',
          high: 'warning',
          medium: 'info',
          low: 'default',
        };
        return (
          <Badge variant={variants[row.severity] || 'default'}>
            {row.severity?.toUpperCase() || 'UNKNOWN'}
          </Badge>
        );
      },
    },
    {
      key: 'pattern',
      label: 'Attack Pattern',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-gray-900">
            {row.pattern_name || row.correlation_type?.replace('_', ' ').toUpperCase()}
          </div>
          <div className="text-sm text-gray-500">
            {row.correlation_type?.replace(/_/g, ' ') || ''}
          </div>
        </div>
      ),
    },
    {
      key: 'mitre',
      label: 'MITRE',
      render: (row: any) => {
        const rowTactic: string | undefined = row.attack_stage;
        const rowTechnique: string | undefined = row.correlation_data?.mitre_technique;
        const techName: string | undefined = row.correlation_data?.mitre_technique_name;
        const d3fend: string | undefined = row.correlation_data?.mitigating_d3fend;
        return (
          <div className="flex flex-col gap-1">
            {rowTactic ? (
              <span
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 border border-red-200"
                title="MITRE ATT&CK tactic"
              >
                ATT&amp;CK: {rowTactic.replace(/_/g, ' ')}
              </span>
            ) : (
              <span className="text-xs text-gray-400">—</span>
            )}
            {rowTechnique && (
              <span
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-50 text-orange-700 border border-orange-200"
                title={techName || 'MITRE ATT&CK technique'}
              >
                {rowTechnique}
                {techName ? ` · ${techName}` : ''}
              </span>
            )}
            {d3fend && (
              <span
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-50 text-green-700 border border-green-200"
                title="MITRE D3FEND — controllo difensivo mitigante"
              >
                D3FEND: {d3fend}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'sensor',
      label: 'Sensor',
      render: (row: any) => {
        const s = sensorOf(row);
        return s === 'ebpf' ? (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-violet-50 text-violet-700 border border-violet-200"
            title="Rilevato dal sensore eBPF (kernel) — resistente a evasione io_uring/auid"
          >
            <Cpu className="w-3 h-3" /> eBPF
          </span>
        ) : (
          <span
            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-50 text-slate-600 border border-slate-200"
            title="Canale auditd / Laurel"
          >
            auditd
          </span>
        );
      },
    },
    {
      key: 'entities',
      label: 'Involved Entities',
      render: (row: any) => (
        <div>
          <div className="font-medium text-sm text-gray-900">
            Hosts: {row.involved_hosts?.slice(0, 2).join(', ') || 'N/A'}
            {row.involved_hosts?.length > 2 && ` +${row.involved_hosts.length - 2} more`}
          </div>
          <div className="text-xs text-gray-500">
            Users: {row.involved_users?.slice(0, 2).join(', ') || 'N/A'}
            {row.involved_users?.length > 2 && ` +${row.involved_users.length - 2} more`}
          </div>
        </div>
      ),
    },
    {
      key: 'risk',
      label: 'Risk Score',
      sortable: true,
      render: (row: any) => (
        <div>
          <div className="font-medium text-sm text-gray-900">
            {row.risk_score?.toFixed(1) || 'N/A'} / 100
          </div>
          <div className="text-xs text-gray-500">
            Events: {row.event_count || 0}
          </div>
        </div>
      ),
    },
    {
      key: 'confidence',
      label: 'Confidence',
      sortable: true,
      render: (row: any) => (
        <span className="text-sm font-mono text-gray-900">
          {(row.confidence * 100).toFixed(0)}%
        </span>
      ),
    },
    {
      key: 'created_at',
      label: 'Detected',
      sortable: true,
      render: (row: any) => (
        <div className="text-sm text-gray-600">{format(new Date(row.created_at), 'PPp')}</div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (row: any) => {
        const variants: Record<string, 'warning' | 'info' | 'success'> = {
          active: 'warning',
          investigating: 'info',
          resolved: 'success',
        };
        return <Badge variant={variants[row.status] || 'default'}>{row.status}</Badge>;
      },
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row: any) => (
        <div className="flex items-center gap-2">
          {row.status === 'active' && (
            <>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => acknowledgeMutation.mutate(row.id)}
                loading={acknowledgeMutation.isPending}
                title="Acknowledge (legacy action)"
              >
                Acknowledge
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => handleResolve(row)}
                loading={resolveMutation.isPending}
                title="Resolve (legacy action)"
              >
                Resolve
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      {/* Stats */}
      <StatsGrid columns={4} className="mb-6">
        <StatCard
          title="Total Correlations"
          value={stats.total}
          icon={<Activity className="w-6 h-6" />}
          variant="info"
        />
        <StatCard
          title="Critical"
          value={stats.critical}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="danger"
        />
        <StatCard
          title="High Severity"
          value={stats.high}
          icon={<AlertTriangle className="w-6 h-6" />}
          variant="warning"
        />
        <StatCard
          title="Active"
          value={stats.active}
          icon={<CheckCircle className="w-6 h-6" />}
          variant="warning"
        />
      </StatsGrid>

      {/* Barra filtri */}
      <div className="flex flex-wrap items-end gap-3 mb-4 p-3 bg-white rounded-lg border border-slate-200">
        <div className="w-52">
          <label className="block text-xs font-medium text-slate-500 mb-1">Tattica ATT&amp;CK</label>
          <Select value={tactic} onChange={(e: any) => setTactic(e.target.value)}>
            <option value="all">Tutte le tattiche</option>
            {TACTIC_OPTIONS.map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
            ))}
          </Select>
        </div>
        <div className="w-40">
          <label className="block text-xs font-medium text-slate-500 mb-1">Severità</label>
          <Select value={severity} onChange={(e: any) => setSeverity(e.target.value)}>
            <option value="all">Tutte</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
        </div>
        <div className="w-40">
          <label className="block text-xs font-medium text-slate-500 mb-1">Sensore</label>
          <Select value={sensor} onChange={(e: any) => setSensor(e.target.value)}>
            <option value="all">Tutti</option>
            <option value="ebpf">eBPF (kernel)</option>
            <option value="auditd">auditd / Laurel</option>
          </Select>
        </div>
        {technique && (
          <button
            onClick={clearTechnique}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-orange-50 text-orange-700 border border-orange-200 hover:bg-orange-100"
            title="Rimuovi il filtro per tecnica"
          >
            Tecnica: {technique} <X className="w-3 h-3" />
          </button>
        )}
        <div className="ml-auto text-sm text-slate-500 self-center">
          {correlations.length} di {allCorrelations.length} correlazioni
        </div>
      </div>

      {/* Table or Empty State */}
      {correlations?.length === 0 && !isLoading ? (
        <EmptyState
          icon={<CheckCircle className="w-8 h-8" />}
          title="No Active Correlations"
          description="The advanced correlation engine has not detected any suspicious patterns or attack sequences in the last 24 hours"
        />
      ) : (
        <Table
          data={correlations || []}
          columns={columns}
          loading={isLoading}
          emptyMessage="No correlations found"
        />
      )}
    </div>
  );
}
