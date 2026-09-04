import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { X } from 'lucide-react';

interface EditTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
  target: any;
}

// Gruppi hardening per destinazione d'uso (allineato ad AddTargetModal).
const HARDENING_GROUPS = [
  'general',
  'webserver',
  'database',
  'application',
  'container',
  'dns',
  'mail',
  'proxy',
  'workstation',
  'firewall',
];

// Rimuove l'eventuale netmask (/32) dall'IP INET restituito dal backend, così il
// valore prefillato coincide col testo usato per calcolare l'identity_hash.
const stripMask = (ip?: string) => (ip || '').split('/')[0];

export default function EditTargetModal({ isOpen, onClose, target }: EditTargetModalProps) {
  const queryClient = useQueryClient();
  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    mac_address: '',
    environment: 'production',
    gruppo: 'general',
    monitoring_enabled: true,
    monitoring_interval_seconds: 300,
  });
  const [error, setError] = useState('');

  // Prefill quando si apre / cambia il target.
  useEffect(() => {
    if (isOpen && target) {
      setFormData({
        hostname: target.hostname || '',
        ip_address: stripMask(target.ip_address),
        mac_address: target.mac_address || '',
        environment: target.environment || 'production',
        gruppo: target.gruppo || 'general',
        monitoring_enabled: target.monitoring_enabled ?? true,
        monitoring_interval_seconds: target.monitoring_interval_seconds ?? 300,
      });
      setError('');
    }
  }, [isOpen, target]);

  const updateMutation = useMutation({
    mutationFn: (data: any) => api.updateTarget(target.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      onClose();
    },
    onError: (err: any) => {
      setError(err.response?.data?.error || 'Impossibile aggiornare il target');
    },
  });

  const identityChanged =
    stripMask(target?.ip_address) !== formData.ip_address ||
    (target?.hostname || '') !== formData.hostname ||
    (target?.mac_address || '').toLowerCase() !== formData.mac_address.toLowerCase();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    updateMutation.mutate(formData);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    setFormData((prev) => ({ ...prev, [name]: type === 'number' ? parseInt(value) : value }));
  };

  const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = e.target;
    setFormData((prev) => ({ ...prev, [name]: checked }));
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold">Modifica target</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Hostname *</label>
              <input
                type="text" name="hostname" value={formData.hostname} onChange={handleChange} required
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Indirizzo IP *</label>
              <input
                type="text" name="ip_address" value={formData.ip_address} onChange={handleChange} required
                pattern="^(\d{1,3}\.){3}\d{1,3}$"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">MAC Address *</label>
            <input
              type="text" name="mac_address" value={formData.mac_address} onChange={handleChange} required
              pattern="^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono"
            />
            <p className="text-xs text-gray-500 mt-1">
              Identità agent = SHA512(IP + hostname + MAC).
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Group (hardening)</label>
              <select
                name="gruppo" value={formData.gruppo} onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                {HARDENING_GROUPS.map((g) => (<option key={g} value={g}>{g}</option>))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Environment</label>
              <select
                name="environment" value={formData.environment} onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
              </select>
            </div>
          </div>

          <div className="border-t pt-4">
            <div className="flex items-center mb-3">
              <input
                type="checkbox" name="monitoring_enabled" checked={formData.monitoring_enabled} onChange={handleCheckboxChange}
                className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
              />
              <label className="ml-2 text-sm text-gray-700">Abilita monitoraggio</label>
            </div>
            {formData.monitoring_enabled && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Intervallo monitoraggio (secondi)</label>
                <input
                  type="number" name="monitoring_interval_seconds" value={formData.monitoring_interval_seconds} onChange={handleChange}
                  min="60" max="3600"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            )}
          </div>

          {identityChanged && (
            <div className="bg-amber-50 border border-amber-200 text-amber-800 px-4 py-3 rounded-lg text-sm">
              Stai modificando l'identità (IP/hostname/MAC): l'identity_hash verrà ricalcolato e
              sarà necessario <strong>rifare il pairing</strong> dell'agent.
            </div>
          )}

          {error && <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">{error}</div>}

          <div className="flex justify-end space-x-3 pt-4 border-t">
            <button type="button" onClick={onClose} className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50">
              Annulla
            </button>
            <button type="submit" disabled={updateMutation.isPending}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
              {updateMutation.isPending ? 'Salvataggio…' : 'Salva modifiche'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
