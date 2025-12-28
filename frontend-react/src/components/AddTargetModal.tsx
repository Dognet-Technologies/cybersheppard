import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '../services/api';
import { X } from 'lucide-react';

interface AddTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function AddTargetModal({ isOpen, onClose }: AddTargetModalProps) {
  const queryClient = useQueryClient();
  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    ssh_port: 22,
    ssh_username: 'microcyber',
    environment: 'production',
    gruppo: '',
    monitoring_enabled: true,
    monitoring_interval_seconds: 300,
  });
  const [error, setError] = useState('');

  const createMutation = useMutation({
    mutationFn: (data: any) => api.createTarget(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      onClose();
      resetForm();
    },
    onError: (err: any) => {
      setError(err.response?.data?.error || 'Failed to create target');
    },
  });

  const resetForm = () => {
    setFormData({
      hostname: '',
      ip_address: '',
      ssh_port: 22,
      ssh_username: 'microcyber',
      environment: 'production',
      gruppo: '',
      monitoring_enabled: true,
      monitoring_interval_seconds: 300,
    });
    setError('');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    createMutation.mutate(formData);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'number' ? parseInt(value) : value,
    }));
  };

  const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: checked,
    }));
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold">Add New Target</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Hostname */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Hostname *
            </label>
            <input
              type="text"
              name="hostname"
              value={formData.hostname}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
              placeholder="server01.example.com"
            />
          </div>

          {/* IP Address */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              IP Address *
            </label>
            <input
              type="text"
              name="ip_address"
              value={formData.ip_address}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
              placeholder="192.168.1.100"
              pattern="^(\d{1,3}\.){3}\d{1,3}$"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* SSH Port */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                SSH Port
              </label>
              <input
                type="number"
                name="ssh_port"
                value={formData.ssh_port}
                onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                min="1"
                max="65535"
              />
            </div>

            {/* SSH Username */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                SSH Username
              </label>
              <input
                type="text"
                name="ssh_username"
                value={formData.ssh_username}
                onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {/* Environment */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Environment
              </label>
              <select
                name="environment"
                value={formData.environment}
                onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
              </select>
            </div>

            {/* Group */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Group (Optional)
              </label>
              <input
                type="text"
                name="gruppo"
                value={formData.gruppo}
                onChange={handleChange}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="web-servers"
              />
            </div>
          </div>

          {/* Monitoring Settings */}
          <div className="border-t pt-4">
            <h3 className="font-medium mb-3">Monitoring Settings</h3>

            <div className="flex items-center mb-3">
              <input
                type="checkbox"
                name="monitoring_enabled"
                checked={formData.monitoring_enabled}
                onChange={handleCheckboxChange}
                className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
              />
              <label className="ml-2 text-sm text-gray-700">
                Enable monitoring
              </label>
            </div>

            {formData.monitoring_enabled && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Monitoring Interval (seconds)
                </label>
                <input
                  type="number"
                  name="monitoring_interval_seconds"
                  value={formData.monitoring_interval_seconds}
                  onChange={handleChange}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  min="60"
                  max="3600"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Recommended: 300 seconds (5 minutes)
                </p>
              </div>
            )}
          </div>

          {error && (
            <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
              {error}
            </div>
          )}

          <div className="flex justify-end space-x-3 pt-4 border-t">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Create Target'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
