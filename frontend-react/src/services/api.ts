// ============================================================================
// CYBERSHEPPARD - API Service
// ============================================================================

import axios, { AxiosInstance } from 'axios';

// Same-origin di default: in produzione il frontend è servito da nginx, che fa
// da reverse-proxy TLS verso il backend (location /api → backend_rust), quindi
// le richieste relative viaggiano su HTTPS senza mixed-content. In sviluppo il
// dev-server Vite proxya /api verso il backend (vedi vite.config). Un override
// esplicito è possibile via VITE_API_URL.
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor - add auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('access_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor - handle token refresh
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          try {
            const refreshToken = localStorage.getItem('refresh_token');
            const response = await axios.post(`${API_BASE_URL}/api/auth/refresh`, {
              refresh_token: refreshToken,
            });
            const { access_token } = response.data;
            localStorage.setItem('access_token', access_token);
            originalRequest.headers.Authorization = `Bearer ${access_token}`;
            return this.client(originalRequest);
          } catch (refreshError) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = '/login';
            return Promise.reject(refreshError);
          }
        }
        return Promise.reject(error);
      }
    );
  }

  // ========================================================================
  // AUTH
  // ========================================================================

  async login(username: string, password: string) {
    const response = await this.client.post('/api/auth/login', {
      username,
      password,
    });
    return response.data;
  }

  async logout() {
    const response = await this.client.post('/api/auth/logout');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    return response.data;
  }

  async getCurrentUser() {
    const response = await this.client.get('/api/auth/me');
    return response.data;
  }

  // ========================================================================
  // TARGETS
  // ========================================================================

  async getTargets(params?: Record<string, any>) {
    const response = await this.client.get('/api/targets', { params });
    return response.data;
  }

  async getTarget(id: number) {
    const response = await this.client.get(`/api/targets/${id}`);
    return response.data;
  }

  async createTarget(data: any) {
    const response = await this.client.post('/api/targets', data);
    return response.data;
  }

  async updateTarget(id: number, data: any) {
    const response = await this.client.put(`/api/targets/${id}`, data);
    return response.data;
  }

  async deleteTarget(id: number) {
    const response = await this.client.delete(`/api/targets/${id}`);
    return response.data;
  }

  // ========================================================================
  // COMPLIANCE
  // ========================================================================

  async getViolations(params?: Record<string, any>) {
    const response = await this.client.get('/api/compliance/violations', { params });
    return response.data;
  }

  async getViolation(id: number) {
    const response = await this.client.get(`/api/compliance/violations/${id}`);
    return response.data;
  }

  async acknowledgeViolation(id: number, notes?: string) {
    const response = await this.client.patch(
      `/api/compliance/violations/${id}/acknowledge`,
      { notes }
    );
    return response.data;
  }

  async resolveViolation(id: number, resolution_notes: string, status?: string) {
    const response = await this.client.patch(
      `/api/compliance/violations/${id}/resolve`,
      { resolution_notes, status }
    );
    return response.data;
  }

  async getPolicies() {
    const response = await this.client.get('/api/compliance/policies');
    return response.data;
  }

  async getTargetComplianceStatus(targetId: number) {
    const response = await this.client.get(
      `/api/compliance/targets/${targetId}/status`
    );
    return response.data;
  }

  // ========================================================================
  // HARDENING
  // ========================================================================

  async getHardeningModels() {
    const response = await this.client.get('/api/hardening/models');
    return response.data;
  }

  async applyHardening(targetId: number, modelId: number) {
    const response = await this.client.post(`/api/hardening/apply`, {
      target_id: targetId,
      model_id: modelId,
    });
    return response.data;
  }

  async applyHardeningToTarget(targetId: number, modelPath: string) {
    const response = await this.client.post(`/api/hardening/apply`, {
      target_id: targetId,
      model_path: modelPath,
    });
    return response.data;
  }

  async getHardeningApplications(params?: Record<string, any>) {
    const response = await this.client.get('/api/hardening/applications', { params });
    return response.data;
  }

  async getHardeningApplication(id: number) {
    const response = await this.client.get(`/api/hardening/applications/${id}`);
    return response.data;
  }

  // ========================================================================
  // HARDENING TEMPLATES (YAML)
  // ========================================================================

  async getHardeningTemplates(params?: {
    framework?: string;
    os?: string;
    priority?: string;
  }) {
    const response = await this.client.get('/api/hardening/templates', { params });
    return response.data;
  }

  async getHardeningTemplate(id: number) {
    const response = await this.client.get(`/api/hardening/templates/${id}`);
    return response.data;
  }

  async executeHardeningTemplate(data: {
    template_id: number;
    target_ids: number[];
    execution_mode: 'dry_run' | 'apply';
  }) {
    const response = await this.client.post('/api/hardening/execute', data);
    return response.data;
  }

  async getHardeningExecution(id: number) {
    const response = await this.client.get(`/api/hardening/executions/${id}`);
    return response.data;
  }

  async getHardeningExecutions(params?: {
    template_id?: number;
    target_id?: number;
    status?: string;
  }) {
    const response = await this.client.get('/api/hardening/executions', { params });
    return response.data;
  }

  async rollbackHardeningExecution(id: number) {
    const response = await this.client.post(`/api/hardening/executions/${id}/rollback`);
    return response.data;
  }

  // ========================================================================
  // MONITORING
  // ========================================================================

  async getMetrics(targetId: number, params?: Record<string, any>) {
    const response = await this.client.get(`/api/monitoring/metrics`, {
      params: { target_id: targetId, ...params },
    });
    return response.data;
  }

  // ========================================================================
  // INTEGRATIONS
  // ========================================================================

  async getIntegrationStatus() {
    const response = await this.client.get('/api/integrations/status');
    return response.data;
  }

  async triggerSync(integrationName: string) {
    const response = await this.client.post(`/api/integrations/${integrationName}/sync`);
    return response.data;
  }

  // ========================================================================
  // SECURITY EVENTS & CORRELATIONS (NEW API)
  // ========================================================================

  async getSecurityEvents(params?: {
    hours?: number;
    limit?: number;
    severity?: string;
    host?: string;
    user?: string;
  }) {
    const response = await this.client.get('/api/events', { params });
    return response.data;
  }

  async getSecurityEventStats(params?: { hours?: number }) {
    const response = await this.client.get('/api/events/stats', { params });
    return response.data;
  }

  async getSecurityCorrelations(params?: { hours?: number; limit?: number }) {
    const response = await this.client.get('/api/events/correlations', { params });
    return response.data;
  }

  async getCorrelationStats(params?: { hours?: number }) {
    const response = await this.client.get('/api/events/correlations/stats', { params });
    return response.data;
  }

  async analyzeCorrelations(params?: { hours?: number }) {
    const response = await this.client.post('/api/events/correlations/analyze', params);
    return response.data;
  }

  async calculateBaselines(params?: { user?: string; host?: string; days?: number }) {
    const response = await this.client.post('/api/events/baselines/calculate', params);
    return response.data;
  }

  async detectAnomalies(params?: { user?: string; host?: string; hours?: number }) {
    const response = await this.client.post('/api/events/anomalies/detect', params);
    return response.data;
  }

  async getHostRisk(hostName: string) {
    const response = await this.client.get(`/api/events/hosts/${hostName}/risk`);
    return response.data;
  }

  async getDashboardMetrics(params?: { hours?: number }) {
    const response = await this.client.get('/api/events/dashboard/metrics', { params });
    return response.data;
  }

  // Auditd event detail / status methods
  async getAuditdEvents(params?: {
    target_id?: number;
    severity?: string;
    category?: string;
    status?: string;
    limit?: number;
  }) {
    const response = await this.client.get('/api/auditd/events', { params });
    return response.data;
  }

  async getAuditdStats() {
    const response = await this.client.get('/api/auditd/stats');
    return response.data;
  }

  async getAuditdEventDetails(eventId: number) {
    const response = await this.client.get(`/api/auditd/events/${eventId}`);
    return response.data;
  }

  async updateAuditdEventStatus(eventId: number, status: string, resolutionNotes?: string) {
    const response = await this.client.post(`/api/auditd/events/${eventId}/status`, {
      status,
      resolution_notes: resolutionNotes,
    });
    return response.data;
  }

  // Legacy correlation methods - kept for backward compatibility
  // These now map to the new event correlation system
  async getTargetCorrelations(_targetId: number) {
    // Target-specific correlations can be filtered from general correlations
    const response = await this.client.get('/api/events/correlations', {
      params: { hours: 24, limit: 100 }
    });
    // Filter by target on client side if needed
    return response.data;
  }

  async acknowledgeCorrelation(_correlationId: number) {
    // Note: The new event correlation system doesn't have acknowledge/resolve
    // This is a no-op for backward compatibility
    console.warn('acknowledgeCorrelation is deprecated - new system uses status updates');
    return { success: true, message: 'Correlation acknowledged (legacy API)' };
  }

  async resolveCorrelation(_correlationId: number, _resolutionNotes: string) {
    // Note: The new event correlation system doesn't have acknowledge/resolve
    // This is a no-op for backward compatibility
    console.warn('resolveCorrelation is deprecated - new system uses status updates');
    return { success: true, message: 'Correlation resolved (legacy API)' };
  }

  // ========================================================================
  // COMPLIANCE FRAMEWORKS
  // ========================================================================

  async getComplianceFrameworks() {
    const response = await this.client.get('/api/compliance-frameworks/frameworks');
    return response.data;
  }

  async getComplianceFramework(id: number) {
    const response = await this.client.get(`/api/compliance-frameworks/frameworks/${id}`);
    return response.data;
  }

  async getFrameworkSummary() {
    const response = await this.client.get('/api/compliance-frameworks/frameworks/summary');
    return response.data;
  }

  async getComplianceOverview() {
    const response = await this.client.get('/api/compliance-frameworks/overview');
    return response.data;
  }

  async getTargetAssessments(targetId: number) {
    const response = await this.client.get(
      `/api/compliance-frameworks/assessments/target/${targetId}`
    );
    return response.data;
  }

  async createAssessment(data: {
    target_id: number;
    framework_id: number;
    total_controls: number;
  }) {
    const response = await this.client.post('/api/compliance-frameworks/assessments', data);
    return response.data;
  }

  // ========================================================================
  // COMPLIANCE CONTROLS & MACROAREAS
  // ========================================================================

  async getComplianceMacroareas() {
    const response = await this.client.get('/api/compliance/macroareas');
    return response.data;
  }

  async getComplianceControls(params?: {
    framework?: string;
    priority?: string;
    os?: string;
    macroarea_id?: number;
  }) {
    const response = await this.client.get('/api/compliance/controls', { params });
    return response.data;
  }

  async getComplianceControl(id: number) {
    const response = await this.client.get(`/api/compliance/controls/${id}`);
    return response.data;
  }

  async getComplianceDashboard(params?: { target_id?: number }) {
    const response = await this.client.get('/api/compliance/dashboard', { params });
    return response.data;
  }

  async getComplianceTargets() {
    const response = await this.client.get('/api/compliance/targets');
    return response.data;
  }

  async getComplianceGaps(params?: { framework?: string; priority?: string[] }) {
    const response = await this.client.get('/api/compliance/gaps', { params });
    return response.data;
  }

  async getTargetComplianceScore(targetId: number, frameworkCode: string) {
    const response = await this.client.get(
      `/api/compliance/targets/${targetId}/score/${frameworkCode}`
    );
    return response.data;
  }

  // ========================================================================
  // ALERTS
  // ========================================================================

  async getAlerts(severity?: string, status?: string) {
    const params: Record<string, any> = {};
    if (severity && severity !== 'all') params.severity = severity;
    if (status && status !== 'all') {
      if (status === 'active') {
        params.resolved = false;
      } else if (status === 'new') {
        params.status = 'new';
      } else if (status === 'acknowledged') {
        params.acknowledged = true;
        params.resolved = false;
      } else if (status === 'resolved') {
        params.resolved = true;
      }
    }
    const response = await this.client.get('/api/alerts', { params });
    return response.data;
  }

  async getActiveAlerts() {
    const response = await this.client.get('/api/alerts/active');
    return response.data;
  }

  async createAlert(data: {
    severity: string;
    title: string;
    message: string;
    alert_type: string;
    entity_type?: string;
    entity_id?: number;
    metadata?: any;
  }) {
    const response = await this.client.post('/api/alerts', data);
    return response.data;
  }

  async acknowledgeAlert(alertId: number, acknowledgedBy: string) {
    const response = await this.client.patch(`/api/alerts/${alertId}/acknowledge`, {
      acknowledged_by: acknowledgedBy,
    });
    return response.data;
  }

  async resolveAlert(alertId: number, resolvedBy: string, resolutionNotes: string) {
    const response = await this.client.patch(`/api/alerts/${alertId}/resolve`, {
      resolved_by: resolvedBy,
      resolution_notes: resolutionNotes,
    });
    return response.data;
  }

  async getAlertRules() {
    const response = await this.client.get('/api/alerts/rules');
    return response.data;
  }

  // ========================================================================
  // SETTINGS
  // ========================================================================

  async getSystemSettings(category?: string) {
    const params = category ? { category } : {};
    const response = await this.client.get('/api/settings/system', { params });
    return response.data;
  }

  async updateSystemSetting(key: string, value: string) {
    const response = await this.client.put(`/api/settings/system/${key}`, { value });
    return response.data;
  }

  async getUserSettings() {
    const response = await this.client.get('/api/settings/user');
    return response.data;
  }

  async setUserSetting(key: string, value: string) {
    const response = await this.client.put(`/api/settings/user/${key}`, { value });
    return response.data;
  }

  async getApiKeys(service?: string) {
    const params = service ? { service } : {};
    const response = await this.client.get('/api/settings/api-keys', { params });
    return response.data;
  }

  async generateApiKey(data: {
    name: string;
    description?: string;
    service?: string;
    permissions?: any;
    expires_days?: number;
  }) {
    const response = await this.client.post('/api/settings/api-keys', data);
    return response.data;
  }

  async revokeApiKey(id: number) {
    const response = await this.client.delete(`/api/settings/api-keys/${id}`);
    return response.data;
  }

  // ── MCP access keys (inbound, per-user, scope read/write) ──────────────
  // Distinte dalle integration API keys sopra: queste autenticano un client
  // (es. un agente MCP) VERSO CyberSheppard su POST /api/mcp.
  async getMcpKeys() {
    const response = await this.client.get('/api/api-keys');
    return response.data as Array<{
      id: number;
      name: string;
      key_prefix: string;
      scope: 'read' | 'write';
      created_at: string;
      last_used_at: string | null;
      expires_at: string | null;
    }>;
  }

  async createMcpKey(data: { name: string; scope?: 'read' | 'write'; expires_at?: string }) {
    const response = await this.client.post('/api/api-keys', data);
    return response.data as { id: number; name: string; scope: string; key_prefix: string; api_key: string };
  }

  async revokeMcpKey(id: number) {
    await this.client.delete(`/api/api-keys/${id}`);
  }

  async getHealthCheck() {
    const response = await this.client.get('/api/settings/health');
    return response.data;
  }

  async testConnection(service: string, url: string, apiKey?: string) {
    const response = await this.client.post('/api/settings/test-connection', {
      service,
      url,
      api_key: apiKey,
    });
    return response.data;
  }

  async changePassword(data: { current_password: string; new_password: string }) {
    const response = await this.client.post('/api/settings/change-password', data);
    return response.data;
  }

  async cleanupOldData() {
    const response = await this.client.post('/api/settings/cleanup');
    return response.data;
  }

  async resetDatabase(confirmation: string) {
    const response = await this.client.post('/api/settings/reset', { confirmation });
    return response.data;
  }

  // ========================================================================
  // PLUGINS
  // ========================================================================

  async getPluginRepositories() {
    const response = await this.client.get('/api/plugins/repositories');
    return response.data;
  }

  async addPluginRepository(data: {
    name: string;
    url: string;
    branch: string;
    trust_level: string;
  }) {
    const response = await this.client.post('/api/plugins/repositories', data);
    return response.data;
  }

  async removePluginRepository(id: number) {
    const response = await this.client.delete(`/api/plugins/repositories/${id}`);
    return response.data;
  }

  async fetchRepositoryPlugins(repoId: number) {
    const response = await this.client.post(`/api/plugins/repositories/${repoId}/fetch`);
    return response.data;
  }

  async getAvailablePlugins() {
    const response = await this.client.get('/api/plugins/registry');
    return response.data;
  }

  async getInstalledPlugins() {
    const response = await this.client.get('/api/plugins/installed');
    return response.data;
  }

  async installPlugin(registryId: number) {
    const response = await this.client.post(`/api/plugins/install/${registryId}`);
    return response.data;
  }

  async uninstallPlugin(pluginId: number) {
    const response = await this.client.delete(`/api/plugins/installed/${pluginId}`);
    return response.data;
  }

  async enablePlugin(pluginId: number) {
    const response = await this.client.post(`/api/plugins/installed/${pluginId}/enable`);
    return response.data;
  }

  async disablePlugin(pluginId: number) {
    const response = await this.client.post(`/api/plugins/installed/${pluginId}/disable`);
    return response.data;
  }

  async configurePlugin(pluginId: number, configuration: any) {
    const response = await this.client.put(`/api/plugins/installed/${pluginId}/configure`, {
      configuration,
    });
    return response.data;
  }
}

export const api = new ApiService();
export default api;
