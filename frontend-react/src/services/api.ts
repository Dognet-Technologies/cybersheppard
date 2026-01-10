// ============================================================================
// CYBERSHEPPARD - API Service
// ============================================================================

import axios, { AxiosInstance } from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

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

  async getSecurityCorrelations(params?: Record<string, any>) {
    const response = await this.client.get('/api/integrations/correlations', { params });
    return response.data;
  }

  async getTargetCorrelations(targetId: number) {
    const response = await this.client.get(`/api/integrations/correlations/target/${targetId}`);
    return response.data;
  }

  async acknowledgeCorrelation(correlationId: number) {
    const response = await this.client.post(
      `/api/integrations/correlations/${correlationId}/acknowledge`,
      { acknowledged_by: 'current_user' }
    );
    return response.data;
  }

  async resolveCorrelation(correlationId: number, resolutionNotes: string) {
    const response = await this.client.post(
      `/api/integrations/correlations/${correlationId}/resolve`,
      {
        resolved_by: 'current_user',
        resolution_notes: resolutionNotes,
      }
    );
    return response.data;
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
}

export const api = new ApiService();
export default api;
