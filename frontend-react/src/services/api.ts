// ============================================================================
// CYBERSHEPPARD - API Service
// ============================================================================

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

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

  // ========================================================================
  // MONITORING
  // ========================================================================

  async getMetrics(targetId: number, params?: Record<string, any>) {
    const response = await this.client.get(`/api/monitoring/metrics`, {
      params: { target_id: targetId, ...params },
    });
    return response.data;
  }
}

export const api = new ApiService();
export default api;
