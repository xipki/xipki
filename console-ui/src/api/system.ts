// License Apache License 2.0


import api from './client'
import type { ApiEnvelope, DashboardData, QuickStartRequest, QuickStartStatus } from '../types/api'

export const systemApi = {
  status: () => api.get('/api/system/status'),
  restart: () => api.post('/api/system/restart'),
  unlock: () => api.post('/api/system/unlock'),
  notifyChange: () => api.post('/api/system/notify-change'),
  republish: (data: { caName: string; publisherNames?: string[]; numThreads?: number }) =>
    api.post('/api/system/republish', data, { timeout: 120000 }),
  exportConf: (caNames?: string[]) =>
    api.get('/api/system/export', { params: { caNames }, responseType: 'blob' }),
  importConf: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/api/system/import', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    })
  },
  tokenInfo: (module?: string, slot?: number, verbose?: boolean) =>
    api.get('/api/system/token-info', { params: { module, slot, verbose } }),
  supportedTypes: () => api.get('/api/system/supported-types'),
  dashboard: () => api.get<ApiEnvelope<DashboardData>>('/api/dashboard'),
}

export const dbSchemaApi = {
  list: () => api.get('/api/dbschema'),
  add: (name: string, value: string) => api.post('/api/dbschema', { name, value }),
  update: (name: string, value: string) => api.put(`/api/dbschema/${name}`, { value }),
  remove: (name: string) => api.delete(`/api/dbschema/${name}`),
}

export const quickStartApi = {
  status: () => api.get<ApiEnvelope<QuickStartStatus>>('/api/quick-start'),
  execute: (request: QuickStartRequest) =>
    api.post<ApiEnvelope<QuickStartStatus>>('/api/quick-start', request, { timeout: 120000 }),
}
