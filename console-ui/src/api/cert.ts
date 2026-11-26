// License Apache License 2.0


import api from './client'

export type CertificateQuery = {
  ca: string
  subject?: string
  validFrom?: string
  validTo?: string
  orderBy?: string
  limit?: number
  paged?: boolean
  cursor?: string
}
export type KeyCertificateRequest = {
  ca: string
  profile: string
  subject: string
  notBefore?: string
  notAfter?: string
  downloadPassword: string
}
const path = (ca: string, serial: string) =>
  `/api/cert/${encodeURIComponent(ca)}/${encodeURIComponent(serial)}`

export { canIssueFromCa } from '../ca-availability'

export const certApi = {
  list: (params: CertificateQuery) => api.get('/api/cert', { params }),
  get: (ca: string, serial: string) => api.get(path(ca, serial)),
  enroll: (data: FormData) =>
    api.post('/api/cert/enroll', data, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    }),
  enrollCross: (data: FormData) =>
    api.post('/api/cert/enroll-cross', data, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    }),
  enrollKeyDownload: (data: KeyCertificateRequest) =>
    api.post('/api/cert/enroll-key/download', data, {
      responseType: 'blob',
      timeout: 120000,
    }),
  revoke: (ca: string, serial: string, reason: string, invalidityTime?: string) =>
    api.post(`${path(ca, serial)}/revoke`, { reason, invalidityTime }),
  unsuspend: (ca: string, serial: string) => api.post(`${path(ca, serial)}/unsuspend`),
  remove: (ca: string, serial: string) => api.delete(path(ca, serial)),
  downloadUrl: (ca: string, serial: string, format = 'pem') =>
    `${path(ca, serial)}/download?format=${encodeURIComponent(format)}`,
}

export function saveDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
