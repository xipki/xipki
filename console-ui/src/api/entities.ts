// License Apache License 2.0


import api from './client'
import type { ApiEnvelope, EntityPayload, EntityRecord, FormValues } from '../types/api'

export function entityEditPayload(values: FormValues, editing: boolean): EntityPayload {
  const { name, type, base64Cert, conf, replaceConf } = values
  const payload: EntityPayload = {}
  if (!editing) {
    if (typeof name !== 'string' || !name.trim()) throw new Error('A name is required')
    payload.name = name
  }
  if (typeof type === 'string') payload.type = type
  if (typeof base64Cert === 'string') payload.base64Cert = base64Cert
  if (!editing || replaceConf) {
    const configuration = typeof conf === 'string' ? conf : undefined
    if (
      (editing && !configuration?.trim()) ||
      configuration?.includes('****') ||
      configuration?.includes('<redacted>') ||
      configuration?.includes('<sensitive>')
    ) {
      throw new Error('Enter the complete configuration; masked values cannot be saved')
    }
    if (configuration !== undefined) payload.conf = configuration
    if (editing) payload.replaceConf = true
  }
  return payload
}

function crudApi(base: string) {
  return {
    list: () => api.get<ApiEnvelope<EntityRecord[]>>(base),
    get: (name: string) =>
      api.get<ApiEnvelope<EntityRecord>>(`${base}/${encodeURIComponent(name)}`),
    create: (data: EntityPayload) => api.post(base, data),
    update: (name: string, data: EntityPayload) =>
      api.put(`${base}/${encodeURIComponent(name)}`, data),
    remove: (name: string) => api.delete(`${base}/${encodeURIComponent(name)}`),
  }
}

function crudWithCaApi(base: string) {
  return {
    ...crudApi(base),
    getForCa: (ca: string) => api.get(`${base}/ca/${encodeURIComponent(ca)}`),
    addToCa: (name: string, ca: string, data?: EntityPayload) =>
      api.post(`${base}/${encodeURIComponent(name)}/ca/${encodeURIComponent(ca)}`, data || {}),
    removeFromCa: (name: string, ca: string) =>
      api.delete(`${base}/${encodeURIComponent(name)}/ca/${encodeURIComponent(ca)}`),
  }
}

export const profileApi = {
  ...crudWithCaApi('/api/profile'),
  associationsForCa: (ca: string) =>
    api.get(`/api/profile/ca/${encodeURIComponent(ca)}/associations`),
}
export const signerApi = crudApi('/api/signer')
export const requestorApi = {
  ...crudWithCaApi('/api/requestor'),
  updateForCa: (name: string, ca: string, data: EntityPayload) =>
    api.put(`/api/requestor/${encodeURIComponent(name)}/ca/${encodeURIComponent(ca)}`, data),
}
export const publisherApi = crudWithCaApi('/api/publisher')
export const keypairGenApi = crudApi('/api/keypairgen')
