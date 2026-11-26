// License Apache License 2.0


export type FormValues = Record<string, unknown>

export type ApiEnvelope<T> = {
  data: T
  success?: boolean
  error?: string
}

export type EntityRecord = {
  name: string
  type?: string
  conf?: string
  base64Cert?: string
  faulty?: boolean
  [key: string]: unknown
}

export type EntityPayload = {
  name?: string
  type?: string
  conf?: string
  base64Cert?: string
  replaceConf?: boolean
  [key: string]: unknown
}

export type CaSummary = {
  name: string
  status?: string
  type?: string
  runtimeState?: string
  subject?: string
  signerType?: string
  notAfter?: string
  certificateFingerprint?: string
  parentCertificateFingerprint?: string
  chainStatus?: string
  faulty?: boolean
  [key: string]: unknown
}

export type CaDetails = CaSummary & {
  serialNumber?: string
  issuer?: string
  notBefore?: string
  revocationCheck?: string
  pathLength?: number
  chainCertificateFingerprints?: string[]
  maxValidity?: string
  serialNoLen?: number
  revocationInfo?: unknown
  permissions?: string[]
  aliases?: string[]
  certPem?: string
}

export type DeleteImpact = {
  namedGrantCount?: number
  profiles?: string[]
  publishers?: string[]
  aliases?: string[]
  visibleChildCas?: string[]
  visibleChainReferences?: string[]
  pendingEnrollmentCount?: number
}

export type DashboardData = {
  systemStatus: string
  caNames: string[]
  successfulCaNames: string[]
  failedCaNames: string[]
  inactiveCaNames: string[]
  certprofileCount: number
  signerCount: number
  requestorCount: number
  publisherCount: number
}

export type QuickStartState = 'AVAILABLE' | 'IN_PROGRESS' | 'COMPLETED' | 'UNAVAILABLE' | 'CONFLICT'

export type QuickStartStatus = {
  state: QuickStartState
  available: boolean
  caName?: string | null
  steps: Array<{ code: string; complete: boolean }>
  message?: string | null
}

export type QuickStartRequest = {
  caName: string
  organization: string
  country?: string
  confirmed: true
}

export type CaEnrollmentParent = {
  name: string
  profiles: Array<{
    name: string
    capabilities?: { pathLenConstraint?: number | null }
  }>
}

export type HttpError = {
  message?: string
  code?: string
  response?: {
    status?: number
    data?: { error?: unknown }
  }
  errorFields?: unknown
  isAxiosError?: boolean
}

export function errorMessage(error: unknown, fallback: string): string {
  if (!error || typeof error !== 'object') return fallback
  const candidate = error as HttpError
  const responseError = candidate.response?.data?.error
  if (typeof responseError === 'string' && responseError.trim()) return responseError
  if (typeof candidate.message === 'string' && candidate.message.trim()) return candidate.message
  return fallback
}

export function isFormValidationError(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'errorFields' in error)
}

export function isHandledRequestError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const candidate = error as HttpError
  return candidate.isAxiosError === true || candidate.response != null
}
