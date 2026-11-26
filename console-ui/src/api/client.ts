// License Apache License 2.0


import axios, {
  type AxiosInstance,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios'
import { message } from 'antd'
import { translateNotification as t } from '../i18n/locale'

type CsrfToken = { token: string; headerName: string }

let csrfToken: CsrfToken | undefined
let csrfRequest: Promise<CsrfToken> | undefined
const requestTimeout = 15000
const heavyWriteTimeout = 120000
const heavyWritePaths = new Set([
  '/api/ca',
  '/api/ca/root',
  '/api/quick-start',
  '/api/cert/enroll',
  '/api/cert/enroll-cross',
  '/api/cert/enroll-key',
  '/api/cert/enroll-key/download',
  '/api/system/republish',
])
export const authenticationRequiredEvent = 'xipki:authentication-required'

function getCsrfToken(): Promise<CsrfToken> {
  if (csrfToken) return Promise.resolve(csrfToken)
  if (!csrfRequest) {
    csrfRequest = axios
      .get<CsrfToken>('/api/auth/csrf', { withCredentials: true, timeout: requestTimeout })
      .then(({ data }) => {
        csrfToken = data
        return data
      })
      .finally(() => {
        csrfRequest = undefined
      })
  }
  return csrfRequest
}

const api = axios.create({
  baseURL: '',
  withCredentials: true,
  timeout: requestTimeout,
  headers: { 'Content-Type': 'application/json' },
})

export const authApi = axios.create({ baseURL: '', withCredentials: true, timeout: requestTimeout })

function isStateChanging(config: InternalAxiosRequestConfig) {
  return !['get', 'head', 'options'].includes((config.method || 'get').toLowerCase())
}

type ClientError = Error & {
  config?: InternalAxiosRequestConfig
  response?: AxiosResponse
  code?: string
}

async function responseBody(
  data: unknown,
  errorResponse = false,
): Promise<Record<string, unknown> | undefined> {
  if (data instanceof Blob) {
    // Downloads can return the same JSON error envelope as ordinary APIs.
    if (data.size > 65536 || (!errorResponse && !data.type.includes('json'))) return undefined
    try {
      return JSON.parse(await data.text())
    } catch {
      return undefined
    }
  }
  return data && typeof data === 'object' ? (data as Record<string, unknown>) : undefined
}

function configureClient(client: AxiosInstance, sessionProbe = false) {
  client.interceptors.request.use(async (config) => {
    const path = (config.url || '').split(/[?#]/)[0].replace(/\/$/, '')
    if (config.method?.toLowerCase() === 'post' && heavyWritePaths.has(path))
      config.timeout = heavyWriteTimeout
    if (!config.headers.has('X-Request-ID')) {
      config.headers.set(
        'X-Request-ID',
        globalThis.crypto?.randomUUID?.() ||
          `web-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`,
      )
    }
    if (isStateChanging(config)) {
      const csrf = await getCsrfToken()
      config.headers.set(csrf.headerName, csrf.token)
    }
    return config
  })

  async function reject(error: ClientError) {
    const status = error.response?.status
    const url = error.config?.url || ''
    const body = await responseBody(error.response?.data, true)
    const detail =
      typeof body?.error === 'string'
        ? body.error
        : typeof body?.message === 'string'
          ? body.message
          : error.message || t('Request failed')
    const requestId =
      error.response?.headers?.['x-request-id'] || error.config?.headers?.get('X-Request-ID')
    const correlation = requestId ? t(' (Request ID: {id})', { id: requestId }) : ''
    error.message = detail
    if (
      status === 401 &&
      (sessionProbe || url.endsWith('/api/auth/login') || url.endsWith('/api/auth/certificate'))
    ) {
      // App renders Login after an anonymous probe; the form handles invalid credentials.
    } else if (status === 401) {
      csrfToken = undefined
      window.dispatchEvent(new Event(authenticationRequiredEvent))
    } else if (status === 403) {
      // Fetch a fresh token on the next explicit attempt; never replay a denied mutation.
      csrfToken = undefined
      message.error(t('Request denied. Check permissions or refresh and retry.') + correlation)
    } else if (
      (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') &&
      error.config &&
      isStateChanging(error.config)
    ) {
      error.message =
        t('Request timed out. It may have taken effect; verify the result before retrying.') +
        correlation
      message.error(error.message, 10)
    } else if (status === 503) {
      message.error(
        t('{detail}. For writes, verify the result before retrying.', {
          detail: body ? detail : t('Platform service unavailable'),
        }) + correlation,
        10,
      )
    } else {
      message.error(`${detail}${correlation}`)
    }
    return Promise.reject(error)
  }

  client.interceptors.response.use(async (response) => {
    const url = response.config.url || ''
    if (
      url.endsWith('/api/auth/login') ||
      url.endsWith('/api/auth/certificate') ||
      url.endsWith('/api/auth/logout') ||
      url.endsWith('/api/auth/password')
    ) {
      csrfToken = undefined
    }
    const body = await responseBody(response.data)
    if (body?.success === false) {
      const error: ClientError = new Error(
        typeof body.error === 'string' ? body.error : t('Operation failed'),
      )
      error.config = response.config
      error.response = response
      return reject(error)
    }
    return response
  }, reject)
}

configureClient(api)
configureClient(authApi, true)

export default api
