// License Apache License 2.0


import dayjs, { type Dayjs } from 'dayjs'
import type { CertificateQuery } from '../../api/cert'

export type CertificateSortField = 'notBefore' | 'notAfter' | 'subject'
export type CertificateSortDirection = 'asc' | 'desc'
export type CertificateSort = {
  field: CertificateSortField
  direction: CertificateSortDirection
}

export function certificateOrder(field: CertificateSortField, direction: CertificateSortDirection) {
  return `${field}${direction === 'desc' ? '-desc' : ''}`
}

export function certificateQueryTime(value: Dayjs | null) {
  return value?.second(0).millisecond(0).toISOString()
}

export function localCertificateTime(value: string) {
  const time = dayjs(value)
  return time.isValid() ? time.format('YYYY-MM-DD HH:mm') : value
}

export function certificatePage<T>(items: T[], page: number, pageSize: number) {
  const current = Math.min(page, Math.max(1, Math.ceil(items.length / pageSize)))
  return { current, items: items.slice((current - 1) * pageSize, current * pageSize) }
}

type CertificateSummary = { subject: string; notBefore: string; notAfter: string }
type CertificatePage<T> = { data: { data: T[] }; headers?: Record<string, unknown> }

export async function collectCertificatePages<T extends CertificateSummary>(
  query: CertificateQuery,
  fetch: (query: CertificateQuery) => Promise<CertificatePage<T>>,
  current: () => boolean,
): Promise<T[] | undefined> {
  const items: T[] = []
  const cursors = new Set<string>()
  let cursor: string | undefined
  let paged = false
  do {
    const response = await fetch({ ...query, paged: true, cursor })
    if (!current()) return undefined
    items.push(...(response.data.data || []))
    const next = response.headers?.['x-next-cursor']
    cursor = typeof next === 'string' ? next : undefined
    if (cursor) {
      if (cursors.has(cursor)) throw new Error('Repeated certificate cursor')
      cursors.add(cursor)
      paged = true
    }
    if (paged) {
      const field = query.orderBy?.startsWith('subject')
        ? 'subject'
        : query.orderBy?.startsWith('notAfter')
          ? 'notAfter'
          : 'notBefore'
      const direction = query.orderBy?.endsWith('-desc') ? -1 : 1
      items.sort((a, b) => (a[field] < b[field] ? -1 : a[field] > b[field] ? 1 : 0) * direction)
      items.length = Math.min(items.length, query.limit ?? 1000)
    }
  } while (cursor)
  return items
}
