// License Apache License 2.0


export type CertificateValidity =
  'not-yet-valid' | 'valid' | 'expiring-soon' | 'expired' | 'unknown'

export function matchesCertificateValidity(
  filter: CertificateValidity,
  state: CertificateValidity,
) {
  return filter === state || (filter === 'valid' && state === 'expiring-soon')
}

export function certificateValidity(
  cert: { notBefore: string; notAfter: string },
  now = Date.now(),
): CertificateValidity {
  const starts = Date.parse(cert.notBefore)
  const ends = Date.parse(cert.notAfter)
  if (!Number.isFinite(starts) || !Number.isFinite(ends) || ends <= starts) return 'unknown'
  if (now < starts) return 'not-yet-valid'
  if (now >= ends) return 'expired'
  return ends - now <= 30 * 24 * 60 * 60 * 1000 ? 'expiring-soon' : 'valid'
}
