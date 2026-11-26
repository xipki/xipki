// License Apache License 2.0


export type CertificateRevocation = {
  revoked?: boolean | null
  revocationReason?: string
  revocationTime?: string
  invalidityTime?: string
}

export function revocationDisplay(value: CertificateRevocation) {
  if (value.revoked == null)
    return { kind: 'unknown', label: 'Revocation status unavailable', color: 'default' }
  if (value.revoked && value.revocationReason === 'certificateHold')
    return { kind: 'hold', label: 'ON HOLD', color: 'orange' }
  if (value.revoked) return { kind: 'revoked', label: 'REVOKED', color: 'red' }
  return { kind: 'active', label: 'NOT REVOKED', color: 'green' }
}

export function withKnownRevocation<T extends CertificateRevocation>(
  detail: T,
  summary: CertificateRevocation,
): T {
  if (detail.revoked != null || summary.revoked == null) return detail
  return {
    ...detail,
    revoked: summary.revoked,
    revocationReason: summary.revocationReason,
    revocationTime: summary.revocationTime,
    invalidityTime: summary.invalidityTime,
  }
}
