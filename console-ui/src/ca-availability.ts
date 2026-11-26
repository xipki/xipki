// License Apache License 2.0


export interface CaState {
  status?: string
  runtimeState?: string
  revocationInfo?: unknown
  notBefore?: string
  notAfter?: string
}
export interface CaOption extends CaState {
  name: string
  certificateFingerprint?: string
}

// Runtime-backed operations cannot use a configured but stopped CA.
// Read access remains valid for old/revoked certificates when the CA is running.
export function operationalCaNames(
  cas: CaOption[],
  permission: string,
  can: (permission: string, ca: CaOption) => boolean,
) {
  return cas
    .filter((ca) => ca.runtimeState === 'started' && can(permission, ca))
    .map((ca) => ca.name)
}

export function canIssueFromCa(ca: CaState, now = Date.now()) {
  return (
    ca.status?.toLowerCase() === 'active' &&
    ca.runtimeState === 'started' &&
    !ca.revocationInfo &&
    (!ca.notBefore || Date.parse(ca.notBefore) <= now) &&
    (!ca.notAfter || Date.parse(ca.notAfter) > now)
  )
}
