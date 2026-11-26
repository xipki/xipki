// License Apache License 2.0


export type CaResource = string | { name: string; certificateFingerprint?: string }
export interface Binding {
  role: string
  scope: 'PLATFORM' | 'NAMED_CA' | 'ALL_CAS'
  caName?: string | null
  caFingerprint?: string | null
  allProfiles?: boolean
  profiles: string[]
}
export interface AccessUser {
  roles: string[]
  permissions: string[]
  bindings?: Binding[]
  rolePermissions?: Record<string, string[]>
  passwordChangeRequired?: boolean
}

// UI hints only. Backend repeats authorization against the current account and CA identity.
export function canUser(
  user: AccessUser | null,
  permission: string,
  ca?: CaResource,
  profile?: string,
): boolean {
  if (!user?.permissions.includes(permission)) return false
  if (ca === undefined) return true
  const name = typeof ca === 'string' ? ca : ca.name
  const fingerprint = typeof ca === 'string' ? undefined : ca.certificateFingerprint
  return (
    user.bindings?.some((binding) => {
      if (!user.rolePermissions?.[binding.role]?.includes(permission)) return false
      if (binding.role === 'SUPER_ADMIN' && binding.scope === 'PLATFORM') return true
      if (
        binding.scope !== 'ALL_CAS' &&
        !(
          binding.scope === 'NAMED_CA' &&
          binding.caName === name &&
          (!fingerprint || binding.caFingerprint === fingerprint)
        )
      )
        return false
      return (
        !['CERT_ISSUE', 'CERT_KEYGEN', 'CERT_CROSS', 'CA_ISSUE_SUBCA'].includes(permission) ||
        profile === undefined ||
        binding.allProfiles === true ||
        binding.profiles.includes(profile)
      )
    }) ?? false
  )
}

export function landingPath(user: AccessUser): string {
  if (user.passwordChangeRequired) return '/account/password'
  if (user.roles.includes('SUPER_ADMIN')) return '/dashboard'
  if (user.permissions.includes('CA_CONFIG_UPDATE') && user.permissions.includes('CA_READ'))
    return '/ca'
  if (user.permissions.includes('CERT_READ')) return '/cert'
  if (user.permissions.some((p) => ['CERT_ISSUE', 'CERT_KEYGEN', 'CERT_CROSS'].includes(p)))
    return '/cert/enroll'
  if (user.permissions.includes('USER_READ')) return '/access/users'
  if (user.permissions.includes('AUDIT_READ')) return '/audit'
  if (user.permissions.includes('CA_READ')) return '/dashboard'
  if (user.permissions.includes('ROLE_READ')) return '/access/roles'
  for (const [permission, path] of [
    ['SIGNER_READ', '/signer'],
    ['PUBLISHER_READ', '/publisher'],
    ['REQUESTOR_READ', '/requestor'],
    ['PROFILE_READ', '/profile'],
    ['KEYPAIRGEN_READ', '/keypairgen'],
    ['DBSCHEMA_READ', '/dbschema'],
    ['CRL_READ', '/crl'],
  ])
    if (user.permissions.includes(permission)) return path
  if (user.permissions.some((p) => ['CA_CREATE_ROOT', 'CA_IMPORT', 'CA_ISSUE_SUBCA'].includes(p)))
    return '/ca'
  if (
    user.permissions.some((p) =>
      [
        'SYSTEM_READ',
        'SYSTEM_RESTART',
        'SYSTEM_UNLOCK',
        'SYSTEM_NOTIFY_CHANGE',
        'TOKEN_READ',
        'CONFIG_IMPORT',
        'CONFIG_EXPORT',
        'CERT_REPUBLISH',
      ].includes(p),
    )
  )
    return '/system'
  return '/account'
}

export function enrollmentOptions<T extends { name: string; certificateFingerprint?: string }>(
  user: AccessUser | null,
  permission: string,
  cas: T[],
  selectedCa: string | undefined,
  profiles: string[],
): { cas: T[]; profiles: string[] } {
  const allowedCas = cas.filter((ca) => canUser(user, permission, ca))
  const identity = allowedCas.find((ca) => ca.name === selectedCa)
  return {
    cas: allowedCas,
    profiles: identity
      ? profiles.filter((profile) => canUser(user, permission, identity, profile))
      : [],
  }
}
