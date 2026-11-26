// License Apache License 2.0


import type { AccessUser } from './access-policy'

export const navigationItems = {
  '/dashboard': { label: 'Dashboard', permission: 'CA_READ' },
  '/ca': { label: 'CA Management', permission: 'CA_READ|CA_CREATE_ROOT|CA_IMPORT|CA_ISSUE_SUBCA' },
  '/cert': { label: 'Certificate list', permission: 'CERT_READ' },
  '/cert/enroll': { label: 'Issue certificate', permission: 'CERT_ISSUE|CERT_KEYGEN|CERT_CROSS' },
  '/crl': { label: 'CRL Management', permission: 'CRL_READ' },
  '/profile': { label: 'Cert Profiles', permission: 'PROFILE_READ' },
  '/signer': { label: 'Signers', permission: 'SIGNER_READ' },
  '/requestor': { label: 'Requestors', permission: 'REQUESTOR_READ' },
  '/publisher': { label: 'Publishers', permission: 'PUBLISHER_READ' },
  '/keypairgen': { label: 'Keypair Generators', permission: 'KEYPAIRGEN_READ' },
  '/system': {
    label: 'System',
    permission:
      'SYSTEM_READ|SYSTEM_RESTART|SYSTEM_UNLOCK|SYSTEM_NOTIFY_CHANGE|TOKEN_READ|CONFIG_EXPORT|CONFIG_IMPORT|CERT_REPUBLISH',
  },
  '/dbschema': { label: 'DB Schema', permission: 'DBSCHEMA_READ' },
  '/audit': { label: 'Audit Log', permission: 'AUDIT_READ' },
  '/access/users': { label: 'User management', permission: 'USER_READ' },
  '/access/roles': { label: 'Roles and permissions', permission: 'ROLE_READ' },
} as const

export type NavigationKey = keyof typeof navigationItems

const groups: { label: string; keys: NavigationKey[] }[] = [
  { label: 'Operations', keys: ['/dashboard', '/ca'] },
  { label: 'Certificate Management', keys: ['/cert', '/cert/enroll', '/crl'] },
  {
    label: 'CA configuration',
    keys: ['/profile', '/signer', '/requestor', '/publisher', '/keypairgen'],
  },
  {
    label: 'Administration',
    keys: ['/system', '/dbschema', '/audit', '/access/users', '/access/roles'],
  },
]

export function navigationPermission(key: NavigationKey): string {
  return navigationItems[key].permission
}

export function visibleNavigationGroups(user: AccessUser) {
  if (user.passwordChangeRequired) return []
  return groups
    .map((group) => ({
      label: group.label,
      items: group.keys
        .filter((key) =>
          navigationPermission(key)
            .split('|')
            .some((code) => user.permissions.includes(code)),
        )
        .map((key) => ({ key, ...navigationItems[key] })),
    }))
    .filter((group) => group.items.length > 0)
}

export function selectedNavigationKey(pathname: string): NavigationKey | undefined {
  return (Object.keys(navigationItems) as NavigationKey[])
    .filter((key) => pathname === key || pathname.startsWith(`${key}/`))
    .sort((a, b) => b.length - a.length)[0]
}
