// License Apache License 2.0


export type Role = {
  name: string
  displayName: string
  description: string
  scope: 'PLATFORM' | 'CA'
  builtin: boolean
  enabled: boolean
  revision: number
  permissions: string[]
  needsProfiles: boolean
  userCount: number
}
export type Permission = {
  code: string
  scope: 'PLATFORM' | 'CA'
  group: string
  dependencies: string[]
  readOnly: boolean
  privileged: boolean
  highRisk: boolean
  profileRequired: boolean
  allCasOnly: boolean
  reserved: boolean
  recentAuthRequired: boolean
  auditCompatible: boolean
}

export function togglePermission(
  selected: string[],
  code: string,
  checked: boolean,
  catalog: Pick<Permission, 'code' | 'dependencies'>[],
): string[] {
  const result = new Set(selected)
  if (checked) {
    const add = (value: string) => {
      if (result.has(value)) return
      result.add(value)
      catalog.find((item) => item.code === value)?.dependencies.forEach(add)
    }
    add(code)
  } else {
    result.delete(code)
    let changed = true
    while (changed) {
      changed = false
      for (const item of catalog)
        if (result.has(item.code) && item.dependencies.some((value) => !result.has(value))) {
          result.delete(item.code)
          changed = true
        }
    }
  }
  return [...result].sort()
}
