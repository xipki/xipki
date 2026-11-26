// License Apache License 2.0


interface CaIdentity {
  name: string
  certificateFingerprint?: string
  parentCertificateFingerprint?: string
  chainStatus?: string
}
export interface CaNode {
  key: string
  title: string
  children: CaNode[]
}
export function caForest(cas: CaIdentity[]): CaNode[] {
  const nodes = new Map(
    cas.map((ca) => [ca.name, { key: ca.name, title: ca.name, children: [] } as CaNode]),
  )
  const byFingerprint = new Map<string, CaIdentity[]>()
  for (const ca of cas)
    if (ca.certificateFingerprint)
      byFingerprint.set(ca.certificateFingerprint, [
        ...(byFingerprint.get(ca.certificateFingerprint) || []),
        ca,
      ])
  const parents = new Map<string, string>()
  for (const ca of cas) {
    const matches = byFingerprint.get(ca.parentCertificateFingerprint || '') || []
    if (
      ['verified', 'not-yet-valid'].includes(ca.chainStatus || '') &&
      matches.length === 1 &&
      matches[0].name !== ca.name
    )
      parents.set(ca.name, matches[0].name)
  }
  const cycleNodes = new Set<string>()
  for (const ca of cas) {
    const path = new Set<string>()
    let current: string | undefined = ca.name
    while (current && parents.has(current)) {
      if (path.has(current)) {
        for (const key of path) cycleNodes.add(key)
        break
      }
      path.add(current)
      current = parents.get(current)
    }
  }
  for (const name of cycleNodes) parents.delete(name)
  const roots: CaNode[] = []
  for (const ca of cas) {
    const node = nodes.get(ca.name)!,
      parent = nodes.get(parents.get(ca.name) || '')
    if (parent) parent.children.push(node)
    else roots.push(node)
  }
  return roots
}
