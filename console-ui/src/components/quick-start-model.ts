// License Apache License 2.0


import type { QuickStartStatus } from '../types/api'

export const quickStartDefaults = {
  caName: 'business-ca',
  organization: '',
  country: '',
}

/** Decides whether the deployment-level assistant has useful information for this operator. */
export function quickStartVisible(
  status: Pick<QuickStartStatus, 'state'> | null,
  superAdmin: boolean,
  canCreateRoot: boolean,
): boolean {
  return (
    superAdmin &&
    canCreateRoot &&
    status != null &&
    ['AVAILABLE', 'IN_PROGRESS', 'CONFLICT'].includes(status.state)
  )
}

/** Summarizes server-observed steps for a stable progress indicator. */
export function quickStartProgress(status: Pick<QuickStartStatus, 'steps'>) {
  return {
    complete: status.steps?.filter((step) => step.complete).length || 0,
    total: status.steps?.length || 0,
  }
}
