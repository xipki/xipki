// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  quickStartDefaults,
  quickStartProgress,
  quickStartVisible,
} from '../src/components/quick-start-model.ts'

test('quick start is shown only to an eligible super administrator', () => {
  assert.equal(quickStartVisible({ state: 'AVAILABLE' }, true, true), true)
  assert.equal(quickStartVisible({ state: 'IN_PROGRESS' }, true, true), true)
  assert.equal(quickStartVisible({ state: 'CONFLICT' }, true, true), true)
  assert.equal(quickStartVisible({ state: 'COMPLETED' }, true, true), false)
  assert.equal(quickStartVisible({ state: 'AVAILABLE' }, false, true), false)
  assert.equal(quickStartVisible({ state: 'AVAILABLE' }, true, false), false)
})

test('quick start defaults and progress reflect the agreed safe profile', () => {
  assert.deepEqual(quickStartDefaults, {
    caName: 'business-ca',
    organization: '',
    country: '',
  })
  assert.deepEqual(
    quickStartProgress({
      state: 'IN_PROGRESS',
      steps: [
        { code: 'profiles', complete: true },
        { code: 'ca', complete: false },
      ],
    }),
    { complete: 1, total: 2 },
  )
})
