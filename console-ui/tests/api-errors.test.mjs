// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isHandledRequestError } from '../src/types/api.ts'

test('API errors already reported by the client do not need a second notification', () => {
  assert.equal(isHandledRequestError({ isAxiosError: true }), true)
  assert.equal(isHandledRequestError({ response: { status: 400 } }), true)
  assert.equal(isHandledRequestError(new Error('local validation failed')), false)
  assert.equal(isHandledRequestError(null), false)
})
