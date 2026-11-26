// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { revocationDisplay, withKnownRevocation } from '../src/pages/cert/certificate-revocation.ts'

test('revocation display distinguishes an unavailable status from an active certificate', () => {
  assert.equal(revocationDisplay({ revoked: null }).kind, 'unknown')
  assert.equal(revocationDisplay({ revoked: false }).kind, 'active')
  assert.equal(revocationDisplay({ revoked: true, revocationReason: 'certificateHold' }).kind, 'hold')
  assert.equal(revocationDisplay({ revoked: true, revocationReason: 'keyCompromise' }).kind,
    'revoked')
})

test('certificate detail uses a known list status only when the remote status is missing', () => {
  const summary = { revoked: true, revocationReason: 'certificateHold' }
  assert.deepEqual(withKnownRevocation({ subject: 'CN=Test', revoked: null }, summary),
    { subject: 'CN=Test', ...summary, revocationTime: undefined, invalidityTime: undefined })
  assert.deepEqual(withKnownRevocation({ revoked: false }, summary), { revoked: false })
  assert.deepEqual(withKnownRevocation({ revoked: null }, { revoked: null }), { revoked: null })
})
