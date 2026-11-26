// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'

const validity = await import('../src/pages/cert/certificate-validity.ts').catch(() => null)

test('certificate validity uses only the returned validity dates', () => {
  assert.ok(validity, 'certificate validity classifier is available')
  const now = Date.parse('2026-10-30T00:00:00Z')
  const certificate = (notBefore, notAfter) => ({notBefore, notAfter})
  assert.equal(validity.certificateValidity(certificate('2026-11-01T00:00:00Z', '2027-01-01T00:00:00Z'), now), 'not-yet-valid')
  assert.equal(validity.certificateValidity(certificate('2026-01-01T00:00:00Z', '2026-10-30T00:00:00Z'), now), 'expired')
  assert.equal(validity.certificateValidity(certificate('2026-01-01T00:00:00Z', '2026-11-20T00:00:00Z'), now), 'expiring-soon')
  assert.equal(validity.certificateValidity(certificate('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z'), now), 'valid')
  assert.equal(validity.certificateValidity(certificate('invalid', '2027-01-01T00:00:00Z'), now), 'unknown')
})

test('within validity period includes certificates expiring soon', () => {
  assert.equal(typeof validity.matchesCertificateValidity, 'function')
  assert.equal(validity.matchesCertificateValidity('valid', 'valid'), true)
  assert.equal(validity.matchesCertificateValidity('valid', 'expiring-soon'), true)
  assert.equal(validity.matchesCertificateValidity('expiring-soon', 'valid'), false)
})
