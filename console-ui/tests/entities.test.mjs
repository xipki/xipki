// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const ts = require('typescript')
const code = ts.transpileModule(readFileSync(new URL('../src/api/entities.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
}).outputText
function entities() {
  const exports = {}, calls = []
  const client = Object.fromEntries(['get', 'put', 'post', 'delete'].map(method => [method,
    async (...args) => { calls.push([method, ...args]); return { data: { success: true } } },
  ]))
  new Function('require', 'exports', code)(() => client, exports)
  return { ...exports, calls }
}
test('entity edit preserves existing conf unless complete replacement is explicitly selected', () => {
  const { entityEditPayload } = entities()
  assert.deepEqual(entityEditPayload({ type: 'password', conf: 'stale secret', replaceConf: false }, true), { type: 'password' })
  assert.deepEqual(entityEditPayload({ type: 'password', conf: 'new secret', replaceConf: true }, true),
    { type: 'password', conf: 'new secret', replaceConf: true })
  assert.throws(() => entityEditPayload({ type: 'password', conf: '', replaceConf: true }, true))
  assert.throws(() => entityEditPayload({ conf: 'password=****', replaceConf: true }, true))
})
test('association API encodes each path segment and sends explicit non-atomic requestor update', async () => {
  const api = entities()
  const payload = { permissions: ['enroll_cert'], profiles: ['tls'], confirmNonAtomic: true }
  await api.requestorApi.updateForCa('requestor/one', 'ca one', payload)
  await api.profileApi.associationsForCa('ca one')
  await api.publisherApi.removeFromCa('pub/one', 'ca one')
  assert.deepEqual(api.calls, [
    ['put', '/api/requestor/requestor%2Fone/ca/ca%20one', payload],
    ['get', '/api/profile/ca/ca%20one/associations'],
    ['delete', '/api/publisher/pub%2Fone/ca/ca%20one'],
  ])
})
test('creating an entity still supports types whose configuration is optional', () => {
  const { entityEditPayload } = entities()
  assert.deepEqual(entityEditPayload({ name: 'software', type: 'software' }, false),
    { name: 'software', type: 'software' })
  assert.deepEqual(entityEditPayload({ name: 'software', type: 'software', conf: '' }, false),
    { name: 'software', type: 'software', conf: '' })
})
