// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import * as availability from '../src/ca-availability.ts'
const require = createRequire(import.meta.url)
const ts = require('typescript')
const code = ts.transpileModule(readFileSync(new URL('../src/api/cert.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
}).outputText
function certificateApi() {
  const exports = {}, calls = []
  const client = Object.fromEntries(['get', 'post', 'delete'].map(method => [method,
    async (...args) => { calls.push([method, ...args]); return { data: { success: true } } },
  ]))
  new Function('require', 'exports', code)(name => name === '../ca-availability' ? availability : client, exports)
  return { ...exports, calls }
}
test('only active and successfully started CA can be selected for issuance', () => {
  const { canIssueFromCa } = certificateApi()
  assert.equal(canIssueFromCa({ status: 'active', runtimeState: 'started' }), true)
  assert.equal(canIssueFromCa({ status: 'active', runtimeState: 'failed' }), false)
  assert.equal(canIssueFromCa({ status: 'inactive', runtimeState: 'started' }), false)
  assert.equal(canIssueFromCa({ status: 'active' }), false)
})
test('protected key delivery keeps subject/password in JSON and allows one bounded heavy request', async () => {
  const { certApi, calls } = certificateApi()
  const data = { ca: 'ca one', profile: 'tls', subject: 'CN=private subject', downloadPassword: 'private-test-password' }
  await certApi.enrollKeyDownload(data)
  assert.deepEqual(calls, [['post', '/api/cert/enroll-key/download', data, { responseType: 'blob', timeout: 120000 }]])
})
test('certificate paths encode each component and optional revoke time is forwarded', async () => {
  const { certApi, calls } = certificateApi()
  await certApi.revoke('ca one', 'a/b', 'certificateHold', '2026-01-01T00:00:00Z')
  assert.equal(certApi.downloadUrl('ca one', 'a/b'), '/api/cert/ca%20one/a%2Fb/download?format=pem')
  assert.deepEqual(calls, [['post', '/api/cert/ca%20one/a%2Fb/revoke', { reason: 'certificateHold', invalidityTime: '2026-01-01T00:00:00Z' }]])
})
