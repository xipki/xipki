// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import { togglePermission } from '../src/pages/access/roles-model.ts'

const catalog=[{code:'CA_READ',dependencies:[]},{code:'CERT_READ',dependencies:['CA_READ']},
  {code:'CERT_ISSUE',dependencies:['CERT_READ']},{code:'SHARED_READ',dependencies:['CA_READ']}]
test('permission selection adds required reads and removes dependent writes transitively', () => {
  assert.deepEqual(togglePermission([], 'CERT_ISSUE',true,catalog),['CA_READ','CERT_ISSUE','CERT_READ'])
  assert.deepEqual(togglePermission(['CA_READ','CERT_READ','CERT_ISSUE','SHARED_READ'],'CERT_READ',false,catalog),['CA_READ','SHARED_READ'])
  assert.deepEqual(togglePermission(['CA_READ','CERT_READ','CERT_ISSUE'],'CA_READ',false,catalog),[])
})
