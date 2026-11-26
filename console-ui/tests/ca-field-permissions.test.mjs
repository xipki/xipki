// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import { configurationChanges } from '../src/pages/ca/ca-config-policy.ts'

test('ordinary CA editor submits only changed authorized fields and preserves read-only values', () => {
  const initial={status:'active',maxValidity:'365d',permissions:['all'],saveKeypair:false,caUris:{ocspUris:['https://ocsp.test']}}
  const can=permission => permission==='CA_CONFIG_UPDATE'
  assert.deepEqual(configurationChanges(initial,{...initial,maxValidity:'30d'},can),{maxValidity:'30d'})
  for(const next of [{status:'inactive'},{saveKeypair:true},{permissions:[]},{crlSignerName:'NULL'},{key:{}},{encodedCert:'cert'}])
    assert.throws(() => configurationChanges(initial,{...initial,maxValidity:'30d',...next},can),/Permission denied/)
  assert.throws(() => configurationChanges(initial,initial,can),/No configuration changes/)
})
test('explicit clearing and structured replacements use their own permissions', () => {
  assert.deepEqual(configurationChanges({crlSignerName:'old'},{crlSignerName:'NULL'},p => p==='CA_CRYPTO_CONFIG_UPDATE'),{crlSignerName:'NULL'})
  assert.deepEqual(configurationChanges({},{replaceSigner:true,key:{mode:'PKCS11'}},p => p==='CA_KEY_REPLACE'),{replaceSigner:true,key:{mode:'PKCS11'}})
  assert.throws(() => configurationChanges({},{unknown:true},()=>true),/Unsupported configuration field/)
  assert.throws(() => configurationChanges({},{replaceSigner:false},()=>true),/No configuration changes/)
})
