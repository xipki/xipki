// License Apache License 2.0

import test from 'node:test'
import assert from 'node:assert/strict'
import { enrollmentActions, newIdempotencyKey, publicPem } from '../src/pages/ca/enrollment-policy.ts'
import { canUser } from '../src/access-policy.ts'
import { caForest } from '../src/pages/ca/ca-chain.ts'

test('uncertain issuance exposes reconciliation and certificate recovery without resending',()=>{
  assert.deepEqual(enrollmentActions('RESULT_UNKNOWN','REGISTER_CA'),['reconcile','certificate'])
  assert.deepEqual(enrollmentActions('ISSUING','SIGN_ONLY'),['reconcile'])
  assert.deepEqual(enrollmentActions('REGISTERING','REGISTER_CA'),['reconcile'])
  assert.deepEqual(enrollmentActions('PREPARED','SIGN_ONLY'),['issue','cancel'])
  assert.deepEqual(enrollmentActions('CERTIFICATE_READY','SIGN_ONLY'),[])
  assert.deepEqual(enrollmentActions('CERTIFICATE_READY','REGISTER_CA'),['register'])
})
test('CSR download contains base64 PEM rather than raw DER inside PEM markers',()=>{
  assert.equal(publicPem('AQIDBA==','CERTIFICATE REQUEST'),'-----BEGIN CERTIFICATE REQUEST-----\nAQIDBA==\n-----END CERTIFICATE REQUEST-----\n')
})
test('CA enrollment idempotency key works without randomUUID on HTTP LAN',()=>{
  const random={getRandomValues(bytes){bytes.set(Array.from({length:16},(_,index)=>index));return bytes}}
  assert.equal(newIdempotencyKey(random),'000102030405060708090a0b0c0d0e0f')
})
test('CA hierarchy uses verified certificate fingerprints and keeps ambiguous parents as roots',()=>{
  const root={name:'root',certificateFingerprint:'r',chainStatus:'verified'}
  const sub={name:'sub',certificateFingerprint:'s',parentCertificateFingerprint:'r',chainStatus:'verified'}
  const fake={name:'same issuer text',certificateFingerprint:'f',parentCertificateFingerprint:'r',chainStatus:'unverified'}
  assert.deepEqual(caForest([root,sub,fake]).map(n=>[n.key,n.children.map(c=>c.key)]),[['root',['sub']],['same issuer text',[]]])
  assert.equal(caForest([root,{...root,name:'duplicate'},sub]).length,3)
  assert.equal(caForest([{...root,parentCertificateFingerprint:'s'},sub]).length,2)
})
test('SubCA UI respects the same profile-bound grant as the backend',()=>{
  const user={roles:['SUBCA'],permissions:['CA_ISSUE_SUBCA'],rolePermissions:{SUBCA:['CA_ISSUE_SUBCA']},
    bindings:[{role:'SUBCA',scope:'NAMED_CA',caName:'root',caFingerprint:'f',profiles:['issuing']} ]}
  assert.equal(canUser(user,'CA_ISSUE_SUBCA',{name:'root',certificateFingerprint:'f'},'issuing'),true)
  assert.equal(canUser(user,'CA_ISSUE_SUBCA',{name:'root',certificateFingerprint:'f'},'other'),false)
})
