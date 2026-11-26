// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import { canUser, landingPath, enrollmentOptions } from '../src/access-policy.ts'

test('single platform resource readers land on the page they can actually open', () => {
  for(const [permission,path] of [['SIGNER_READ','/signer'],['PUBLISHER_READ','/publisher'],['REQUESTOR_READ','/requestor'],['PROFILE_READ','/profile'],['KEYPAIRGEN_READ','/keypairgen'],['USER_READ','/access/users'],['DBSCHEMA_READ','/dbschema'],['CA_CREATE_ROOT','/ca']])
    assert.equal(landingPath({roles:['CUSTOM'],permissions:[permission]}),path)
})

const user = { username: 'alice', roles: ['CA_ADMIN','CERT_OPERATOR'], permissions: ['CA_READ','CA_CONFIG_UPDATE','CERT_READ','CERT_REVOKE'],
  rolePermissions: { CA_ADMIN: ['CA_READ','CA_CONFIG_UPDATE'], CERT_OPERATOR: ['CA_READ','CERT_READ','CERT_REVOKE'] },
  bindings: [{ role: 'CA_ADMIN', scope: 'NAMED_CA', caName: 'ca-a', caFingerprint: 'a', profiles: [] },
    { role: 'CERT_OPERATOR', scope: 'NAMED_CA', caName: 'ca-b', caFingerprint: 'b', profiles: [] }] }

test('CA controls use the matching role binding and reject changed identities', () => {
  assert.equal(canUser(user,'CA_CONFIG_UPDATE',{ name: 'ca-a', certificateFingerprint: 'a' }),true)
  assert.equal(canUser(user,'CA_CONFIG_UPDATE',{ name: 'ca-b', certificateFingerprint: 'b' }),false)
  assert.equal(canUser(user,'CERT_REVOKE','ca-a'),false)
  assert.equal(canUser(user,'CERT_REVOKE','ca-b'),true)
  assert.equal(canUser(user,'CA_CONFIG_UPDATE',{ name: 'ca-a', certificateFingerprint: 'replacement' }),false)
  assert.equal(canUser(null,'CA_READ'),false)
})
test('requester grants require allowed profiles and do not provide keygen or deletion', () => {
  const requester={ username:'r',roles:['CERT_REQUESTER'],permissions:['CERT_ISSUE','CERT_READ'],
    rolePermissions:{ CERT_REQUESTER:['CERT_ISSUE','CERT_READ'] },
    bindings:[{ role:'CERT_REQUESTER',scope:'ALL_CAS',profiles:['tls'],allProfiles:false }] }
  assert.equal(canUser(requester,'CERT_ISSUE','ca-a','tls'),true)
  assert.equal(canUser(requester,'CERT_ISSUE','ca-a','ca'),false)
  assert.equal(canUser(requester,'CERT_KEYGEN','ca-a','tls'),false)
  assert.equal(canUser(requester,'CERT_DELETE','ca-a'),false)
})
test('each restricted role has a usable landing page and forced change wins', () => {
  assert.equal(landingPath({ roles:['CERT_REQUESTER'],permissions:['CERT_READ','CA_READ'] }),'/cert')
  assert.equal(landingPath({ roles:['USER_ADMIN'],permissions:['USER_READ'] }),'/access/users')
  assert.equal(landingPath({ roles:['AUDITOR'],permissions:['AUDIT_READ'] }),'/audit')
  assert.equal(landingPath({ roles:['CA_ADMIN'],permissions:['CA_READ','CA_CONFIG_UPDATE'] }),'/ca')
  assert.equal(landingPath({ roles:[],permissions:[] }),'/account')
  assert.equal(landingPath({ roles:['SUPER_ADMIN'],permissions:['CA_READ'],passwordChangeRequired:true }),'/account/password')
})

test('custom role landing uses capabilities and all issuance operations enforce profile grants', () => {
  assert.equal(landingPath({ roles:['CUSTOM_CA'],permissions:['CA_READ','CA_CONFIG_UPDATE'] }),'/ca')
  const custom={ roles:['CUSTOM_KEYS'],permissions:['CA_READ','CERT_READ','CERT_KEYGEN','CERT_CROSS'],
    rolePermissions:{ CUSTOM_KEYS:['CA_READ','CERT_READ','CERT_KEYGEN','CERT_CROSS'] },
    bindings:[{ role:'CUSTOM_KEYS',scope:'ALL_CAS',profiles:['tls'],allProfiles:false }] }
  for(const permission of ['CERT_KEYGEN','CERT_CROSS']) {
    assert.equal(canUser(custom,permission,'ca-a','tls'),true)
    assert.equal(canUser(custom,permission,'ca-a','root'),false)
  }
  assert.equal(canUser({...custom,rolePermissions:{ CUSTOM_KEYS:[] }},'CERT_KEYGEN','ca-a','tls'),false)
})

test('issuance dropdowns keep CSR and key generation CA/profile scopes separate', () => {
  const user={roles:['CSR_TEAM','KEY_TEAM'],permissions:['CERT_ISSUE','CERT_KEYGEN'],
    rolePermissions:{CSR_TEAM:['CERT_ISSUE'],KEY_TEAM:['CERT_KEYGEN']},
    bindings:[{role:'CSR_TEAM',scope:'NAMED_CA',caName:'ca-a',caFingerprint:'a',profiles:['tls']},
      {role:'KEY_TEAM',scope:'NAMED_CA',caName:'ca-b',caFingerprint:'b',profiles:['client']}]}
  const cas=[{name:'ca-a',certificateFingerprint:'a'},{name:'ca-b',certificateFingerprint:'b'}]
  assert.deepEqual(enrollmentOptions(user,'CERT_ISSUE',cas,'ca-a',['tls','client']),{cas:[cas[0]],profiles:['tls']})
  assert.deepEqual(enrollmentOptions(user,'CERT_KEYGEN',cas,'ca-a',['tls','client']),{cas:[cas[1]],profiles:[]})
  assert.deepEqual(enrollmentOptions(user,'CERT_KEYGEN',cas,'ca-b',['tls','client']),{cas:[cas[1]],profiles:['client']})
})
