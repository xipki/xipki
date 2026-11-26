// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import {landingPath} from '../src/access-policy.ts'
import {navigationPermission, selectedNavigationKey, visibleNavigationGroups} from '../src/navigation.ts'

const keys = user => visibleNavigationGroups(user).flatMap(group => group.items.map(item => item.key))

test('navigation groups hide unavailable sections and honor password change', () => {
  assert.deepEqual(keys({roles:['CUSTOM'],permissions:['CA_READ','PROFILE_READ','AUDIT_READ']}),
    ['/dashboard','/ca','/profile','/audit'])
  const caGroups = visibleNavigationGroups({roles:['CUSTOM'],permissions:['CA_READ','PROFILE_READ']})
  assert.deepEqual(caGroups.map(group => group.label), ['Operations','CA configuration'])
  assert.deepEqual(caGroups.map(group => group.items.map(item => item.label)), [['Dashboard','CA Management'],['Cert Profiles']])
  assert.deepEqual(visibleNavigationGroups({roles:['CUSTOM'],permissions:['AUDIT_READ']}).map(group => group.label),
    ['Administration'])
  assert.deepEqual(visibleNavigationGroups({roles:['CUSTOM'],permissions:['CA_READ'],passwordChangeRequired:true}),[])
})

test('CA enrollment and certificate issuance have usable navigation and landing routes', () => {
  for (const permission of ['CA_ISSUE_SUBCA']) {
    const user={roles:['CUSTOM'],permissions:[permission]}
    assert.ok(keys(user).includes('/ca'))
    assert.equal(landingPath(user),'/ca')
    assert.ok(navigationPermission('/ca').split('|').includes(permission))
  }
  for (const permission of ['CERT_ISSUE','CERT_KEYGEN','CERT_CROSS']) {
    const user={roles:['CUSTOM'],permissions:[permission]}
    assert.deepEqual(keys(user),['/cert/enroll'])
    assert.equal(landingPath(user),'/cert/enroll')
    assert.ok(navigationPermission('/cert/enroll').split('|').includes(permission))
  }
})

test('certificate management is a peer navigation group with only permitted destinations', () => {
  const reader = visibleNavigationGroups({roles:['CUSTOM'],permissions:['CERT_READ']})
  assert.deepEqual(reader.map(group=>group.label), ['Certificate Management'])
  assert.deepEqual(reader[0].items.map(item=>item.key), ['/cert'])

  const operator = visibleNavigationGroups({roles:['CUSTOM'],permissions:['CERT_READ','CERT_ISSUE','CRL_READ']})
  assert.deepEqual(operator[0].items.map(item=>item.key), ['/cert','/cert/enroll','/crl'])

  const crlReader = visibleNavigationGroups({roles:['CUSTOM'],permissions:['CRL_READ']})
  assert.deepEqual(crlReader[0].items.map(item=>item.key), ['/crl'])
})

test('nested routes select their matching navigation item', () => {
  assert.equal(selectedNavigationKey('/cert/enroll'),'/cert/enroll')
  assert.equal(selectedNavigationKey('/cert/example'),'/cert')
  assert.equal(selectedNavigationKey('/ca/demo-ca'),'/ca')
  assert.equal(selectedNavigationKey('/ca/operations/enrollments'),'/ca')
  assert.equal(selectedNavigationKey('/access/roles'),'/access/roles')
  assert.equal(selectedNavigationKey('/ca-options'),undefined)
})
