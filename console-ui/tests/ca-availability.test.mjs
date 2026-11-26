// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import { operationalCaNames, canIssueFromCa } from '../src/ca-availability.ts'

test('certificate, CRL and republish choices skip inactive, failed and unknown states without widening grants', () => {
  const cas=[{name:'inactive',status:'inactive',runtimeState:'inactive'},
    {name:'failed',status:'active',runtimeState:'failed'}, {name:'missing',status:'active'},
    {name:'running',status:'active',runtimeState:'started'}, {name:'other',status:'active',runtimeState:'started'}]
  for(const permission of ['CERT_READ','CRL_READ','CERT_REPUBLISH'])
    assert.deepEqual(operationalCaNames(cas,permission,(p,ca)=>p===permission && ca.name!=='other'),['running'])
  assert.deepEqual(operationalCaNames(cas.slice(0,3),'CERT_READ',()=>true),[])
})
test('historical reads do not hide expired or revoked CAs when their runtime is available', () => {
  const ca={name:'old',status:'active',runtimeState:'started',notAfter:'2020-01-01T00:00:00Z',revocationInfo:{reason:'keyCompromise'}}
  assert.deepEqual(operationalCaNames([ca],'CERT_READ',()=>true),['old'])
  assert.equal(canIssueFromCa(ca),false)
})
test('issuance requires active running unrevoked and currently valid CA', () => {
  const ca={name:'ca',status:'active',runtimeState:'started',notBefore:'2020-01-01T00:00:00Z',notAfter:'2030-01-01T00:00:00Z'}
  const now=Date.parse('2026-10-27T00:00:00Z')
  assert.equal(canIssueFromCa(ca,now),true)
  for(const change of [{status:'inactive'},{runtimeState:'failed'},{runtimeState:undefined},{revocationInfo:{reason:'certificateHold'}},
    {notBefore:'2027-01-01T00:00:00Z'},{notAfter:'2025-01-01T00:00:00Z'},{notAfter:'invalid'}])
    assert.equal(canIssueFromCa({...ca,...change},now),false)
})
