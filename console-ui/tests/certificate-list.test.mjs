// License Apache License 2.0

import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import dayjs from 'dayjs'
import { revocationDisplay } from '../src/pages/cert/certificate-revocation.ts'
import { certificateOrder, certificatePage, certificateQueryTime, collectCertificatePages, localCertificateTime } from '../src/pages/cert/certificate-list.ts'

const require = createRequire(import.meta.url)
const ts = require('typescript')
const deferred = () => {
  let resolve
  const promise = new Promise(done => { resolve = done })
  return { promise, resolve }
}

test('certificate list uses the same local clock for display and UTC query boundaries', () => {
  const previousZone = process.env.TZ
  process.env.TZ = 'Asia/Shanghai'
  try {
    const selected = dayjs('2026-10-30T08:30:42')
    assert.equal(localCertificateTime('2026-10-30T00:30:00Z'), '2026-10-30 08:30')
    assert.equal(certificateQueryTime(selected), '2026-10-30T00:30:00.000Z')
    assert.equal(certificateQueryTime(null), undefined)
    assert.equal(localCertificateTime('invalid'), 'invalid')
  } finally {
    if (previousZone === undefined) delete process.env.TZ
    else process.env.TZ = previousZone
  }
})

test('certificate sort and loaded-result pagination preserve query order and clamp the last page', () => {
  assert.equal(certificateOrder('notBefore', 'desc'), 'notBefore-desc')
  assert.equal(certificateOrder('notAfter', 'asc'), 'notAfter')
  assert.equal(certificateOrder('subject', 'desc'), 'subject-desc')

  const rows = Array.from({ length: 45 }, (_, index) => index + 1)
  assert.deepEqual(certificatePage(rows, 3, 20), { current: 3, items: [41, 42, 43, 44, 45] })
  assert.deepEqual(certificatePage(rows.slice(0, 7), 3, 20), { current: 1, items: rows.slice(0, 7) })
  assert.deepEqual(certificatePage([], 2, 20), { current: 1, items: [] })
})

test('certificate search merges cursor pages before applying the global sort and limit', async () => {
  const list = await import('../src/pages/cert/certificate-list.ts')
  assert.equal(typeof list.collectCertificatePages, 'function')
  const requests = []
  const query = { ca: 'test-ca', orderBy: 'notBefore-desc', limit: 1 }
  const response = (data, cursor) => ({ data: { data }, headers: cursor ? { 'x-next-cursor': cursor } : {} })
  const rows = [
    { serialNumber: '1', subject: 'CN=Older', notBefore: '2025-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' },
    { serialNumber: '2', subject: 'CN=Newer', notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' },
  ]
  const fetch = async params => {
    requests.push(params)
    return requests.length === 1 ? response([rows[0]], 'next-page') : response([rows[1]])
  }

  const result = await list.collectCertificatePages(query, fetch, () => true)

  assert.deepEqual(requests.map(request => request.cursor), [undefined, 'next-page'])
  assert.ok(requests.every(request => request.paged === true))
  assert.deepEqual(result, [rows[1]])
})

test('cancelling a paged certificate search stops after the current batch', async () => {
  let active = true
  let calls = 0
  const result = await collectCertificatePages({ ca: 'test-ca', orderBy: 'notBefore' }, async () => {
    calls++
    active = false
    return { data: { data: [] }, headers: { 'x-next-cursor': 'next-page' } }
  }, () => active)
  assert.equal(result, undefined)
  assert.equal(calls, 1)
})

test('a later certificate mutation refresh supersedes a list request still in flight', async () => {
  const source = readFileSync(new URL('../src/pages/cert/CertList.tsx', import.meta.url), 'utf8')
  const code = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020,
    jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true,
  } }).outputText
  const slots = [], effects = [], requests = []
  let cursor = 0, dirty = false, tree
  const react = {
    useState(initial) {
      const index = cursor++
      slots[index] ??= { value: initial }
      return [slots[index].value, value => {
        slots[index].value = typeof value === 'function' ? value(slots[index].value) : value
        dirty = true
      }]
    },
    useRef(initial) { const index = cursor++; return slots[index] ??= { current: initial } },
    useEffect(run, deps) {
      const index = cursor++, previous = slots[index]
      if (!previous || deps.some((value, position) => value !== previous.deps[position])) {
        slots[index] = { deps, cleanup: previous?.cleanup }
        effects.push(() => { slots[index].cleanup?.(); slots[index].cleanup = run() })
      }
    },
  }
  const jsx = (type, props) => ({ type, props })
  const antd = Object.fromEntries(['Alert', 'Button', 'DatePicker', 'Input', 'InputNumber',
    'Pagination', 'Segmented', 'Select', 'Table', 'Tag'].map(name => [name, name]))
  antd.Typography = { Title: 'Title', Text: 'Text' }
  antd.message = { error() {} }
  const certApi = {
    list(params) { const request = deferred(); requests.push({ ...request, params }); return request.promise },
    downloadUrl: () => '/download',
  }
  const response = data => ({ data: { data } })
  const exports = {}
  new Function('require', 'exports', 'window', code)(id => {
    if (id === 'react') return react
    if (id === 'react/jsx-runtime') return { jsx, jsxs: jsx }
    if (id === 'antd') return antd
    if (id === '@ant-design/icons') return new Proxy({}, { get: (_, name) => name })
    if (id === 'react-router-dom') return { useNavigate: () => () => {} }
    if (id === '../../i18n') return { useI18n: () => ({ t: value => value }) }
    if (id === '../../api/cert') return { certApi }
    if (id === '../../api/ca') return { caApi: { list: async () => response([{ name: 'test-ca' }]) } }
    if (id === '../../ca-availability') return { operationalCaNames: cas => cas.map(ca => ca.name) }
    if (id === '../../auth') return { useCan: () => () => true }
    if (id === './certificate-list') return { certificateOrder, certificatePage, certificateQueryTime, collectCertificatePages, localCertificateTime }
    if (id === './certificate-validity') return { certificateValidity: () => 'valid' }
    if (id === './certificate-revocation') return { revocationDisplay }
    if (id === './CertDetailDrawer') return 'CertDetailDrawer'
    if (id === './CertList.css') return {}
    throw new Error(`Unexpected dependency: ${id}`)
  }, exports, { setInterval: () => 1, clearInterval() {} })
  const render = () => {
    cursor = 0
    dirty = false
    tree = exports.default()
    while (effects.length) effects.shift()()
  }
  const nodes = value => value && typeof value === 'object'
    ? [value, ...[value.props?.children].flat(Infinity).flatMap(nodes)] : []
  const flush = async () => {
    for (let turn = 0; turn < 8; turn++) {
      await new Promise(done => setImmediate(done))
      if (dirty) render()
    }
  }
  const row = subject => ({ ca: 'test-ca', serialNumber: '1', subject,
    notBefore: '2026-01-01T00:00:00Z', notAfter: '2027-01-01T00:00:00Z' })

  render()
  await flush()
  assert.equal(requests.length, 1)
  assert.equal(requests[0].params.orderBy, 'notBefore-desc')
  requests[0].resolve(response([row('original')]))
  await flush()
  nodes(tree).find(node => node.type === 'Input' && node.props?.['aria-label'] === 'Subject DN filter')
    .props.onChange({ target: { value: 'CN=unsubmitted' } })
  await flush()
  const initialTable = nodes(tree).find(node => node.type === 'Table')
  const actions = initialTable.props.columns.find(column => column.title === 'Actions').render(null, row('original'))
  nodes(actions).find(node => node.type === 'Button' && node.props?.['aria-label'] === 'Certificate Detail').props.onClick()
  await flush()

  nodes(tree).find(node => node.type === 'CertDetailDrawer').props.onChanged()
  await flush()
  nodes(tree).find(node => node.type === 'CertDetailDrawer').props.onChanged()
  await flush()
  assert.equal(requests.length, 3, 'the second mutation must trigger a new list request')
  assert.equal(requests[2].params.subject, undefined, 'mutation refresh must reuse the applied filters')

  requests[2].resolve(response([row('latest')]))
  await flush()
  requests[1].resolve(response([row('stale')]))
  await flush()
  assert.equal(nodes(tree).find(node => node.type === 'Table').props.dataSource[0].subject, 'latest')

  const table = () => nodes(tree).find(node => node.type === 'Table').props
  assert.deepEqual(table().columns.slice(0, 3).map(column => column.key || column.dataIndex),
    ['rowNumber', 'serialNumber', 'subject'])
  assert.deepEqual(table().columns.filter(column => column.sorter).map(column => column.dataIndex),
    ['subject', 'notBefore', 'notAfter'])
  const rowNumber = index => table().columns[0].render(undefined, table().dataSource[index], index)
  assert.equal(rowNumber(0), 1)
  assert.equal(table().columns.find(column => column.dataIndex === 'notBefore').sortOrder,
    'descend')
  assert.deepEqual(table().sortDirections, ['descend', 'ascend', 'descend'])
  const sort = (field, order) => table().onChange({}, {}, { field, order }, { action: 'sort' })
  sort('notBefore', 'ascend')
  await flush()
  assert.equal(requests[3].params.orderBy, 'notBefore')
  assert.equal(requests[3].params.subject, undefined, 'sorting must retain applied filters')
  sort('notAfter', 'descend')
  await flush()
  assert.equal(requests[4].params.orderBy, 'notAfter-desc')
  assert.equal(table().columns.find(column => column.dataIndex === 'notBefore').sortOrder, null)
  assert.equal(table().columns.find(column => column.dataIndex === 'notAfter').sortOrder,
    'descend')
  const rows = Array.from({ length: 25 }, (_, index) => ({
    ...row('sorted-' + index), serialNumber: String(index + 1),
  }))
  requests[4].resolve(response(rows))
  await flush()
  requests[3].resolve(response([row('outdated sort')]))
  await flush()
  assert.equal(table().dataSource[0].subject, 'sorted-0')
  nodes(tree).find(node => node.type === 'Pagination').props.onChange(2, 20)
  await flush()
  assert.equal(table().dataSource[0].subject, 'sorted-20')
  assert.equal(rowNumber(0), 21)
  assert.equal(rowNumber(4), 25)
  sort('notAfter', 'ascend')
  await flush()
  assert.equal(requests[5].params.orderBy, 'notAfter')
  requests[5].resolve(response(rows))
  await flush()
  assert.equal(nodes(tree).find(node => node.type === 'Pagination').props.current, 1)
  assert.equal(rowNumber(0), 1)
  sort('notAfter', 'descend')
  await flush()
  assert.equal(requests[6].params.orderBy, 'notAfter-desc')
  nodes(tree).find(node => node.type === 'CertDetailDrawer').props.onChanged()
  await flush()
  assert.equal(requests[7].params.orderBy, 'notAfter-desc', 'refresh keeps the latest sort')
  requests[7].resolve(response(rows))
  requests[6].resolve(response([row('old sort')]))
  await flush()
  assert.equal(table().dataSource[0].subject, 'sorted-0')
})
