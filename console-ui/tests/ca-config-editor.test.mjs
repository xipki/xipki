// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { translate } from '../src/i18n/catalog.ts'
import { configurationChanges } from '../src/pages/ca/ca-config-policy.ts'
const require = createRequire(import.meta.url)
const ts = require('typescript')
const options = { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true }
const compile = path => ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), { compilerOptions: options }).outputText
const editorCode = compile('../src/pages/ca/CaConfigEditor.tsx')
const fieldsCode = compile('../src/pages/ca/CaConfigFields.tsx')
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }
const response = data => ({ data: { data } })

// Exercise the component's effects and event handlers without adding a DOM/test-renderer dependency.
// API and Ant Design form are boundary doubles; config payload/value conversion runs unchanged.
function editor() {
  let cursor = 0, dirty = false, tree, props = { name: 'first', onSaved: () => saved++ }, saved = 0
  const slots = [], effects = [], requests = [], writes = [], notices = [], form = {
    values: {}, resetFields() { this.values = {} }, setFieldsValue(values) { this.values = { ...this.values, ...values } },
    async validateFields() { return this.values },
  }
  const react = {
    useState(initial) { const i = cursor++; slots[i] ??= { value: initial }; return [slots[i].value, value => { slots[i].value = typeof value === 'function' ? value(slots[i].value) : value; dirty = true }] },
    useRef(initial) { const i = cursor++; return slots[i] ??= { current: initial } },
    useEffect(fn, deps) { const i = cursor++; const old = slots[i]; if (!old || deps.some((value, n) => value !== old.deps[n])) { slots[i] = { deps, cleanup: old?.cleanup }; effects.push(() => { slots[i].cleanup?.(); slots[i].cleanup = fn() }) } },
  }
  const jsx = (type, props) => ({ type, props })
  const antd = {
    Alert: 'Alert', Button: 'Button', Card: 'Card', Checkbox: 'Checkbox', Collapse: 'Collapse', Input: { TextArea: 'TextArea' },
    Form: Object.assign(() => {}, { useForm: () => [form], useWatch: name => form.values[name], Item: 'FormItem' }),
    message: { success: text => notices.push(text), error: text => notices.push(text) },
  }
  const fields = {}; new Function('require', 'exports', fieldsCode)(() => antd, fields)
  const api = {
    config(name) { const request = deferred(); requests.push({ name, ...request }); return request.promise },
    async update(name, body) { writes.push({ name, body }); return {} },
  }
  const exports = {}
  new Function('require', 'exports', editorCode)(id => {
    if (id === 'react') return react
    if (id === 'react/jsx-runtime') return { jsx, jsxs: jsx, Fragment: 'Fragment' }
    if (id === 'antd') return antd
    if (id === '../../i18n') return { useI18n: () => ({ t: key => translate('en-US', key) }) }
    if (id.endsWith('/ca')) return { caApi: api }
    if (id === './CaConfigFields') return fields
    if (id === './CaKeyFields') return { default: 'CaKeyFields' }
    if (id === '../../auth') return { useCan: () => () => true }
    if (id === '../../components/Reauthentication') return { useReauthentication: () => ({ authorize: (_,run) => {void run()},dialog:null }) }
    if (id === './ca-config-policy') return { configurationChanges }
    throw new Error(`Unexpected dependency ${id}`)
  }, exports)
  function render() { cursor = 0; dirty = false; tree = exports.default(props); while (effects.length) effects.shift()() }
  function elements(node) { return !node || typeof node !== 'object' ? [] : [node, ...[node.props?.children].flat(Infinity).flatMap(child => elements(child))] }
  async function flush() { for (let n = 0; n < 5; n++) { await new Promise(resolve => setImmediate(resolve)); if (dirty) render() } }
  const button = text => elements(tree).find(node => node.type === 'Button' && node.props.children === text)
  render()
  return { form, requests, writes, notices, button, flush, saved: () => saved,
    changeName(name) { props = { ...props, name }; render() },
    async load(data) { requests.at(-1).resolve(response(data)); await flush() },
    async save() { button('Save configuration')?.props.onClick(); await flush() },
  }
}

test('CA form keeps ordinary fields out of advanced configuration', async () => {
  const ui = editor()
  await ui.load({
    status: 'inactive', maxValidity: '90d', permissions: ['all'],
    saveCert: true, saveKeypair: false, serialNoLen: 20,
    crlControl: 'interval.hours=24',
  })
  assert.deepEqual(JSON.parse(ui.form.values.advanced), {
    crlControl: 'interval.hours=24',
  })
})

test('failed initial configuration load prevents a write until explicit retry succeeds', async () => {
  const ui = editor()
  ui.requests[0].reject(new Error('unavailable')); await ui.flush()
  await ui.save()
  assert.equal(ui.writes.length, 0, 'a failed GET must never enable saving an empty configuration')
  const retry = ui.button('Retry loading configuration')
  assert.ok(retry, 'load failure must offer a retry')
  retry.props.onClick(); await ui.flush()
  await ui.load({ status: 'inactive', maxValidity: '90d' })
  ui.form.values.maxValidity='91d'
  await ui.save()
  assert.equal(ui.writes[0].body.maxValidity, '91d')
})

test('changing CA clears the old form and ignores an earlier outstanding configuration response', async () => {
  const ui = editor()
  await ui.load({ maxValidity: '90d' })
  ui.form.values.key = { password: 'old-password', pkcs12: 'old-key' }
  ui.form.values.replaceSigner = true
  ui.changeName('second'); await ui.flush()
  assert.deepEqual(ui.form.values, {}, 'the next CA must not inherit old fields or replacement secrets')
  await ui.save(); assert.equal(ui.writes.length, 0)
  ui.changeName('third'); await ui.flush()
  ui.requests[1].resolve(response({ maxValidity: '123d' })); await ui.flush()
  assert.deepEqual(ui.form.values, {})
  await ui.load({ maxValidity: '45d' })
  ui.form.values.maxValidity='46d'
  await ui.save()
  assert.equal(ui.writes[0].name, 'third')
  assert.equal(ui.writes[0].body.maxValidity, '46d')
})

test('successful replacement clears all entered material and confirmation before reloading safe configuration', async () => {
  const ui = editor()
  await ui.load({ maxValidity: '90d' })
  Object.assign(ui.form.values, { replaceSigner: true, key: { mode: 'pkcs12', pkcs12: 'private-key', password: 'private-password' },
    replaceCertificates: true, encodedCert: 'replacement-cert', encodedCertchain: '["issuer-cert"]' })
  await ui.save()
  assert.equal(ui.writes[0].body.key.password, 'private-password')
  for (const field of ['key', 'replaceSigner', 'replaceCertificates', 'encodedCert', 'encodedCertchain']) assert.equal(ui.form.values[field], undefined, `${field} must be cleared after success`)
  assert.equal(ui.requests.length, 2, 'success must reload configuration from the server')
  assert.equal(ui.saved(), 1)
  await ui.save(); assert.equal(ui.writes.length, 1, 'do not save again while the safe reload is pending')
  await ui.load({ maxValidity: '91d', signerConf: 'must-not-display', key: { password: 'must-not-display' } })
  assert.equal(ui.form.values.maxValidity, '91d')
  assert.equal(ui.form.values.key, undefined)
})
