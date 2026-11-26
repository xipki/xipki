// License Apache License 2.0

import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
import { translate, normalizeLocale, resources, languages, defaultLocale, localeStorageKey } from '../src/i18n/catalog.ts'
import * as catalog from '../src/i18n/catalog.ts'

const english=Object.assign({},...Object.values(resources[defaultLocale]))

test('counted permission summaries use the language plural rules, including zero', () => {
  assert.equal(translate('en-US', '{count} permissions', {count:1}), '1 permission')
  assert.equal(translate('en-US', '{count} permissions', {count:0}), '0 permissions')
  assert.equal(translate('en-US', '{count} permissions', {count:2}), '2 permissions')
  assert.equal(translate('zh-CN', '{count} permissions', {count:1}), '1 项权限')
})

test('an additional language pack gets module lookup, English fallback and plural handling without page changes', () => {
  assert.equal(typeof catalog.createTranslationEngine, 'function', 'Translation engine must accept language packs')
  const engine=catalog.createTranslationEngine({
    'en-US': {common:{Save:'Save',Cancel:'Cancel'},access:{summary_one:'{count} permission',summary_other:'{count} permissions'}},
    'fr-FR': {common:{Save:'Enregistrer'},access:{summary_one:'{count} autorisation',summary_other:'{count} autorisations'}},
  })
  assert.equal(engine.t('Save',{lng:'fr-FR'}),'Enregistrer')
  assert.equal(engine.t('Cancel',{lng:'fr-FR'}),'Cancel')
  assert.equal(engine.t('summary',{lng:'fr-FR',count:1}),'1 autorisation')
  assert.equal(engine.t('summary',{lng:'fr-FR',count:2}),'2 autorisations')
})

test('interpolated user values stay literal and cannot become translation options or nested translations', () => {
  assert.equal(translate('zh-CN','Edit {name}',{name:'<CA> $t(Save) {count}',count:7}),'编辑 <CA> $t(Save) {count}')
  assert.equal(translate('en-US','Edit {name}',{name:'safe',lng:'zh-CN',ns:'missing',defaultValue:'wrong'}),'Edit safe')
})

test('locale selection defaults to English and accepts saved Chinese', () => {
  for (const value of [null, '', 'fr-FR', 'en-US', 'constructor']) assert.equal(normalizeLocale(value), 'en-US')
  assert.equal(normalizeLocale('zh-CN'), 'zh-CN')
})

test('translations preserve dynamic names, zero counts, and diagnostic text', () => {
  assert.equal(translate('en-US', 'Delete {name}?', { name: 'root-ca' }), 'Delete root-ca?')
  assert.equal(translate('zh-CN', 'Delete {name}?', { name: 'root-ca' }), '确认删除 root-ca？')
  assert.equal(translate('zh-CN', '{count} CAs configured', { count: 0 }), '当前已有 0 个 CA')
  for (const text of ['HSM error: CKR_DEVICE_ERROR', 'HSM error: $t(Save) {diagnostic}', 'toString', '__proto__', 'constructor', 'RSA3072', 'enroll_cert']) {
    assert.equal(translate('zh-CN', text), text)
  }
  // A substituted value must not itself be reinterpreted as a placeholder.
  assert.equal(translate('zh-CN', 'Edit {name}', { name: '{name}' }), '编辑 {name}')
})

test('every registered language has complete module dictionaries, valid plurals and matching placeholders', () => {
  const placeholders = text => [...text.matchAll(/\{(\w+)\}/g)].map(match => match[1]).sort()
  const baseKey=key=>key.replace(/_(zero|one|two|few|many|other)$/,'')
  for(const [locale,definition] of Object.entries(languages)) {
    assert.ok(definition.label.trim(),locale)
    assert.ok(definition.antd.locale,locale+' component locale')
    assert.ok(definition.dayjs,locale+' date locale')
    assert.deepEqual(Object.keys(resources[locale]).sort(),Object.keys(resources[defaultLocale]).sort(),locale)
    const seen=new Set()
    for(const [namespace,messages] of Object.entries(resources[locale])) {
      const source=resources[defaultLocale][namespace]
      for(const [key,value] of Object.entries(messages)) {
        assert.equal(seen.has(key),false,`${locale}: ambiguous duplicate key ${key}`);seen.add(key)
        assert.ok(typeof value==='string' && value.trim(),`${locale}/${namespace}: ${key}`)
        assert.ok(Object.hasOwn(source,key) || Object.hasOwn(source,baseKey(key)),`${locale}: unknown key ${key}`)
        assert.deepEqual(placeholders(value),placeholders(source[key] || source[baseKey(key)]),`${locale}: ${key}`)
      }
      for(const key of Object.keys(source).filter(key=>key===baseKey(key))) {
        assert.ok(Object.hasOwn(messages,key),`${locale}/${namespace}: missing ${key}`)
        if(Object.hasOwn(source,key+'_other')) for(const category of new Intl.PluralRules(locale).resolvedOptions().pluralCategories)
          assert.ok(Object.hasOwn(messages,key+'_'+category),`${locale}: missing plural ${key}_${category}`)
      }
    }
  }
})

test('notification locale follows saved selection and still switches when storage is blocked', async () => {
  let value = 'zh-CN', blocked = false
  const storage = {
    getItem: () => { if (blocked) throw new Error('Storage disabled'); return value },
    setItem: (key, next) => { if (blocked) throw new Error('Storage disabled'); assert.equal(key, 'xipki.locale'); value = next },
  }
  const previous=Object.getOwnPropertyDescriptor(globalThis,'localStorage')
  Object.defineProperty(globalThis,'localStorage',{configurable:true,value:storage})
  try {
  const runtime = await import('../src/i18n/locale.ts')
  assert.equal(runtime.translateNotification('Login'), '登录')
  runtime.saveLocale('en-US')
  assert.equal(value, 'en-US')
  assert.equal(runtime.translateNotification('Login'), 'Login')
  blocked = true
  assert.equal(runtime.storedLocale(), 'en-US')
  runtime.saveLocale('zh-CN')
  assert.equal(runtime.translateNotification('Login'), '登录')
  } finally {if(previous)Object.defineProperty(globalThis,'localStorage',previous);else delete globalThis.localStorage}
})

test('all literal translation calls and navigation labels have registered language-pack entries', () => {
  function check(file) {
    const source = readFileSync(file, 'utf8')
    const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
    function visit(node) {
      if (ts.isCallExpression(node) && ['t', 'translateNotification'].includes(node.expression.getText(ast)) && ts.isStringLiteral(node.arguments[0])) {
        assert.ok(Object.hasOwn(english, node.arguments[0].text), `${file}: ${node.arguments[0].text}`)
      }
      ts.forEachChild(node, visit)
    }
    visit(ast)
    if (file.endsWith('MainLayout.tsx')) {
      for (const [, label] of source.matchAll(/label: '([^']+)'/g)) assert.ok(Object.hasOwn(english, label), label)
    }
  }
  function walk(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const file = join(dir, entry.name)
      if (entry.isDirectory()) walk(file)
      else if (/\.tsx?$/.test(file)) check(file)
    }
  }
  walk(new URL('../src', import.meta.url).pathname)
})
