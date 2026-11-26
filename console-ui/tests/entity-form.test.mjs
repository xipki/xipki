// License Apache License 2.0

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { translate } from '../src/i18n/catalog.ts'

const compile = path => ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), {
  compilerOptions: {module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true},
}).outputText
const component = compile('../src/components/EntityCrudPage.tsx')
const deferred = () => {let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no});return {promise,resolve,reject}}

// Runs the real component's state and handlers; UI widgets and HTTP are boundaries.
function formPage(resource, extra={}) {
  let cursor=0,dirty=false,tree
  const slots=[],effects=[],requests=[],writes=[]
  const form={values:{},resetFields(){this.values={}},setFieldsValue(v){Object.assign(this.values,v)}}
  const react={
    useState(initial){const n=cursor++;slots[n]??={value:typeof initial==='function'?initial():initial};return [slots[n].value,v=>{slots[n].value=typeof v==='function'?v(slots[n].value):v;dirty=true}]},
    useEffect(fn,deps){const n=cursor++,old=slots[n];if(!old||deps.some((v,i)=>v!==old.deps[i])){slots[n]={deps,cleanup:old?.cleanup};effects.push(()=>{slots[n].cleanup?.();slots[n].cleanup=fn()})}},
  }
  const jsx=(type,props)=>({type,props})
  const antd=Object.fromEntries(['Table','Button','Space','Tag','Popconfirm','Modal','Checkbox','Alert','Select'].map(name=>[name,name]))
  Object.assign(antd,{Input:Object.assign(function Input(){},{TextArea:'TextArea'}),Typography:{Title:'Title',Paragraph:'Paragraph',Text:'Text'},
    Form:Object.assign(()=>{},{useForm:()=>[form],useWatch:name=>form.values[name],Item:'FormItem'}),message:{error(){},success(){}}})
  const exports={}
  new Function('require','exports',component)(id=>{
    if(id==='react') return react
    if(id==='react/jsx-runtime') return {jsx,jsxs:jsx,Fragment:'Fragment'}
    if(id==='antd') return antd
    if(id==='@ant-design/icons') return {PlusOutlined:'Plus',ReloadOutlined:'Reload'}
    if(id==='../i18n') return {useI18n:()=>({t:(key,values)=>translate('en-US',key,values)})}
    if(id==='../auth') return {useCan:()=>()=>true}
    if(id==='./Reauthentication') return {useReauthentication:()=>({authorize:(_,fn)=>fn(),dialog:null})}
    if(id==='../api/entities') return {entityEditPayload:values=>values}
    if(id==='../types/api') return {errorMessage:(_,fallback)=>fallback}
    if(id==='../api/system') return {systemApi:{supportedTypes(){const r=deferred();requests.push(r);return r.promise}}}
    if(id==='./entity-guidance') {const e={};new Function('exports',compile('../src/components/entity-guidance.ts'))(e);return e}
    throw new Error('Unexpected dependency: '+id)
  },exports)
  const props={title:resource,resource,api:{list:async()=>({data:{data:[]}}),create:async body=>writes.push(body),update:async()=>{},remove:async()=>{}},...extra}
  function render(){cursor=0;dirty=false;tree=exports.default(props);while(effects.length)effects.shift()()}
  function elements(node){return !node||typeof node!=='object'?[]:[node,...[node.props?.children,node.props?.action].flat(Infinity).flatMap(elements)]}
  async function flush(){for(let i=0;i<5;i++){await new Promise(resolve=>setImmediate(resolve));if(dirty)render()}}
  render()
  return {form,requests,writes,flush,all:()=>elements(tree),field:name=>elements(tree).find(n=>n.type==='FormItem'&&n.props.name===name),
    button:label=>elements(tree).find(n=>n.type==='Button'&&n.props.children===label),
    async choose(type){form.values.type=type;render();await flush()},
  }
}

test('generic key generator type remains editable when no runtime type catalog exists',async()=>{
  const ui=formPage('KEYPAIRGEN');await ui.flush()
  assert.equal(ui.field('type').props.children.type.name,'Input')
  assert.equal(ui.requests.length,0)
})

test('failed runtime type loading offers retry and does not offer unregistered hardware types',async()=>{
  const ui=formPage('SIGNER',{supportedTypeKey:'signerTypes',typeOptions:['pkcs12','pkcs11']})
  ui.requests[0].reject(new Error('offline'));await ui.flush()
  assert.deepEqual(ui.field('type').props.children.props.options,[])
  assert.ok(ui.button('Retry loading types'))
  ui.button('Retry loading types').props.onClick();await ui.flush()
  ui.requests.at(-1).resolve({data:{data:{signerTypes:['pkcs12','jceks']}}});await ui.flush()
  assert.deepEqual(ui.field('type').props.children.props.options.map(o=>o.value),['pkcs12','jceks'])
})

test('a runtime with no publishers keeps the catalog empty and blocks creation',async()=>{
  const ui=formPage('PUBLISHER',{supportedTypeKey:'publisherTypes',typeOptions:['ocsp']})
  ui.requests[0].resolve({data:{data:{publisherTypes:[]}}});await ui.flush()
  assert.deepEqual(ui.field('type').props.children.props.options,[])
  const modal=ui.all().find(n=>n.type==='Modal'&&n.props.onOk)
  assert.equal(modal.props.okButtonProps.disabled,true)
})

test('type-specific examples are visible without overwriting entered configuration',async()=>{
  const ui=formPage('SIGNER',{supportedTypeKey:'signerTypes'})
  ui.requests[0].resolve({data:{data:{signerTypes:['pkcs12','pkcs11']}}});await ui.flush()
  ui.form.values.conf='my unsaved configuration'
  await ui.choose('pkcs12')
  assert.ok(ui.all().some(n=>n.type==='Paragraph'&&String(n.props.children).includes('keystore=file:')))
  await ui.choose('pkcs11')
  assert.ok(ui.all().some(n=>n.type==='Paragraph'&&String(n.props.children).includes('module=')))
  assert.ok(!ui.all().some(n=>n.type==='Paragraph'&&String(n.props.children).includes('keystore=file:')))
  assert.equal(ui.form.values.conf,'my unsaved configuration')
})
