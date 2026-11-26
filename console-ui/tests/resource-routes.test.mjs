// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const ts = require('typescript')
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b }); return { promise, resolve, reject } }
const response = data => ({ data: { data } })

// Run the real component effects and handlers; only HTTP, routing and widget boundaries are doubled.
function screen(kind) {
  let cursor=0, dirty=false, tree, name='first'
  const slots=[], effects=[], requests=[], writes=[], confirmations=[]
  const form={ values:{}, resetFields(){this.values={}}, setFieldsValue(value){this.values={...this.values,...value}} }
  const react={
    useState(value){const i=cursor++;slots[i]??={value};return [slots[i].value,value=>{slots[i].value=typeof value==='function'?value(slots[i].value):value;dirty=true}]},
    useRef(value){const i=cursor++;return slots[i]??={current:value}},
    useEffect(fn,deps){const i=cursor++,old=slots[i];if(!old||deps.some((value,n)=>value!==old.deps[n])){slots[i]={deps,cleanup:old?.cleanup};effects.push(()=>{slots[i].cleanup?.();slots[i].cleanup=fn()})}},
  }
  const jsx=(type,props)=>({type,props})
  const antd=Object.fromEntries(['Alert','Button','Card','Tag','Spin','Tabs','Space','Popconfirm'].map(x=>[x,x]))
  Object.assign(antd,{Descriptions:Object.assign(()=>{},{Item:'Item'}),Typography:{Title:'Title',Text:'Text'},Input:{TextArea:'TextArea'},Select:Object.assign(()=>{},{Option:'Option'}),
    Form:Object.assign(()=>{},{Item:'FormItem',useForm:()=>[form]}),message:{success(){},error(){}}})
  const api={get(resource){const request=deferred();requests.push({name:resource,...request});return request.promise},async restart(resource){writes.push({name:resource})},async update(resource,body){writes.push({name:resource,body})}}
  const path=kind==='ca'?'../src/pages/ca/CaDetail.tsx':'../src/pages/profile/ProfileEditor.tsx'
  const code=ts.transpileModule(readFileSync(new URL(path,import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText
  const exports={}
  new Function('require','exports',code)(id=>{
    if(id==='react')return react
    if(id==='react/jsx-runtime')return {jsx,jsxs:jsx}
    if(id==='react-router-dom')return {useParams:()=>({name}),useNavigate:()=>()=>{}}
    if(id==='antd')return antd
    if(id==='@ant-design/icons')return {ArrowLeftOutlined:'Back',SaveOutlined:'Save'}
    if(id==='../../i18n')return {useI18n:()=>({t:x=>x})}
    if(id==='../../auth')return {useCan:()=>()=>true}
    if(id==='../../api/ca')return {caApi:api}
    if(id==='../../api/entities')return {profileApi:api}
    if(id==='../../components/Reauthentication')return {useReauthentication:()=>({authorize:(_,run)=>confirmations.push(run),dialog:null})}
    if(id==='../../types/api')return {errorMessage:(_,fallback)=>fallback}
    if(['./CaConfigEditor','./CaAssociations','./CaRevoke'].includes(id))return {default:id}
    throw new Error(`Unexpected dependency ${id}`)
  },exports)
  function render(){cursor=0;dirty=false;tree=exports.default();while(effects.length)effects.shift()()}
  function nodes(value){if(!value||typeof value!=='object')return [];return [value,...[value.props?.children,...(value.props?.items||[]).map(x=>x.children)].flat(Infinity).flatMap(nodes)]}
  async function flush(){for(let n=0;n<5;n++){await new Promise(resolve=>setImmediate(resolve));if(dirty)render()}}
  render()
  return {requests,writes,form,confirmations,flush,nodes:()=>nodes(tree),changeName(value){name=value;render()},
    async load(data,index=requests.length-1){requests[index].resolve(response(data));await flush()},
    async fail(index=requests.length-1){requests[index].reject(new Error('unavailable'));await flush()},
    restart(){nodes(tree).find(x=>x.type==='Button'&&x.props.children==='Restart CA')?.props.onClick()},
    save(){nodes(tree).find(x=>x.props?.onFinish)?.props.onFinish(form.values)},
  }
}

test('CA route change hides old actions and failed load cannot restore them',async()=>{
  const ui=screen('ca');await ui.load({name:'first',status:'active'})
  assert.ok(ui.nodes().some(x=>x.type==='Button'&&x.props.children==='Restart CA'))
  ui.changeName('second');ui.restart();await ui.flush()
  assert.equal(ui.writes.length,0)
  assert.ok(!ui.nodes().some(x=>x.type==='Button'&&x.props.children==='Restart CA'))
  await ui.fail();assert.equal(ui.writes.length,0)
  assert.ok(ui.nodes().some(x=>x.type==='Alert'&&x.props.message==='CA could not be loaded'))
})

test('late CA response cannot replace the current resource',async()=>{
  const ui=screen('ca');ui.changeName('second');await ui.flush()
  await ui.load({name:'second',status:'active'},1);await ui.load({name:'first',status:'active'},0)
  assert.ok(ui.nodes().some(x=>x.type==='Title'&&x.props.children.join('')==='CA: second'))
  ui.restart();await ui.flush();assert.equal(ui.writes[0].name,'second')
})

test('a completed old child operation cannot reload or clear a later CA route, including A to B to A',async()=>{
  const ui=screen('ca');await ui.load({name:'first',status:'active'})
  const oldSaved=ui.nodes().find(x=>x.props?.onSaved)?.props.onSaved
  assert.equal(typeof oldSaved,'function')
  ui.changeName('second');await ui.flush();await ui.load({name:'second',status:'active'})
  oldSaved();await ui.flush()
  assert.equal(ui.requests.length,2,'old child completion must not start another fetch')
  assert.ok(ui.nodes().some(x=>x.type==='Title'&&x.props.children.join('')==='CA: second'))
  ui.changeName('first');await ui.flush();await ui.load({name:'first',status:'active'})
  oldSaved();await ui.flush()
  assert.equal(ui.requests.length,3,'returning to the same name must not revive a previous route lifetime')
  assert.ok(ui.nodes().some(x=>x.type==='Title'&&x.props.children.join('')==='CA: first'))
})

test('profile navigation clears values and rejects a pending confirmation for the previous profile',async()=>{
  const ui=screen('profile');await ui.load({type:'xijson',conf:'old configuration'})
  ui.save();assert.equal(ui.confirmations.length,1)
  ui.changeName('second');await ui.flush()
  assert.deepEqual(ui.form.values,{})
  await ui.confirmations[0]();assert.equal(ui.writes.length,0)
  await ui.fail();ui.save();assert.equal(ui.writes.length,0)
})

test('late profile response cannot populate or save the wrong configuration',async()=>{
  const ui=screen('profile');ui.changeName('second');await ui.flush()
  await ui.load({type:'xijson',conf:'second configuration'},1)
  await ui.load({type:'xijson',conf:'first configuration'},0)
  assert.equal(ui.form.values.conf,'second configuration')
  ui.save();await ui.confirmations[0]();assert.deepEqual(ui.writes,[{name:'second',body:{type:'xijson',conf:'second configuration'}}])
})
