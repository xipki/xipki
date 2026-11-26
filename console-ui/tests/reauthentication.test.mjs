// License Apache License 2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
const ts=createRequire(import.meta.url)('typescript')
const code=ts.transpileModule(readFileSync(new URL('../src/components/Reauthentication.tsx',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText
function confirmation(){
  let cursor=0,dirty=false,scope='first',value,finish,unmounted=false
  const slots=[],effects=[],writes=[]
  const react={
    useState(initial){const i=cursor++;slots[i]??={value:initial};return [slots[i].value,v=>{slots[i].value=v;dirty=true}]},
    useRef(initial){const i=cursor++;return slots[i]??={current:initial}},
    useEffect(fn,deps){const i=cursor++,old=slots[i];if(!old||deps.some((v,n)=>v!==old.deps[n])){slots[i]={deps,cleanup:old?.cleanup};effects.push(()=>{slots[i].cleanup?.();slots[i].cleanup=fn()})}},
  }
  const jsx=(type,props)=>({type,props}),exports={}
  new Function('require','exports',code)(id=>{
    if(id==='react')return react
    if(id==='react/jsx-runtime')return {jsx,jsxs:jsx}
    if(id==='antd')return {Alert:'Alert',Input:{Password:'Password'},Modal:'Modal'}
    if(id==='../i18n')return {useI18n:()=>({t:x=>x})}
    if(id==='../api/client')return {post:()=>new Promise(resolve=>{finish=resolve})}
    throw new Error(id)
  },exports)
  function render(){cursor=0;dirty=false;value=exports.useReauthentication(scope);while(effects.length)effects.shift()()}
  async function flush(){for(let i=0;i<4;i++){await new Promise(r=>setImmediate(r));if(dirty&&!unmounted)render()}}
  render()
  return {writes,flush,get value(){return value},async open(){value.authorize('Change resource',async()=>{writes.push(scope)});await flush();value.dialog.props.children[1].props.onChange({target:{value:'test password'}});await flush()},
    submit(){value.dialog.props.onOk()},async finish(){finish({});await flush()},change(){scope='second';render()},unmount(){unmounted=true;for(const slot of slots)slot?.cleanup?.()},
  }
}
test('reauthentication does not run a confirmed operation after its resource changes',async()=>{
  const ui=confirmation();await ui.open();ui.submit();ui.change();await ui.flush();await ui.finish();assert.deepEqual(ui.writes,[])
})
test('reauthentication does not run an operation after unmount',async()=>{
  const ui=confirmation();await ui.open();ui.submit();ui.unmount();await ui.finish();assert.deepEqual(ui.writes,[])
})
test('current confirmation runs once after successful verification',async()=>{
  const ui=confirmation();await ui.open();ui.submit();await ui.finish();assert.deepEqual(ui.writes,['first'])
})
