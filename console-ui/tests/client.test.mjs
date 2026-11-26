// License Apache License 2.0

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { translate } from '../src/i18n/catalog.ts';

const require = createRequire(import.meta.url);
const axios = require('axios');
const ts = require('typescript');
const source = readFileSync(new URL('../src/api/client.ts', import.meta.url), 'utf8');

function clients(locale = 'en-US') {
  const notices = [], navigations = [], events = [], calls = [];
  const window = { dispatchEvent(event) { events.push(event.type); }, location: {
    set href(value) { navigations.push(value); },
  } };
  let adapter = async config => {
    calls.push(config);
    throw new axios.AxiosError('Request failed', 'ERR_BAD_REQUEST', config, null,
      { status: 401, data: { error: 'Invalid credentials' }, headers: {}, config });
  };
  const boundary = {
    create(options) { return axios.create({ ...options, adapter: config => adapter(config) }); },
    get(url, options) { return axios.get(url, { ...options, adapter: config => adapter(config) }); },
  };
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020, esModuleInterop: true } }).outputText;
  const exports = {};
  new Function('require', 'exports', 'window', code)(name => name === 'axios' ? boundary :
    name === '../i18n/locale' ? { translateNotification: (key, values) => translate(locale, key, values) } :
    name === 'antd' ? { message: { error(...args) { notices.push(args); } } } : require(name), exports, window);
  return { ...exports, notices, navigations, events, calls, setAdapter(value) { adapter = value; } };
}

test('initial anonymous session check rejects quietly without reloading the login page', async () => {
  const client = clients();
  await assert.rejects(client.authApi.get('/api/auth/me'));
  assert.deepEqual(client.navigations, []);
  assert.deepEqual(client.events, []);
  assert.deepEqual(client.notices, []);
});

test('a denied expired bootstrap clears cached CSRF for an explicit retry without replaying the write', async () => {
  const client=clients();let tokens=0,writes=0;
  client.setAdapter(async config=>{
    if(config.url==='/api/auth/csrf')return {status:200,data:{token:`token-${++tokens}`,headerName:'X-CSRF-TOKEN'},headers:{},config};
    writes++;
    if(writes===1)throw new axios.AxiosError('Denied','ERR_BAD_REQUEST',config,null,{status:403,data:{error:'Invalid CSRF token'},headers:{},config});
    return {status:200,data:{success:true},headers:{},config};
  });
  await assert.rejects(client.default.post('/api/auth/login',{}));
  assert.equal(writes,1,'a denied write must not be replayed automatically');
  await client.default.post('/api/auth/login',{});
  assert.equal(tokens,2,'the next explicit attempt must fetch a fresh bootstrap token');
  assert.equal(writes,2);
});

test('expired authenticated API session notifies the mounted app without a document reload', async () => {
  const client = clients();
  await assert.rejects(client.default.get('/api/ca'));
  assert.deepEqual(client.navigations, []);
  assert.deepEqual(client.events, ['xipki:authentication-required']);
});

test('authentication, API and CSRF requests all have finite response timeouts', async () => {
  const client = clients();
  await assert.rejects(client.authApi.get('/api/auth/me'));
  await assert.rejects(client.default.get('/api/ca'));
  await assert.rejects(client.default.post('/api/auth/login', {}));
  assert.equal(client.calls.length, 3);
  for (const call of client.calls) assert.ok(call.timeout > 0 && call.timeout <= 15000, call.url);
});

test('successful login is not reported as failed by an extra CSRF roundtrip', async () => {
  const client = clients();
  let requests = 0;
  client.setAdapter(async config => {
    requests++;
    if (config.url === '/api/auth/csrf' && requests === 1) {
      return { status: 200, data: { token: 'test-csrf', headerName: 'X-CSRF-TOKEN' }, headers: {}, config };
    }
    if (config.url === '/api/auth/login') {
      return { status: 200, data: { success: true }, headers: {}, config };
    }
    throw new Error('Unexpected dependent request after successful login');
  });
  assert.equal((await client.default.post('/api/auth/login', {})).data.success, true);
  assert.equal(requests, 2);
});

test('uncertain write outcome preserves reconciliation guidance and request ID', async () => {
  const client = clients();
  client.setAdapter(async config => {
    throw new axios.AxiosError('Unavailable', 'ERR_BAD_RESPONSE', config, null,
      { status: 503, data: { error: 'Verify operation result before retry' },
        headers: { 'x-request-id': 'audit-test-id' }, config });
  });
  await assert.rejects(client.default.get('/api/ca'));
  assert.match(client.notices[0][0], /Verify operation result before retry/);
  assert.match(client.notices[0][0], /audit-test-id/);
});

function successfulAdapter(config) {
  return Promise.resolve({ status: 200,
    data: config.url === '/api/auth/csrf' ? { token: 'csrf', headerName: 'X-CSRF-TOKEN' } : { success: true },
    headers: {}, config });
}

test('changing password discards the destroyed session CSRF token before signing in again', async () => {
  const client = clients();
  let csrfRequests = 0;
  client.setAdapter(async config => {
    if (config.url === '/api/auth/csrf') return { status: 200,
      data: { token: `csrf-${++csrfRequests}`, headerName: 'X-CSRF-TOKEN' }, headers: {}, config };
    if (config.url === '/api/auth/login') assert.equal(config.headers.get('X-CSRF-TOKEN'), 'csrf-2');
    return successfulAdapter(config);
  });
  await client.default.post('/api/auth/password', { currentPassword: 'temporary', newPassword: 'a long new password' });
  await client.default.post('/api/auth/login', {});
  assert.equal(csrfRequests, 2);
});

test('HTTP 200 business failure rejects instead of allowing a success notification', async () => {
  const client = clients();
  client.setAdapter(async config => ({ status: 200, data: { success: false, error: 'CA not found' },
    headers: { 'x-request-id': 'business-id' }, config }));
  await assert.rejects(client.default.get('/api/ca/missing'), /CA not found/);
  assert.equal(client.notices.length, 1);
  assert.match(client.notices[0][0], /CA not found/);
  assert.match(client.notices[0][0], /business-id/);
});

test('heavy writes have a 120 second budget while reads and ordinary writes stay bounded at 15 seconds', async () => {
  const client = clients();
  const calls = [];
  client.setAdapter(config => { calls.push(config); return successfulAdapter(config); });
  for (const url of ['/api/ca', '/api/ca/root', '/api/cert/enroll', '/api/cert/enroll-cross',
    '/api/cert/enroll-key', '/api/cert/enroll-key/download', '/api/system/republish']) {
    await client.default.post(url, {});
    assert.equal(calls.at(-1).timeout, 120000, url);
  }
  await client.default.get('/api/ca');
  assert.equal(calls.at(-1).timeout, 15000);
  await client.default.put('/api/ca/example', {});
  assert.equal(calls.at(-1).timeout, 15000);
});

test('timed out heavy write is never replayed and provides its preassigned request ID for reconciliation', async () => {
  const client = clients();
  let writes = 0;
  let requestId;
  client.setAdapter(async config => {
    if (config.url === '/api/auth/csrf') return successfulAdapter(config);
    writes++;
    requestId = config.headers.get('X-Request-ID');
    throw new axios.AxiosError('timeout', 'ECONNABORTED', config);
  });
  await assert.rejects(client.default.post('/api/ca/root', {}));
  assert.equal(writes, 1);
  assert.match(requestId, /^[A-Za-z0-9._:-]{1,128}$/);
  assert.match(client.notices[0][0], /may have taken effect; verify the result/);
  assert.ok(client.notices[0][0].includes(requestId));
});

test('Chinese notifications translate guidance while retaining server diagnostics and request IDs', async () => {
  const client = clients('zh-CN');
  client.setAdapter(async config => {
    throw new axios.AxiosError('Unavailable', 'ERR_BAD_RESPONSE', config, null,
      { status: 503, data: { error: 'CKR_DEVICE_ERROR' }, headers: { 'x-request-id': 'locale-test' }, config });
  });
  await assert.rejects(client.default.get('/api/ca'));
  assert.match(client.notices[0][0], /CKR_DEVICE_ERROR.*若为写操作.*核对.*locale-test/);
});

test('JSON error returned for a blob download is decoded and rejects with meaningful details', async () => {
  const client = clients();
  client.setAdapter(async config => {
    throw new axios.AxiosError('Request failed', 'ERR_BAD_RESPONSE', config, null,
      { status: 503, data: new Blob([JSON.stringify({ error: 'Audit storage unavailable' })],
        { type: 'application/json' }), headers: { 'x-request-id': 'blob-id' }, config });
  });
  await assert.rejects(client.default.get('/api/ca/root/certificates', { responseType: 'blob' }));
  assert.match(client.notices[0][0], /Audit storage unavailable/);
  assert.match(client.notices[0][0], /blob-id/);
});

test('blob HTTP 200 business errors reject while successful binary bytes are preserved', async () => {
  const client = clients();
  const bytes = new Blob(['certificate bytes'], { type: 'application/pkix-cert' });
  client.setAdapter(async config => ({ status: 200, data: bytes, headers: {}, config }));
  assert.equal((await client.default.get('/api/ca/ca/certificates', { responseType: 'blob' })).data, bytes);
  client.setAdapter(async config => ({ status: 200,
    data: new Blob([JSON.stringify({ success: false, error: 'No certificate' })], { type: 'application/json' }),
    headers: {}, config }));
  await assert.rejects(client.default.get('/api/ca/ca/certificates', { responseType: 'blob' }), /No certificate/);
});
