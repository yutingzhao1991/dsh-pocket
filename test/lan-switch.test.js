// issue #79 / §3.3：局域网入口白名单必须在所有判定点一致生效——
// 密码归属、登录页文案、局域网访问总开关（HTTP + WebSocket 同源判定）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket, WebSocketServer } from 'ws';

import { createPocketProxy, classifyHost } from '../lib/proxy.mjs';
import { isLanHost, tokenForHost, credentialKindForHost } from '../lib/index.js';
import { setLanIpOverride, addLanHost, setLanAuthEnabled } from '../lib/settings.mjs';

const LAN_IP = '30.174.129.51';
const LAN_DOMAIN = 'dsh.dev.example.com';

async function withTempHome(fn) {
  const home = await mkdtemp(join(tmpdir(), 'dshp-lan-switch-'));
  const prev = process.env.DSH_HOME;
  process.env.DSH_HOME = home;
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.DSH_HOME;
    else process.env.DSH_HOME = prev;
    await rm(home, { recursive: true, force: true });
  }
}

function fakeUpstream() {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<html><body>dsh</body></html>');
  });
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => ws.close());
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

function request(port, { host, path = '/', method = 'GET', accept = 'text/html', body } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { host, accept };
    if (body !== undefined) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      headers['content-length'] = Buffer.byteLength(body);
    }
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function wsProbe(port, { host, path = '/api/events.host' }) {
  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    let ws = null;
    const done = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws?.close(); } catch { /* 未打开时会抛 */ }
      resolve(result);
    };
    ws = new WebSocket(`ws://127.0.0.1:${port}${path}`, { headers: { Host: host } });
    ws.on('open', () => done({ opened: true }));
    ws.on('unexpected-response', (_req, res) => done({ opened: false, status: res.statusCode }));
    ws.on('error', (err) => done({ opened: false, error: err.message }));
    timer = setTimeout(() => done({ opened: false, error: 'timeout' }), 3000);
  });
}

function lanAuth() {
  return {
    sessionKey: 'test-session-key',
    getToken: (host, source) => tokenForHost(host, source),
    getCredentialKind: (host, source) => credentialKindForHost(host, source),
    isProtected: (host, source) => (isLanHost(host, source) ? true : classifyHost(host) === 'public'),
    isLanHost: (host, source) => isLanHost(host, source),
  };
}

async function setup(lanOn) {
  const up = await fakeUpstream();
  const proxy = await createPocketProxy({
    port: 0,
    host: '127.0.0.1',
    upstream: { host: '127.0.0.1', port: up.port },
    auth: lanAuth(),
    lanAccessEnabled: () => lanOn.value,
    rateLimit: { maxFailures: 1000, globalMaxFailures: 10000 },
  });
  return { up, proxy };
}

test('白名单入口（30.x / 自定义域名）：登录页称局域网、局域网 PIN 通过、公网 PIN 拒绝', () => withTempHome(async () => {
  setLanIpOverride(LAN_IP);
  addLanHost(LAN_DOMAIN);
  setLanAuthEnabled(true);

  const up = await fakeUpstream();
  const lanOn = { value: true };
  const proxy = await createPocketProxy({
    port: 0,
    host: '127.0.0.1',
    upstream: { host: '127.0.0.1', port: up.port },
    auth: lanAuth(),
    lanAccessEnabled: () => lanOn.value,
    rateLimit: { maxFailures: 1000, globalMaxFailures: 10000 },
  });
  const lanPin = tokenForHost(LAN_IP);
  const publicPin = tokenForHost('unknown.example.com');
  assert.notEqual(lanPin, publicPin, '两把 PIN 必须不同');

  try {
    for (const host of [`${LAN_IP}:3081`, `${LAN_DOMAIN.toUpperCase()}:3081`]) {
      const page = await request(proxy.port, { host });
      assert.equal(page.status, 200, `${host} 返回登录页`);
      assert.ok(page.body.includes('此局域网地址'), `${host} 文案应为局域网地址`);
      assert.ok(!page.body.includes('此公网地址'), `${host} 不应显示公网文案`);

      const ok = await request(proxy.port, {
        host,
        method: 'POST',
        path: '/pocket-login',
        body: `token=${encodeURIComponent(lanPin)}`,
      });
      assert.equal(ok.status, 302, `${host} 局域网 PIN 通过`);
      assert.match(String(ok.headers['set-cookie'] ?? ''), /dsh_pocket_token=/, '登录成功种 cookie');

      const wrong = await request(proxy.port, {
        host,
        method: 'POST',
        path: '/pocket-login',
        body: `token=${encodeURIComponent(publicPin)}`,
      });
      assert.equal(wrong.status, 200, `${host} 公网 PIN 被拒绝`);
      assert.ok(wrong.body.includes('密码错误'), `${host} 显示密码错误`);
    }

    // 未在白名单的域名：fail closed，仍按公网文案 + 公网 PIN
    const publicPage = await request(proxy.port, { host: 'unknown.example.com' });
    assert.equal(publicPage.status, 200);
    assert.ok(publicPage.body.includes('此公网地址'), '未知域名仍显示公网文案');

    const publicOk = await request(proxy.port, {
      host: 'unknown.example.com',
      method: 'POST',
      path: '/pocket-login',
      body: `token=${encodeURIComponent(publicPin)}`,
    });
    assert.equal(publicOk.status, 302, '未知域名用公网 PIN 通过');

    const publicWrong = await request(proxy.port, {
      host: 'unknown.example.com',
      method: 'POST',
      path: '/pocket-login',
      body: `token=${encodeURIComponent(lanPin)}`,
    });
    assert.equal(publicWrong.status, 200, '未知域名用局域网 PIN 被拒绝');
  } finally {
    await proxy.close();
    await new Promise((r) => up.server.close(r));
  }
}));

test('review P2：白名单里的 loopback 入口也受局域网总开关约束', () => withTempHome(async () => {
  // §8 允许把 localhost / 127.0.0.1 加入白名单（通常无意义）；一旦加入，
  // 它就是「已加入的入口」，关闭局域网访问时必须和其他入口一样 403，
  // 不能因为 classifyHost/isLoopbackHost 判 loopback 而绕过开关。
  setLanIpOverride('127.0.0.1');
  setLanAuthEnabled(true);

  const lanOn = { value: false };
  const { up, proxy } = await setup(lanOn);
  try {
    const html = await request(proxy.port, { host: '127.0.0.1:3081' });
    assert.equal(html.status, 403, '白名单 loopback HTML 403');
    assert.ok(html.body.includes('局域网访问已关闭'), '返回关闭提示页');

    const api = await request(proxy.port, { host: '127.0.0.1:3081', path: '/api/hello', accept: 'application/json' });
    assert.equal(api.status, 403, '白名单 loopback JSON 403');
    assert.equal(api.body, '{"error":"lan-disabled"}');

    const blocked = await wsProbe(proxy.port, { host: '127.0.0.1:3081' });
    assert.equal(blocked.opened, false, '白名单 loopback WS 403');
    assert.equal(blocked.status, 403);

    // 未加入白名单的 loopback 仍保留本机/cloudflared 回连语义（不受局域网开关影响）
    setLanIpOverride('');
    setLanAuthEnabled(false);
    const local = await request(proxy.port, { host: '127.0.0.1:3081' });
    assert.equal(local.status, 200, '未白名单 loopback 放行');
    assert.ok(local.body.includes('dsh'), '直接拿到上游内容');
    const localWs = await wsProbe(proxy.port, { host: '127.0.0.1:3081' });
    assert.equal(localWs.opened, true, '未白名单 loopback WS 放行');
  } finally {
    await proxy.close();
    await new Promise((r) => up.server.close(r));
  }
}));

test('lanEnabled=false：白名单入口 HTTP/WS 均 403；公网入口放行；WebSocket 与 HTTP 同一把 PIN', () => withTempHome(async () => {
  setLanIpOverride(LAN_IP);
  addLanHost(LAN_DOMAIN);
  setLanAuthEnabled(true);

  const lanOn = { value: false };
  const { up, proxy } = await setup(lanOn);
  const lanPin = tokenForHost(LAN_IP);
  const publicPin = tokenForHost('unknown.example.com');

  try {
    // HTTP：HTML 与 JSON 两条分支都必须 403 lan-disabled
    for (const host of [`${LAN_IP}:3081`, `${LAN_DOMAIN}:3081`]) {
      const html = await request(proxy.port, { host });
      assert.equal(html.status, 403, `${host} HTML 403`);
      assert.ok(html.body.includes('局域网访问已关闭'), `${host} 返回关闭提示页`);

      const api = await request(proxy.port, { host, path: '/api/hello', accept: 'application/json' });
      assert.equal(api.status, 403, `${host} JSON 403`);
      assert.equal(api.body, '{"error":"lan-disabled"}', `${host} JSON 错误体`);
    }

    // 公网入口不受局域网开关影响（仍要公网 PIN）
    const publicPage = await request(proxy.port, { host: 'unknown.example.com' });
    assert.equal(publicPage.status, 200, '公网入口放行');
    assert.ok(publicPage.body.includes('此公网地址'), '公网文案');

    // WebSocket：关闭时白名单入口拒绝握手（403），公网入口可带公网 PIN 打开
    for (const host of [`${LAN_IP}:3081`, `${LAN_DOMAIN}:3081`]) {
      const blocked = await wsProbe(proxy.port, { host, path: `/api/events.host?token=${lanPin}` });
      assert.equal(blocked.opened, false, `${host} WS 被拒绝`);
      assert.equal(blocked.status, 403, `${host} WS 返回 403`);
    }
    const publicWs = await wsProbe(proxy.port, {
      host: 'unknown.example.com',
      path: `/api/events.host?token=${publicPin}`,
    });
    assert.equal(publicWs.opened, true, '关闭局域网时公网 WS 仍可用');

    // 重新开启：白名单入口的 WS 与 HTTP 使用同一把局域网 PIN
    lanOn.value = true;
    const lanWs = await wsProbe(proxy.port, {
      host: `${LAN_DOMAIN}:3081`,
      path: `/api/events.host?token=${lanPin}`,
    });
    assert.equal(lanWs.opened, true, '白名单域名 + 局域网 PIN 可建立 WS');
    const lanWsWrong = await wsProbe(proxy.port, {
      host: `${LAN_DOMAIN}:3081`,
      path: `/api/events.host?token=${publicPin}`,
    });
    assert.equal(lanWsWrong.opened, false, '白名单域名 + 公网 PIN 被拒绝');
    assert.equal(lanWsWrong.status, 401, 'WS 返回 401');

    const publicWsWrong = await wsProbe(proxy.port, {
      host: 'unknown.example.com',
      path: `/api/events.host?token=${lanPin}`,
    });
    assert.equal(publicWsWrong.opened, false, '公网入口 + 局域网 PIN 被拒绝');
    assert.equal(publicWsWrong.status, 401, '公网 WS 返回 401');
  } finally {
    await proxy.close();
    await new Promise((r) => up.server.close(r));
  }
}));