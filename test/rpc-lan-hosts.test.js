// issue #79：局域网白名单 RPC（lan.setOverride 兼容 host/ip、lan.hosts.add/remove）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createPocketService } from '../lib/service.mjs';
import { installPocketRpc } from '../lib/web-rpc.js';
import { POCKET_RPC_CHANNEL, POCKET_ENDPOINTS } from '../client/api.js';
import { lanIpOverride, setLanIpOverride, lanHosts, addLanHost, removeLanHost, setTunnelHostname, setTunnelMode } from '../lib/settings.mjs';

async function withTempHome(fn) {
  const home = await mkdtemp(join(tmpdir(), 'dshp-rpc-lan-'));
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

function fakeCtxConnection() {
  let handler = null;
  const handle = (channel, fn, opts) => {
    assert.equal(channel, POCKET_RPC_CHANNEL);
    assert.deepEqual(opts, { authority: 'loopback' });
    handler = fn;
    return () => { handler = null; };
  };
  return { rpc: { handle }, get handler() { return handler; } };
}

function stubInternals() {
  return {
    lanIPv4: () => '192.168.1.50',
    lanCandidates: async () => ['192.168.1.50', '100.119.24.44'],
    encodeQr: async (text) => `data:qr;${text}`,
    createProxy: async ({ port }) => ({ port, close: async () => {} }),
  };
}

test('RPC lan.hosts.add/remove：归一化、去重、幂等、校验与隧道域名冲突', () => withTempHome(async () => {
  const service = createPocketService({
    dshPort: 3080,
    port: 3081,
    internals: stubInternals(),
    getLanIpOverride: () => lanIpOverride(),
    getLanHosts: () => lanHosts(),
  });
  const conn = fakeCtxConnection();
  installPocketRpc({ connection: conn }, {
    service,
    getLanIpOverride: () => lanIpOverride(),
    setLanIpOverride: (host) => setLanIpOverride(host),
    addLanHost: (host) => addLanHost(host),
    removeLanHost: (host) => removeLanHost(host),
    log: { error() {}, warn() {} },
  });
  await service.startProxy();

  try {
    const initial = await conn.handler(POCKET_ENDPOINTS.status, {});
    assert.deepEqual(initial.value.lanHosts, [], '默认无其他入口');

    const added = await conn.handler(POCKET_ENDPOINTS.lanHostsAdd, { host: '30.174.129.51' });
    assert.equal(added.ok, true, '添加成功');
    assert.deepEqual(added.value.lanHosts, ['30.174.129.51'], '返回完整 status');
    assert.ok(added.value.lanCandidates.includes('30.174.129.51'), '候选合并白名单');
    assert.equal(
      added.value.lanCandidatesDetail.find((d) => d.address === '30.174.129.51').rfc1918,
      false,
      '30.x 标记为非 RFC1918',
    );

    const domain = await conn.handler(POCKET_ENDPOINTS.lanHostsAdd, { host: 'DSH.Dev.Example.COM.:3081' });
    assert.equal(domain.ok, false, '带端口拒绝（保存时必须无端口）');

    const domain2 = await conn.handler(POCKET_ENDPOINTS.lanHostsAdd, { host: 'DSH.Dev.Example.COM.' });
    assert.equal(domain2.ok, true);
    assert.deepEqual(domain2.value.lanHosts, ['30.174.129.51', 'dsh.dev.example.com'], '域名归一化');

    const dup = await conn.handler(POCKET_ENDPOINTS.lanHostsAdd, { host: 'dsh.dev.example.com' });
    assert.equal(dup.ok, true, '重复添加幂等');
    assert.deepEqual(dup.value.lanHosts, ['30.174.129.51', 'dsh.dev.example.com'], '不产生重复');

    const bad = await conn.handler(POCKET_ENDPOINTS.lanHostsAdd, { host: '*.corp.example.com' });
    assert.equal(bad.ok, false, '通配符拒绝');
    assert.equal(bad.error.code, 'bad-request');
    assert.match(bad.error.message, /局域网入口/);

    // 主入口：兼容新 { host } 与旧 { ip }，可域名
    const primary = await conn.handler(POCKET_ENDPOINTS.lanSetOverride, { host: 'portal.dev.example.com' });
    assert.equal(primary.ok, true);
    assert.equal(primary.value.lanIpOverride, 'portal.dev.example.com');
    assert.equal(primary.value.lanUrl, 'http://portal.dev.example.com:3081', '二维码/URL 支持域名');

    const legacy = await conn.handler(POCKET_ENDPOINTS.lanSetOverride, { ip: '100.119.24.44' });
    assert.equal(legacy.ok, true, '旧 { ip } 载荷兼容');
    assert.equal(legacy.value.lanIpOverride, '100.119.24.44');

    // 命名隧道域名冲突：RPC 必须返回 bad-request（§6.3）
    setTunnelMode('named');
    setTunnelHostname('pocket.example.com');
    const conflict = await conn.handler(POCKET_ENDPOINTS.lanHostsAdd, { host: 'pocket.example.com' });
    assert.equal(conflict.ok, false, '隧道域名加入白名单被拒绝');
    assert.equal(conflict.error.code, 'bad-request');
    assert.match(conflict.error.message, /公网固定隧道|局域网入口/);
    const conflictPrimary = await conn.handler(POCKET_ENDPOINTS.lanSetOverride, { host: 'pocket.example.com' });
    assert.equal(conflictPrimary.ok, false, '隧道域名设为主入口被拒绝');

    // 删除：带端口按匹配语义归一化；重复删除幂等
    const removed = await conn.handler(POCKET_ENDPOINTS.lanHostsRemove, { host: '30.174.129.51:3081' });
    assert.equal(removed.ok, true);
    assert.deepEqual(removed.value.lanHosts, ['dsh.dev.example.com'], '删除成功');
    const removedAgain = await conn.handler(POCKET_ENDPOINTS.lanHostsRemove, { host: '30.174.129.51' });
    assert.equal(removedAgain.ok, true, '删除不存在的条目幂等');
    assert.deepEqual(removedAgain.value.lanHosts, ['dsh.dev.example.com'], '列表不变');

    const cleared = await conn.handler(POCKET_ENDPOINTS.lanSetOverride, { host: '' });
    assert.equal(cleared.ok, true);
    assert.equal(cleared.value.lanIpOverride, '');
    assert.equal(cleared.value.lanUrl, 'http://192.168.1.50:3081', '清空主入口回退自动探测');
  } finally {
    await service.dispose();
  }
}));