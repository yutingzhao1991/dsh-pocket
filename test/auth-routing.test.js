// issue #79 回归：Tailscale/CGNAT（100.64/10）及用户手动「局域网地址」覆盖，应走局域网密码。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tokenForHost, credentialKindForHost, isLanOverrideHost, isLanHost, rotateAccessToken } from '../lib/index.js';
import { setLanIpOverride, setLanAuthEnabled, lanIpOverride, addLanHost, lanHosts, setPinCustom, setTunnelMode, setTunnelHostname, settingsPath } from '../lib/settings.mjs';
import { policyHost, classifyHost, isTrustedLanSource, resolvePolicyHost } from '../lib/proxy.mjs';
import { isLocalSubnetAddress, isIpv4InCidr, trustedSubnetsFor } from '../lib/ip.mjs';

let tmpHome = null;
let savedHome = null;

function withTempHome(fn) {
  return (async () => {
    savedHome = process.env.DSH_HOME;
    tmpHome = await mkdtemp(join(tmpdir(), 'dsh-pocket-auth-'));
    process.env.DSH_HOME = tmpHome;
    try {
      return await fn();
    } finally {
      if (savedHome === undefined) delete process.env.DSH_HOME;
      else process.env.DSH_HOME = savedHome;
      if (tmpHome) await rm(tmpHome, { recursive: true, force: true });
    }
  })();
}

test('issue #79：手动「局域网地址」覆盖（公网段 IP）走局域网密码，而非公网密码', () => withTempHome(async () => {
  setLanAuthEnabled(true);
  setLanIpOverride('203.0.113.5'); // 故意用公网段 IP，证明覆盖优先级高于 classifyHost
  assert.equal(lanIpOverride(), '203.0.113.5');

  // 覆盖地址（带端口）→ 局域网 token
  const lanToken = tokenForHost('203.0.113.5:3081');
  // 普通公网域名（无覆盖命中）→ 公网 token
  const publicToken = tokenForHost('pocket.example.com');

  assert.notEqual(lanToken, publicToken, '覆盖地址必须比对局域网密码，而非公网密码');
  // 其它内网地址也走局域网 token（与覆盖地址一致）
  assert.equal(tokenForHost('192.168.1.5:3081'), lanToken, 'RFC1918 与覆盖地址共用局域网密码');
  // 公网路径不被覆盖误伤
  assert.equal(tokenForHost('8.8.8.8:3081'), publicToken, '普通公网 Host 仍走公网密码');

  // isLanOverrideHost 判定（带/不带端口）
  assert.equal(isLanOverrideHost('203.0.113.5:3081'), true);
  assert.equal(isLanOverrideHost('203.0.113.5'), true);
  assert.equal(isLanOverrideHost('192.168.1.5:3081'), false, '非覆盖地址不应命中');

  // 清空覆盖后恢复 classifyHost 语义（公网段 IP → 公网密码）
  setLanIpOverride('');
  assert.equal(isLanOverrideHost('203.0.113.5:3081'), false);
  assert.equal(tokenForHost('203.0.113.5:3081'), publicToken, '覆盖清空后回到公网判定');
}));

test('issue #79：CGNAT 100.64/10 无需覆盖即走局域网密码', () => withTempHome(async () => {
  setLanIpOverride(''); // 自动模式
  const lanToken = tokenForHost('100.64.0.1:3081');
  const publicToken = tokenForHost('pocket.example.com');
  assert.notEqual(lanToken, publicToken);
  assert.equal(tokenForHost('100.127.255.254:3081'), lanToken, '100.127 仍属 100.64/10');
  assert.equal(tokenForHost('100.63.0.1:3081'), publicToken, '100.63 超出范围 → 公网密码');
  assert.equal(tokenForHost('100.128.0.1:3081'), publicToken, '100.128 超出范围 → 公网密码');
}));

test('issue #79：白名单归一化矩阵、未命中 fail closed、IPv6 与通配符拒绝', () => withTempHome(async () => {
  setLanIpOverride('30.174.129.51');
  addLanHost('dsh.dev.example.com');
  addLanHost('FD00::5');
  addLanHost('2001:0db8:0:0:0:0:0:5');
  assert.deepEqual(
    lanHosts(),
    ['dsh.dev.example.com', 'fd00::5', '2001:db8::5'],
    '条目归一化；IPv6 压缩为规范表示',
  );

  // Host 侧：带端口 / 大小写 / 尾部点 / 方括号 IPv6 / 未压缩 IPv6 都要命中
  for (const host of [
    '30.174.129.51',
    '30.174.129.51:3081',
    'DSH.DEV.EXAMPLE.COM',
    'dsh.dev.example.com.:3081',
    '[FD00::5]:3081',
    'fd00::5',
    '2001:DB8:0:0:0:0:0:5',
    '[2001:db8::5]:3081',
  ]) {
    assert.equal(isLanHost(host), true, `${host} 应命中白名单`);
  }
  // 未声明的一律不命中（fail closed），不做后缀/通配匹配
  for (const host of ['30.174.129.52', 'other.example.com', 'dsh.dev.example.com.evil.com', 'fd00::6', '2001:db8::6']) {
    assert.equal(isLanHost(host), false, `${host} 不应命中`);
  }

  const lanToken = tokenForHost('30.174.129.51:3081');
  const publicToken = tokenForHost('pocket.example.com');
  assert.notEqual(lanToken, publicToken);
  assert.equal(tokenForHost('DSH.DEV.EXAMPLE.COM.:3081'), lanToken, '域名入口走局域网密码');
  assert.equal(tokenForHost('pocket.example.com'), publicToken, '未命中仍走公网密码');

  assert.throws(() => addLanHost('*.corp.example.com'), /局域网入口/, '通配符拒绝');
  assert.throws(() => addLanHost('host:3081'), /局域网入口/, '端口拒绝');
  assert.throws(() => addLanHost('http://host/path'), /局域网入口/, '路径拒绝');
  assert.equal(isLanHost('pocket.example.com'), false, '拒绝后未污染白名单');
}));

test('issue #79 / §6.3：命名隧道域名即使残留在白名单也永远按公网处理', () => withTempHome(async () => {
  setLanIpOverride('');
  setTunnelMode('named');
  setTunnelHostname('pocket.example.com');
  assert.throws(() => addLanHost('pocket.example.com'), /公网固定隧道|局域网入口/, '保存时拒绝');

  // 模拟手改 settings.json 写入冲突条目：运行时仍必须按公网处理
  const raw = JSON.parse(readFileSync(settingsPath(), 'utf8'));
  raw.lanHosts = ['pocket.example.com'];
  writeFileSync(settingsPath(), JSON.stringify(raw), 'utf8');

  assert.equal(isLanHost('pocket.example.com'), false, '隧道域名不命中局域网白名单');
  assert.notEqual(tokenForHost('pocket.example.com'), tokenForHost('127.0.0.1'), '仍走公网密码');
}));

test('review P1：公网直连伪造白名单 Host 不得降级成局域网密码/免密', () => withTempHome(async () => {
  setLanIpOverride('30.174.129.51');
  addLanHost('dsh.dev.example.com');
  const lanToken = tokenForHost('30.174.129.51', '127.0.0.1');
  const publicToken = tokenForHost('pocket.example.com', '203.0.113.5');
  assert.notEqual(lanToken, publicToken);

  // 公网来源 + 白名单 Host：不命中，仍走公网密码
  assert.equal(isTrustedLanSource('203.0.113.5'), false, '非直连子网的公网来源不可信');
  assert.equal(isLanHost('30.174.129.51', '203.0.113.5'), false, '不能靠伪造 Host 命中白名单');
  assert.equal(isLanHost('dsh.dev.example.com', '203.0.113.5'), false);
  assert.equal(tokenForHost('30.174.129.51', '203.0.113.5'), publicToken, '改走公网密码');
  assert.equal(tokenForHost('dsh.dev.example.com', '203.0.113.5'), publicToken);

  // loopback / RFC1918 来源仍可信；非 RFC1918 内网（30.x）由「白名单 IP 所在本机网卡子网」可信
  assert.equal(isTrustedLanSource('127.0.0.1'), true);
  assert.equal(isTrustedLanSource('192.168.1.9'), true);
  assert.equal(isTrustedLanSource('203.0.113.5'), false, '未授权子网的公网来源不可信');
  assert.equal(isLanHost('30.174.129.51', '127.0.0.1'), true);
  assert.equal(isLanHost('30.174.129.51', '192.168.1.9'), true);
  assert.equal(isLocalSubnetAddress('30.174.129.60', ['30.174.128.0/19']), true, '同网段来源可信');
  assert.equal(isLocalSubnetAddress('30.175.1.2', ['30.174.128.0/19']), false, '跨网段来源不可信');
  assert.equal(isIpv4InCidr('30.174.129.60', '30.174.128.0/19'), true);
  assert.equal(isIpv4InCidr('30.175.1.2', '30.174.128.0/19'), false);

  // 只信任“白名单 IPv4 入口所对应的本机网卡”子网；公网网卡不会自动获得信任
  const fakeInterfaces = {
    en0: [{ family: 'IPv4', address: '30.174.129.51', cidr: '30.174.129.51/19' }],
    eth0: [{ family: 'IPv4', address: '203.0.113.10', cidr: '203.0.113.10/24' }],
  };
  const subnets = trustedSubnetsFor(['30.174.129.51', 'dsh.dev.example.com'], fakeInterfaces);
  assert.deepEqual(subnets, ['30.174.129.51/19'], '只取白名单 IP 对应网卡的子网');
  assert.equal(isTrustedLanSource('30.174.129.60', subnets), true, '30.x 同网段可信');
  assert.equal(isTrustedLanSource('203.0.113.20', subnets), false, '未授权的公网网卡子网不可信');
}));

test('review P2：可信白名单 Host 先于 policyHost 保留，不被 30.x 源地址替换', () => {
  // `.local` / 单标签名被 classifyHost 判 lan，30.x 来源判 public；若先 policyHost
  // 就会换成源地址，导致配置的入口失效。
  assert.equal(resolvePolicyHost('pocket.local:3081', '30.174.129.60', true), 'pocket.local:3081');
  assert.equal(resolvePolicyHost('pocket.local:3081', '30.174.129.60', false), '30.174.129.60');
  // 公网类白名单 Host 不会被 policyHost 改写，但随后仍按公网策略处理（来源不可信）
  assert.equal(resolvePolicyHost('30.174.129.51:3081', '203.0.113.5', false), '30.174.129.51:3081');
});

test('issue #90：policyHost 保留源地址下限（伪造 Host 不能把公网降级）', () => withTempHome(async () => {
  setLanIpOverride('30.174.129.51');
  const req = { socket: { remoteAddress: '8.8.8.8' } };
  // 公网源地址伪造 loopback / 私网 Host → 改用真实源地址（仍 public）
  assert.equal(policyHost(req, '127.0.0.1:3081'), '8.8.8.8');
  assert.equal(classifyHost(policyHost(req, '127.0.0.1:3081')), 'public');
  assert.equal(policyHost(req, '192.168.1.5:3081'), '8.8.8.8');
  assert.equal(classifyHost(policyHost(req, '192.168.1.5:3081')), 'public');
  // 本机/局域网来源声明公网 Host 时不被放宽（仍按声明的公网处理）
  assert.equal(policyHost({ socket: { remoteAddress: '127.0.0.1' } }, 'pocket.example.com'), 'pocket.example.com');
}));

test('issue #90：访问 PIN 必须用 CSPRNG 生成，不得回退到 Math.random', () => withTempHome(async () => {
  // 源码守卫：Math.random 是 V8 的 xorshift128+，可由少量输出还原内部状态并推算后续值。
  // 用它生成访问密码等于把 9×10⁷ 的搜索空间进一步压缩，因此整个 lib/index.js 都不许出现。
  const src = readFileSync(new URL('../lib/index.js', import.meta.url), 'utf8');
  assert.ok(!src.includes('Math.random'), '访问密码生成不得使用 Math.random');

  // 行为守卫：格式仍是 8 位数字（不破坏手机输入体验与 PIN_RE），且取值铺满首位 1-9。
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const pin = rotateAccessToken();
    assert.match(pin, /^[1-9]\d{7}$/, `第 ${i + 1} 次生成的 PIN 应为 8 位数字且无前导零：${pin}`);
    seen.add(pin);
  }
  // 200 次采样在 9×10⁷ 空间里几乎不可能撞车；若大量重复说明随机源退化了。
  assert.ok(seen.size >= 199, `200 次采样应基本互不相同，实际 ${seen.size} 个不同值`);
}));

test('登录页凭据语义：LAN、Named 和自定义公网 PIN 可保存，Quick 自动 PIN 不保存', () => withTempHome(async () => {
  setLanIpOverride('');
  setTunnelMode('quick');
  setPinCustom('public', false);

  assert.equal(credentialKindForHost('192.168.1.5:3081'), 'persistent', 'LAN 自动 PIN 持久到手动刷新');
  assert.equal(credentialKindForHost('abc.trycloudflare.com'), 'ephemeral', 'Quick 自动 PIN 每次开隧道轮换');

  setPinCustom('public', true);
  assert.equal(credentialKindForHost('abc.trycloudflare.com'), 'persistent', 'Quick 自定义 PIN 长期复用');

  setPinCustom('public', false);
  setTunnelMode('named');
  assert.equal(credentialKindForHost('pocket.example.com'), 'persistent', 'Named Tunnel PIN 不自动轮换');

  setLanIpOverride('203.0.113.5');
  assert.equal(credentialKindForHost('203.0.113.5:3081'), 'persistent', '手动 LAN 地址覆盖仍按 LAN 持久 PIN 处理');
}));
