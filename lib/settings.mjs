// dsh-pocket 设置持久化（$DSH_HOME/dsh-pocket/settings.json）
//
// 当前项：
//   - lanEnabled        局域网访问总开关（默认开启）：关闭后局域网扫码/链接直接失效（代理拒绝局域网 Host）
//   - lanAuthEnabled    局域网访问密码开关（issue #24），默认开启
//   - lanIpOverride     局域网主入口（issue #79；IP 或域名，二维码/URL 用；空 = 自动探测）
//   - lanHosts          局域网其他入口白名单（issue #79；IP/域名数组，显式声明才生效）
//   - mobileRightbarEnabled 手机端右边栏入口（默认开启）
//   - publicPinCustom   公网密码是否用户自定义（issue #33），自定义后不自动轮换
//   - lanPinCustom      局域网密码是否用户自定义（issue #33）
//   - tunnelMode        公网隧道模式（issue #66）：'quick'（默认，随机 trycloudflare.com）| 'named'（固定域名）
//   - tunnelToken       Cloudflare 命名隧道 Token（issue #66，秘密；文件 0o600，RPC 不回显）
//   - tunnelHostname    命名隧道绑定的固定域名（issue #66，如 pocket.example.com）
// 默认**开启**（安全优先）：局域网扫码也要输 8 位密码；
// 用户可关闭——关闭后局域网扫码直连（仅同一网络内的设备能访问），公网不受影响（永远要密码）。

import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';

const settingsRel = join('dsh-pocket', 'settings.json');
export function settingsPath() {
  return join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), settingsRel);
}

function readSettings() {
  try {
    const raw = JSON.parse(readFileSync(settingsPath(), 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch { /* 无文件/损坏 → 默认 */ }
  return {};
}

function writeSettings(s) {
  try {
    mkdirSync(dirname(settingsPath()), { recursive: true });
    writeFileSync(settingsPath(), JSON.stringify(s, null, 2), { mode: 0o600 });
  } catch { /* 忽略 */ }
  return s;
}

/** 局域网访问总开关：默认开启（文件缺失/损坏都视为开启）。 */
export function lanEnabled() {
  return readSettings().lanEnabled !== false;
}

/** 设置局域网访问总开关，返回新状态（持久化）。 */
export function setLanEnabled(on) {
  const s = readSettings();
  s.lanEnabled = !!on;
  writeSettings(s);
  return s.lanEnabled;
}

/** 局域网访问密码开关：默认开启（文件缺失/损坏都视为开启）。 */
export function lanAuthEnabled() {
  return readSettings().lanAuthEnabled !== false;
}

/** 设置局域网访问密码开关，返回新状态（持久化）。 */
export function setLanAuthEnabled(on) {
  const s = readSettings();
  s.lanAuthEnabled = !!on;
  writeSettings(s);
  return s.lanAuthEnabled;
}

/** 手机端右边栏入口：默认开启，可按需关闭以保持更紧凑的标题栏。 */
export function mobileRightbarEnabled() {
  return readSettings().mobileRightbarEnabled !== false;
}

/** 设置手机端右边栏入口，返回新状态（持久化）。 */
export function setMobileRightbarEnabled(on) {
  const s = readSettings();
  s.mobileRightbarEnabled = !!on;
  writeSettings(s);
  return s.mobileRightbarEnabled;
}

// ---------- 局域网入口白名单（issue #79 / #33 / #54 / #66） ----------
// 一个安装可以声明多个「局域网入口」：本机 IP（RFC1918 与否都行）+ 自定义内网域名。
//   - lanIpOverride：主入口（二维码 / URL 用它），可 IP 或域名；
//   - lanHosts：其他入口，字符串数组。
// 生效集合 = unique(normalize([lanIpOverride, ...lanHosts]))；未命中一律按公网处理
//（fail closed）。条目只能由本机设置页/RPC 显式写入，不接受请求头动态扩展。
const LAN_HOST_ERROR = '局域网入口格式不对：只接受 IP 或域名（不含端口、路径、空白或通配符） | '
  + 'invalid LAN host: use an IP or hostname without port, path, whitespace, or wildcards';
const LAN_HOST_TUNNEL_CONFLICT = '该域名已用于公网固定隧道，不能同时作为局域网入口（请二选一） | '
  + 'this hostname is used by the named public tunnel; use it for only one of LAN or public';

/** 域名标签规则：单标签内网名也接受；总长度另行限制 253。 */
const HOSTNAME_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;

/**
 * IPv6 规范表示（RFC 5952：小写 + 零压缩）。Node 的 URL 解析器负责重写，
 * 保证配置条目与浏览器 Host 头（URL 里通常已压缩）用同一形态比较。
 * 非法输入回退小写原值（调用方已用 isIP 校验，正常不会走到）。
 */
function canonicalIpv6(value) {
  try {
    return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  } catch {
    return String(value ?? '').toLowerCase();
  }
}

/**
 * Host 归一化（用于比较，不做合法性校验）：小写、去端口（含 `[v6]:port`）、去尾部 `.`。
 * 裸 IPv6（含多个冒号）不会被误当 `host:port` 去尾段。
 */
export function normalizeHost(value) {
  let name = String(value ?? '').trim().toLowerCase();
  if (!name) return '';
  if (name.startsWith('[')) {
    const end = name.indexOf(']');
    if (end >= 0) {
      const rest = name.slice(end + 1);
      name = name.slice(1, end) + (/^:\d+$/.test(rest) ? '' : rest);
    }
  } else if ((name.match(/:/g)?.length ?? 0) === 1) {
    name = name.replace(/:\d+$/, '');
  }
  name = name.replace(/\.$/, '');
  return name.includes(':') && isIP(name) === 6 ? canonicalIpv6(name) : name;
}

/**
 * 校验并归一化一条局域网入口（IP 或域名）。非法输入抛错，调用方（RPC）转 bad-request。
 * 端口 / 路径 / 通配符 / 空白一律拒绝；IPv6 支持裸写与 `[v6]` 形式。
 */
export function normalizeLanHost(value) {
  const raw = String(value ?? '').trim();
  if (!raw || raw.length > 253) throw new Error(LAN_HOST_ERROR);
  if (/[\s/\\?#*]/.test(raw)) throw new Error(LAN_HOST_ERROR);
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end < 0 || raw.slice(end + 1) !== '') throw new Error(LAN_HOST_ERROR);
    const inner = raw.slice(1, end).toLowerCase();
    if (isIP(inner) !== 6) throw new Error(LAN_HOST_ERROR);
    return canonicalIpv6(inner);
  }
  const colons = raw.match(/:/g)?.length ?? 0;
  if (colons === 1) throw new Error(LAN_HOST_ERROR); // host:port / 非 IPv6 的单冒号
  if (colons > 1) {
    const v6 = raw.toLowerCase();
    if (isIP(v6) !== 6) throw new Error(LAN_HOST_ERROR);
    return canonicalIpv6(v6);
  }
  const host = normalizeHost(raw);
  if (!host || host.length > 253) throw new Error(LAN_HOST_ERROR);
  if (isIP(host) === 4) return host;
  // 形如 999.1.1.1 的「伪 IPv4」不能当域名放过
  if (/^[0-9.]+$/.test(host)) throw new Error(LAN_HOST_ERROR);
  if (!HOSTNAME_RE.test(host)) throw new Error(LAN_HOST_ERROR);
  return host;
}

/** 其他局域网入口（白名单，已归一化/去重；坏条目忽略）。 */
export function lanHosts() {
  const raw = readSettings().lanHosts;
  const list = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(',') : [];
  const out = [];
  for (const item of list) {
    try {
      const host = normalizeLanHost(item);
      if (host && !out.includes(host)) out.push(host);
    } catch { /* 坏条目忽略：未命中的入口按公网处理，保持 fail closed */ }
  }
  return out;
}

/** 覆盖写入其他局域网入口（空数组清除）。返回归一化后的数组。 */
export function setLanHosts(value) {
  const list = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : [];
  const tunnel = normalizeHost(tunnelHostname());
  const out = [];
  for (const item of list) {
    if (String(item ?? '').trim() === '') continue;
    const host = normalizeLanHost(item);
    if (tunnel && host === tunnel) throw new Error(LAN_HOST_TUNNEL_CONFLICT);
    if (!out.includes(host)) out.push(host);
  }
  const s = readSettings();
  if (out.length) s.lanHosts = out;
  else delete s.lanHosts;
  writeSettings(s);
  return out;
}

/** 添加一条其他入口（幂等）；返回更新后的数组。 */
export function addLanHost(value) {
  const host = normalizeLanHost(value);
  const tunnel = normalizeHost(tunnelHostname());
  if (tunnel && host === tunnel) throw new Error(LAN_HOST_TUNNEL_CONFLICT);
  const list = lanHosts();
  if (!list.includes(host)) setLanHosts([...list, host]);
  return lanHosts();
}

/** 删除一条其他入口（幂等）；返回更新后的数组。 */
export function removeLanHost(value) {
  const raw = String(value ?? '').trim();
  if (!raw) throw new Error(LAN_HOST_ERROR);
  // 删除按匹配语义归一化（允许带端口/尾点），非法/不存在的条目直接视为已删除。
  const host = normalizeHost(raw);
  const list = lanHosts();
  if (host && list.includes(host)) setLanHosts(list.filter((h) => h !== host));
  return lanHosts();
}

/** 局域网主入口（二维码/URL 用）：默认空字符串 = 自动选择。可 IP 或域名。 */
export function lanIpOverride() {
  return readSettings().lanIpOverride ?? '';
}

/** 设置局域网主入口；空字符串清除（回退自动探测 IP）。非法 host 抛错。 */
export function setLanIpOverride(value) {
  const raw = String(value ?? '').trim();
  let host = '';
  if (raw) {
    host = normalizeLanHost(raw);
    const tunnel = normalizeHost(tunnelHostname());
    if (tunnel && host === tunnel) throw new Error(LAN_HOST_TUNNEL_CONFLICT);
  }
  const s = readSettings();
  if (host) s.lanIpOverride = host;
  else delete s.lanIpOverride;
  writeSettings(s);
  return host;
}

// ---------- 访问密码「自定义」标记（issue #33） ----------
// 用户可把公网/局域网密码设成自己固定的 8–64 位密码（英文字母大小写或数字；自定义后不再自动轮换）。
// 标记存 settings.json：publicPinCustom / lanPinCustom。
const PIN_CUSTOM_KEYS = { public: 'publicPinCustom', lan: 'lanPinCustom' };

/** 该 PIN（public | lan）是否用户自定义过（自定义后不自动轮换）。 */
export function pinCustom(which) {
  const key = PIN_CUSTOM_KEYS[which];
  if (!key) return false;
  return readSettings()[key] === true;
}

/** 设置自定义标记，返回新状态。 */
export function setPinCustom(which, on) {
  const key = PIN_CUSTOM_KEYS[which];
  if (!key) return false;
  const s = readSettings();
  s[key] = !!on;
  writeSettings(s);
  return !!on;
}

// ---------- 恢复出厂设置 ----------
// 设置出问题时的临时兜底：删掉 settings.json 即回到出厂默认（文件缺失 = 默认开启，
// 于是局域网访问开、访问密码开、手机端右边栏开、局域网地址自动、公网模式随机）。
// DSH 自身的会话、模型、插件配置都在 $DSH_HOME 的其他目录，不受影响。

/** 删除本机设置文件（不存在也算成功）；返回 true 表示已清空。 */
export function resetSettings() {
  try {
    rmSync(settingsPath(), { force: true });
    return true;
  } catch {
    return false;
  }
}

// ---------- 命名隧道配置（issue #66：固定公网域名） ----------
// 用户在 Cloudflare Zero Trust（Networks → Tunnels）创建命名隧道并复制 Tunnel Token，
// 把自己域名的 ingress Service 指向 http://127.0.0.1:<代理端口>；填到这里后，
// 开启公网改用 `cloudflared tunnel run`，公网地址固定为该域名（重启不再变化）。
// token 是长期凭据：只存本机 0o600 文件，RPC 只写不读（回显仅 tokenSet 布尔值）。

/** 隧道模式：'quick'（默认，随机地址）| 'named'（固定域名）。 */
export function tunnelMode() {
  return readSettings().tunnelMode === 'named' ? 'named' : 'quick';
}

/** 设置隧道模式（持久化）；非法值抛错。 */
export function setTunnelMode(mode) {
  if (mode !== 'quick' && mode !== 'named') {
    throw new Error('隧道模式必须是 quick 或 named | tunnel mode must be quick or named');
  }
  const s = readSettings();
  if (mode === 'quick') delete s.tunnelMode;
  else s.tunnelMode = mode;
  writeSettings(s);
  return mode;
}

/** 命名隧道 Token（未配置返回空字符串）。 */
export function tunnelToken() {
  const v = readSettings().tunnelToken;
  return typeof v === 'string' ? v : '';
}

/**
 * 设置命名隧道 Token（持久化）。空字符串清除；非空要求至少 20 个
 * base64url 字符（Cloudflare Token 是长 base64 串，过短/含空白视为无效）。
 */
export function setTunnelToken(value) {
  const v = String(value ?? '').trim();
  if (v) {
    if (v.length < 20 || !/^[A-Za-z0-9+/_=-]+$/.test(v)) {
      throw new Error('Tunnel Token 格式不对（应为 Cloudflare 后台复制的完整 Token） | invalid tunnel token');
    }
  }
  const s = readSettings();
  if (v) s.tunnelToken = v;
  else delete s.tunnelToken;
  writeSettings(s);
  return v;
}

/** 命名隧道绑定的固定域名（未配置返回空字符串）。 */
export function tunnelHostname() {
  const v = readSettings().tunnelHostname;
  return typeof v === 'string' ? v : '';
}

/**
 * 设置固定域名（持久化）。接受 `https://host/path` 粘贴并归一化为裸域名；
 * 空字符串清除。要求是带点的合法公网域名（局域网主机名/裸 IP 不允许——
 * 那不该走公网密码边界之外的东西）。
 */
export function setTunnelHostname(value) {
  let v = String(value ?? '').trim().toLowerCase();
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#\s]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  if (v) {
    const HOSTNAME_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
    const IS_IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
    if (IS_IPV4.test(v) || !v.includes('.') || !HOSTNAME_RE.test(v)) {
      throw new Error('固定域名格式不对（如 pocket.example.com） | invalid tunnel hostname');
    }
    // 同一个域名不能既是局域网入口又是公网固定隧道：cloudflared 回连时 Host 就是它、
    // 源地址是 127.0.0.1，若命中白名单会把公网入口降级成局域网密码（§6.3）。
    const lanEntries = [lanIpOverride(), ...lanHosts()].map((h) => normalizeHost(h)).filter(Boolean);
    if (lanEntries.includes(v)) {
      throw new Error('该域名已在局域网入口中，不能同时作为公网固定隧道（请二选一） | '
        + 'this hostname is already a LAN entry; use it for only one of LAN or public');
    }
  }
  const s = readSettings();
  if (v) s.tunnelHostname = v;
  else delete s.tunnelHostname;
  writeSettings(s);
  return v;
}

// ---------- 代理端口（issue #70） ----------
// 局域网代理的监听端口（默认 3081）。插件模式下唯一改法就是写 settings.json 的
// proxyPort 字段（CLI 模式可用 dsh-pocket --port）。允许范围 1-65535；
// 端口已被占用时 dsh web 启动会直接抛 EADDRINUSE（保持原行为），不必在 setter 校验。
/** 当前代理端口（0 = 用默认 3081）。 */
export function proxyPort() {
  const v = Number(readSettings().proxyPort);
  return Number.isInteger(v) && v >= 1 && v <= 65535 ? v : 0;
}

/** 设置代理端口（持久化）。空/0/非法值清除，回退默认 3081。 */
export function setProxyPort(value) {
  const n = Number(value);
  const s = readSettings();
  if (Number.isInteger(n) && n >= 1 && n <= 65535) s.proxyPort = n;
  else delete s.proxyPort;
  writeSettings(s);
  return proxyPort();
}

// ---------- cloudflared 路径（issue #45：远程 Linux 服务器下载源不可达时手动指定） ----------
// Linux 服务器在国内/部分企业网下，所有 CDN 源（GitHub / ghproxy / gh.ddlc / gh-proxy）
// 都连不上时，下载 cloudflared 二进制始终失败。允许用户在 settings.json 里**写死
// 一个已经存在 / 自己上传的 cloudflared 路径**，跳过下载。`lib/tunnel.mjs` 的
// `resolveCloudflared` 启动时会优先读 `process.env.DSH_POCKET_CLOUDFLARED`，
// 找不到再回退到 PATH 探测和下载。`lib/index.js` 在插件 apply 时把 settings
// 的这个值写入 env，确保 service 走自定义路径。
// 空字符串 = 清除，回退到默认行为（PATH 探测 + 下载）。
/** 当前 cloudflared 自定义路径（空 = 用默认）。 */
export function cloudflaredPath() {
  return readSettings().cloudflaredPath ?? '';
}

/** 设置 cloudflared 自定义路径。空字符串清除（回退到 PATH 探测 + 下载）。 */
export function setCloudflaredPath(value) {
  const v = String(value ?? '').trim();
  const s = readSettings();
  if (v) s.cloudflaredPath = v;
  else delete s.cloudflaredPath;
  writeSettings(s);
  return v;
}
