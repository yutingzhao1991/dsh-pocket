// Small shared helpers for the optional LAN IP override / LAN entry allowlist.
import { networkInterfaces } from 'node:os';
import { isIP } from 'node:net';

/** @param {unknown} value
 *  @returns {boolean} */
export function isValidIpv4(value) {
  const m = String(value ?? '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return m !== null && m.slice(1).every((part) => {
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

/** IPv4 字符串 → 32 位无符号整数；非法返回 null。 */
function ipv4ToInt(value) {
  const ip = String(value ?? '').trim();
  if (!isValidIpv4(ip)) return null;
  return ip.split('.').reduce((n, part) => n * 256 + Number(part), 0);
}

/**
 * 判断 IPv4 地址是否落在 CIDR 内（如 `30.174.128.0/19`）。
 * 非法输入一律 false（调用方按不可信处理）。
 */
export function isIpv4InCidr(address, cidr) {
  const [base, bitsRaw] = String(cidr ?? '').trim().split('/');
  const bits = Number(bitsRaw);
  const ip = ipv4ToInt(address);
  const net = ipv4ToInt(base);
  if (ip === null || net === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
  return ((ip & mask) >>> 0) === ((net & mask) >>> 0);
}

/**
 * 来源地址是否属于给定 CIDR 列表（通常由 trustedSubnetsFor 从白名单推导）。
 * **默认不信任任何子网**：调用方必须显式传入授权子网，避免把本机公网网卡
 * 的子网自动当成内网（review P1）。
 * @param {unknown} address
 * @param {string[]} [subnets] 授权 CIDR；不传时一律 false
 */
export function isLocalSubnetAddress(address, subnets = []) {
  let ip = String(address ?? '').trim().toLowerCase();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7); // IPv4-mapped IPv6
  if (isIP(ip) !== 4) return false;
  return (subnets ?? []).some((cidr) => isIpv4InCidr(ip, cidr));
}

/**
 * 从**显式白名单里的 IPv4 入口**推导可信直连子网（review P1）。
 * 只有白名单条目确实是本机某张网卡的地址时，才信任该网卡的 CIDR；
 * 不会因为某张网卡是公网地址就自动信任它。域名条目无法推导子网，
 * 这类入口的公网类别来源仍按 fail closed 处理。
 * @param {string[]} entries 已归一化的白名单条目（IP / 域名）
 * @param {ReturnType<typeof networkInterfaces>} [interfaces] 测试注入
 */
export function trustedSubnetsFor(entries, interfaces = networkInterfaces()) {
  const ips = new Set((entries ?? []).filter((entry) => isIP(entry) === 4));
  const subnets = [];
  for (const addrs of Object.values(interfaces ?? {})) {
    for (const addr of addrs ?? []) {
      if (addr.family !== 'IPv4' || !addr.address || !ips.has(addr.address)) continue;
      const cidr = typeof addr.cidr === 'string' && addr.cidr.includes('/') ? addr.cidr : `${addr.address}/32`;
      if (!subnets.includes(cidr)) subnets.push(cidr);
    }
  }
  return subnets;
}