// IPv4, IPv6 and CIDR calculations. Addresses are handled as unsigned
// integers (IPv4) and BigInt (IPv6) to avoid 32-bit sign errors.

import { classifyIpv4, classifyIpv6, parseIpv4, parseIpv6, type IocClass } from '../../lib/ioc';

export function ipv4ToInt(octets: readonly number[]): number {
  return (((octets[0] as number) << 24) >>> 0) + ((octets[1] as number) << 16) + ((octets[2] as number) << 8) + (octets[3] as number);
}

export function intToIpv4(value: number): string {
  const v = value >>> 0;
  return [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

export function prefixToMask(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

export interface Ipv4Info {
  address: string;
  integer: number;
  hex: string;
  binary: string;
  octal: string;
  addressClass: IocClass;
  reverseDns: string;
}

export function ipv4Info(input: string): Ipv4Info | null {
  const octets = parseIpv4(input.trim());
  if (!octets) return null;
  const integer = ipv4ToInt(octets);
  return {
    address: octets.join('.'),
    integer,
    hex: `0x${integer.toString(16).padStart(8, '0')}`,
    binary: octets.map((octet) => octet.toString(2).padStart(8, '0')).join('.'),
    octal: octets.map((octet) => `0${octet.toString(8)}`).join('.'),
    addressClass: classifyIpv4(octets),
    reverseDns: `${[...octets].reverse().join('.')}.in-addr.arpa`,
  };
}

export interface Ipv4Subnet {
  input: string;
  prefix: number;
  network: string;
  broadcast: string;
  mask: string;
  wildcard: string;
  firstHost: string;
  lastHost: string;
  /** Addresses in the block. */
  total: number;
  /** Usable host addresses: total − 2, except /31 (RFC 3021, 2 hosts) and /32 (1 host). */
  usable: number;
  addressClass: IocClass;
  /** True when the address given was not the network address of the block. */
  hostBitsSet: boolean;
}

/** Accepts "a.b.c.d/nn", "a.b.c.d nn" or "a.b.c.d 255.255.255.0". */
export function ipv4Subnet(input: string): Ipv4Subnet | null {
  const match = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*(?:\/\s*|\s+)(\d{1,2}|\d{1,3}(?:\.\d{1,3}){3})\s*$/.exec(input);
  if (!match) return null;
  const octets = parseIpv4(match[1] as string);
  if (!octets) return null;
  let prefix: number;
  const maskPart = match[2] as string;
  if (maskPart.includes('.')) {
    const maskOctets = parseIpv4(maskPart);
    if (!maskOctets) return null;
    // A netmask is contiguous ones followed by zeros over all 32 bits. Wildcard
    // (inverse) masks such as 0.0.0.255 are rejected rather than misread.
    const bits = ipv4ToInt(maskOctets).toString(2).padStart(32, '0');
    if (!/^1*0*$/.test(bits)) return null;
    prefix = bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
  } else {
    prefix = Number(maskPart);
  }
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefixToMask(prefix);
  const address = ipv4ToInt(octets);
  const network = (address & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = 2 ** (32 - prefix);
  let first = network;
  let last = broadcast;
  let usable = total;
  if (prefix <= 30) {
    first = network + 1;
    last = broadcast - 1;
    usable = total - 2;
  }
  return {
    input: input.trim(),
    prefix,
    network: intToIpv4(network),
    broadcast: intToIpv4(broadcast),
    mask: intToIpv4(mask),
    wildcard: intToIpv4(~mask >>> 0),
    firstHost: intToIpv4(first),
    lastHost: intToIpv4(last),
    total,
    usable,
    addressClass: classifyIpv4(octets),
    hostBitsSet: network !== address,
  };
}

/** Splits a block into equal subnets of a longer prefix (at most 256 rows). */
export function splitSubnet(subnet: Ipv4Subnet, newPrefix: number, limit = 256): { network: string; broadcast: string }[] | null {
  if (!Number.isInteger(newPrefix) || newPrefix < subnet.prefix || newPrefix > 32) return null;
  const start = ipv4ToInt(parseIpv4(subnet.network) as number[]);
  const size = 2 ** (32 - newPrefix);
  const count = Math.min(2 ** (newPrefix - subnet.prefix), limit);
  return Array.from({ length: count }, (_, index) => {
    const network = start + index * size;
    return { network: intToIpv4(network), broadcast: intToIpv4(network + size - 1) };
  });
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

export function groupsToBigInt(groups: readonly number[]): bigint {
  return groups.reduce((acc, group) => (acc << 16n) | BigInt(group), 0n);
}

export function bigIntToGroups(value: bigint): number[] {
  return Array.from({ length: 8 }, (_, index) => Number((value >> BigInt((7 - index) * 16)) & 0xffffn));
}

export function expandIpv6(groups: readonly number[]): string {
  return groups.map((group) => group.toString(16).padStart(4, '0')).join(':');
}

/** Canonical text form defined by RFC 5952 section 4. */
export function compressIpv6(groups: readonly number[]): string {
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < 8; ) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < 8 && groups[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  const hex = groups.map((group) => group.toString(16));
  // 4.2.2: "::" must not shorten a single 16-bit 0 field.
  if (bestLength < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

export interface Ipv6Info {
  compressed: string;
  expanded: string;
  addressClass: IocClass;
  reverseDns: string;
  /** Embedded IPv4 address for IPv4-mapped (::ffff:0:0/96) addresses. */
  mappedIpv4: string | null;
  prefix: number | null;
  network: string | null;
  lastAddress: string | null;
  /** Number of addresses in the prefix, as a decimal string (2^128 does not fit a number). */
  size: string | null;
}

export function ipv6Info(input: string): Ipv6Info | null {
  const match = /^\s*([0-9a-fA-F:.]+)\s*(?:\/\s*(\d{1,3}))?\s*$/.exec(input);
  if (!match) return null;
  const groups = parseIpv6(match[1] as string);
  if (!groups) return null;
  const prefix = match[2] === undefined ? null : Number(match[2]);
  if (prefix !== null && prefix > 128) return null;
  const nibbles = groups.map((group) => group.toString(16).padStart(4, '0')).join('').split('').reverse().join('.');
  const mapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  let network: string | null = null;
  let lastAddress: string | null = null;
  let size: string | null = null;
  if (prefix !== null) {
    const value = groupsToBigInt(groups);
    const hostBits = BigInt(128 - prefix);
    const mask = ((1n << 128n) - 1n) ^ ((1n << hostBits) - 1n);
    const start = value & mask;
    network = compressIpv6(bigIntToGroups(start));
    lastAddress = compressIpv6(bigIntToGroups(start | ((1n << hostBits) - 1n)));
    size = (1n << hostBits).toString();
  }
  return {
    compressed: compressIpv6(groups),
    expanded: expandIpv6(groups),
    addressClass: classifyIpv6(groups),
    reverseDns: `${nibbles}.ip6.arpa`,
    mappedIpv4: mapped ? `${(groups[6] as number) >> 8}.${(groups[6] as number) & 255}.${(groups[7] as number) >> 8}.${(groups[7] as number) & 255}` : null,
    prefix,
    network,
    lastAddress,
    size,
  };
}
