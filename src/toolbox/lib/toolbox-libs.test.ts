import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { analyzeJson, decodeJwt, entropyProfile, formatJson, shannonEntropy } from './analysis';
import { base64Decode, base64Encode, fromHex, hexDump, printableText, toHex, utf8DecodeStrict, utf8Encode } from './bytes';
import { compressIpv6, ipv4Info, ipv4Subnet, ipv6Info, splitSubnet } from './net';
import { parseIpv6 } from '../../lib/ioc';
import { analyzeHeaders, analyzePassword, parseHeaders, parseUrl } from './web';

const b64url = (value: unknown) => base64Encode(utf8Encode(JSON.stringify(value)), true);

describe('bytes', () => {
  it('round-trips Base64 against Node for random data, standard and URL-safe', () => {
    for (const length of [0, 1, 2, 3, 4, 5, 31, 32, 33, 1000]) {
      const bytes = new Uint8Array(randomBytes(length));
      const standard = base64Encode(bytes);
      expect(standard).toBe(Buffer.from(bytes).toString('base64'));
      expect(base64Encode(bytes, true)).toBe(Buffer.from(bytes).toString('base64url'));
      const decoded = base64Decode(standard);
      expect(decoded.ok && [...decoded.bytes]).toEqual([...bytes]);
      const urlDecoded = base64Decode(base64Encode(bytes, true));
      expect(urlDecoded.ok && [...urlDecoded.bytes]).toEqual([...bytes]);
    }
  });

  it('encodes text as UTF-8', () => {
    expect(base64Encode(utf8Encode('héllo ✓'))).toBe(Buffer.from('héllo ✓').toString('base64'));
  });

  it.each(['abc$', 'ab=c', 'a', 'abcde', 'ab-+'])('rejects invalid Base64 %j', (input) => {
    expect(base64Decode(input).ok).toBe(false);
  });

  it('ignores whitespace in Base64 and accepts missing padding', () => {
    const decoded = base64Decode('aGVs\nbG8');
    expect(decoded.ok && new TextDecoder().decode(decoded.bytes)).toBe('hello');
  });

  it('parses hexadecimal in common dump formats', () => {
    for (const input of ['48656c6c6f', '48 65 6c 6c 6f', '48:65:6C:6C:6F', '\\x48\\x65\\x6c\\x6c\\x6f', '0x48 0x65 0x6c 0x6c 0x6f']) {
      const parsed = fromHex(input);
      expect(parsed.ok && new TextDecoder().decode(parsed.bytes), input).toBe('Hello');
    }
    expect(fromHex('abc')).toEqual({ ok: false, reason: 'odd' });
    expect(fromHex('zz')).toMatchObject({ ok: false, reason: 'invalid' });
    expect(toHex(new Uint8Array([0, 255, 16]), ' ')).toBe('00 ff 10');
  });

  it('refuses to decode invalid UTF-8 instead of producing replacement characters', () => {
    expect(utf8DecodeStrict(new Uint8Array([0xc3, 0x28]))).toBeNull();
    expect(printableText(new Uint8Array([0x68, 0x00, 0x69]))).toBeNull();
    expect(printableText(utf8Encode('line\nnext\ttab'))).toBe('line\nnext\ttab');
  });

  it('builds a hex dump with offsets and printable characters', () => {
    expect(hexDump(utf8Encode('ABC\n'))).toBe(`00000000  ${'41 42 43 0a'.padEnd(47)}  ABC.`);
  });
});

describe('entropy', () => {
  it('is 0 for empty and constant input and 8 for all byte values equally', () => {
    expect(shannonEntropy(new Uint8Array()).bitsPerByte).toBe(0);
    expect(shannonEntropy(new Uint8Array(100).fill(7)).bitsPerByte).toBe(0);
    const uniform = new Uint8Array(512).map((_, index) => index % 256);
    expect(shannonEntropy(uniform).bitsPerByte).toBeCloseTo(8, 10);
    expect(shannonEntropy(uniform).distinctBytes).toBe(256);
  });

  it('gives 1 bit per byte for two equally frequent values', () => {
    expect(shannonEntropy(utf8Encode('abababab')).bitsPerByte).toBeCloseTo(1, 10);
  });

  it('profiles a file in windows', () => {
    const bytes = new Uint8Array(8192);
    bytes.set(new Uint8Array(randomBytes(4096)), 4096);
    const profile = entropyProfile(bytes, 4096);
    expect(profile).toHaveLength(2);
    expect(profile[0]).toBe(0);
    expect(profile[1]).toBeGreaterThan(7.9);
  });
});

describe('analyzeJson', () => {
  it('accepts valid JSON and matches JSON.parse', () => {
    const text = '{"a":[1,2,{"b":null}],"c":"\\u00e9\\n","d":-1.5e3,"e":true}';
    const result = analyzeJson(text);
    expect(result.ok && JSON.stringify(result.value)).toBe(JSON.stringify(JSON.parse(text)));
    expect(result.ok && result.issues).toEqual([]);
    expect(result.ok && result.depth).toBe(3);
  });

  it.each([
    ['{"a":1,}', 1, 8],
    ["{'a':1}", 1, 2],
    ['[1,2', 1, 5],
    ['{"a":01}', 1, 7],
    ['{"a":1}\n x', 2, 2],
    ['"tab\there"', 1, 5],
    ['{"a":NaN}', 1, 6],
    ['', 1, 1],
    ['"\\q"', 1, 2],
  ])('reports the position of the error in %j', (text, line, column) => {
    const result = analyzeJson(text);
    expect(result.ok).toBe(false);
    expect(!result.ok && [result.line, result.column]).toEqual([line, column]);
  });

  it('flags duplicate keys and integers that lose precision', () => {
    const result = analyzeJson('{\n  "id": 9007199254740993,\n  "id": 2,\n  "big": 1e400\n}');
    expect(result.ok && result.issues.map((issue) => [issue.kind, issue.line, issue.detail])).toEqual([
      ['unsafeInteger', 2, '9007199254740993'],
      ['duplicateKey', 3, 'id'],
      ['precisionLoss', 4, '1e400'],
    ]);
  });

  it('does not let __proto__ keys pollute prototypes', () => {
    const result = analyzeJson('{"__proto__": {"polluted": true}}');
    expect(result.ok).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(result.ok && formatJson(result.value, null)).toBe('{"__proto__":{"polluted":true}}');
  });

  it('limits nesting depth without overflowing the stack', () => {
    const result = analyzeJson(`${'['.repeat(100_000)}${']'.repeat(100_000)}`);
    expect(result.ok).toBe(false);
  });

  it('formats and minifies', () => {
    const result = analyzeJson('{ "a" : [ 1 ] }');
    expect(result.ok && formatJson(result.value, 2)).toBe('{\n  "a": [\n    1\n  ]\n}');
    expect(result.ok && formatJson(result.value, null)).toBe('{"a":[1]}');
  });
});

describe('decodeJwt', () => {
  const now = Date.parse('2026-01-10T00:00:00Z');
  const header = b64url({ alg: 'RS256', typ: 'JWT' });

  it('decodes header and payload, without claiming verification', () => {
    const token = `${header}.${b64url({ sub: 'alice', exp: now / 1000 + 3600, iat: now / 1000 })}.c2lnbmF0dXJl`;
    const result = decodeJwt(token, now);
    expect(result).toMatchObject({ ok: true, kind: 'JWS', header: { alg: 'RS256' }, payload: { sub: 'alice' }, signaturePresent: true, warnings: [] });
    expect(result.ok && result.times.map((time) => time.claim)).toEqual(['exp', 'iat']);
  });

  it('flags alg none, missing signature, expiry and symmetric algorithms', () => {
    const none = decodeJwt(`${b64url({ alg: 'none' })}.${b64url({ sub: 'x', exp: now / 1000 - 10 })}.`, now);
    expect(none.ok && none.warnings).toEqual(['algNone', 'expired']);
    expect(none.ok && none.signaturePresent).toBe(false);
    const hs = decodeJwt(`${b64url({ alg: 'HS256' })}.${b64url({ nbf: now / 1000 + 60 })}.sig`, now);
    expect(hs.ok && hs.warnings).toEqual(['symmetricAlg', 'noExpiry', 'notYetValid']);
  });

  it('recognises an encrypted token without decrypting it', () => {
    expect(decodeJwt(`${b64url({ alg: 'RSA-OAEP', enc: 'A256GCM' })}.a.b.c.d`, now)).toMatchObject({ ok: true, kind: 'JWE', payload: null });
  });

  it.each([
    ['not a token', 'segments'],
    ['a.b', 'segments'],
    ['!!!.e30.x', 'base64'],
    [`${base64Encode(utf8Encode('not json'), true)}.e30.x`, 'json'],
    [`${b64url([1, 2])}.e30.x`, 'json'],
  ])('rejects %j', (token, reason) => {
    expect(decodeJwt(token, now)).toMatchObject({ ok: false, reason });
  });
});

describe('IPv4 and CIDR', () => {
  it('describes an address', () => {
    expect(ipv4Info('192.168.1.10')).toMatchObject({ integer: 3232235786, hex: '0xc0a8010a', binary: '11000000.10101000.00000001.00001010', addressClass: 'private', reverseDns: '10.1.168.192.in-addr.arpa' });
    expect(ipv4Info('255.255.255.255')).toMatchObject({ integer: 4294967295, hex: '0xffffffff' });
    expect(ipv4Info('256.0.0.1')).toBeNull();
  });

  it.each([
    ['10.0.0.0/8', { network: '10.0.0.0', broadcast: '10.255.255.255', mask: '255.0.0.0', wildcard: '0.255.255.255', firstHost: '10.0.0.1', lastHost: '10.255.255.254', total: 16777216, usable: 16777214 }],
    ['192.168.1.77/24', { network: '192.168.1.0', broadcast: '192.168.1.255', usable: 254, hostBitsSet: true }],
    ['192.168.1.77 255.255.255.192', { prefix: 26, network: '192.168.1.64', broadcast: '192.168.1.127', usable: 62 }],
    ['0.0.0.0/0', { network: '0.0.0.0', broadcast: '255.255.255.255', mask: '0.0.0.0', total: 4294967296, usable: 4294967294 }],
    ['10.1.1.1/31', { network: '10.1.1.0', broadcast: '10.1.1.1', firstHost: '10.1.1.0', lastHost: '10.1.1.1', total: 2, usable: 2 }],
    ['255.255.255.255/32', { network: '255.255.255.255', broadcast: '255.255.255.255', mask: '255.255.255.255', wildcard: '0.0.0.0', total: 1, usable: 1, hostBitsSet: false }],
    ['200.1.2.3/1', { network: '128.0.0.0', broadcast: '255.255.255.255' }],
  ])('computes %s', (input, expected) => {
    expect(ipv4Subnet(input)).toMatchObject(expected);
  });

  it.each(['10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0', '10.0.0.0/255.0.255.0', '10.0.0.256/8', 'x/8'])('rejects %s', (input) => {
    expect(ipv4Subnet(input)).toBeNull();
  });

  it('splits a block into subnets', () => {
    const subnet = ipv4Subnet('10.0.0.0/24');
    expect(subnet && splitSubnet(subnet, 26)).toEqual([
      { network: '10.0.0.0', broadcast: '10.0.0.63' },
      { network: '10.0.0.64', broadcast: '10.0.0.127' },
      { network: '10.0.0.128', broadcast: '10.0.0.191' },
      { network: '10.0.0.192', broadcast: '10.0.0.255' },
    ]);
    expect(subnet && splitSubnet(subnet, 23)).toBeNull();
    expect(subnet && splitSubnet(ipv4Subnet('0.0.0.0/0') as never, 32)).toHaveLength(256);
  });
});

describe('IPv6', () => {
  // Examples from RFC 5952, sections 4.1 to 4.3.
  it.each([
    ['2001:0db8:0000:0000:0000:0000:0002:0001', '2001:db8::2:1'],
    ['2001:db8:0:0:0:0:2:1', '2001:db8::2:1'],
    ['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
    ['2001:0:0:1:0:0:0:1', '2001:0:0:1::1'],
    ['2001:db8:0:0:1:0:0:1', '2001:db8::1:0:0:1'],
    ['2001:DB8::AAAA', '2001:db8::aaaa'],
    ['0:0:0:0:0:0:0:0', '::'],
    ['0:0:0:0:0:0:0:1', '::1'],
    ['fe80:0:0:0:0:0:0:0', 'fe80::'],
  ])('compresses %s to %s', (input, expected) => {
    expect(compressIpv6(parseIpv6(input) as number[])).toBe(expected);
  });

  it('describes an address with a prefix', () => {
    expect(ipv6Info('2001:db8:abcd:12::1/48')).toMatchObject({
      compressed: '2001:db8:abcd:12::1',
      expanded: '2001:0db8:abcd:0012:0000:0000:0000:0001',
      addressClass: 'documentation',
      network: '2001:db8:abcd::',
      lastAddress: '2001:db8:abcd:ffff:ffff:ffff:ffff:ffff',
      size: (2n ** 80n).toString(),
    });
    expect(ipv6Info('::/0')).toMatchObject({ network: '::', lastAddress: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', size: (2n ** 128n).toString() });
    expect(ipv6Info('::1/128')).toMatchObject({ network: '::1', lastAddress: '::1', size: '1' });
    expect(ipv6Info('::ffff:192.0.2.1')?.mappedIpv4).toBe('192.0.2.1');
    expect(ipv6Info('2001:db8::1')?.reverseDns).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
  });

  it.each(['2001:db8::/129', 'gggg::', '1:2:3:4:5:6:7:8:9', ''])('rejects %j', (input) => {
    expect(ipv6Info(input)).toBeNull();
  });
});

describe('parseUrl', () => {
  it('splits a URL and lists its parameters', () => {
    const parsed = parseUrl('https://user:secret@xn--exmple-cua.example:8443/a%20b/@x?q=1&q=2&r=%3Cs%3E#frag');
    expect(parsed).toMatchObject({ protocol: 'https:', username: 'user', passwordPresent: true, hostname: 'xn--exmple-cua.example', port: '8443', hash: '#frag' });
    expect(parsed?.params).toEqual([{ key: 'q', value: '1' }, { key: 'q', value: '2' }, { key: 'r', value: '<s>' }]);
    expect(parsed?.findings.sort()).toEqual(['atInPath', 'encodedPath', 'nonDefaultPort', 'punycode', 'userinfo']);
  });

  it('flags non-HTTP schemes and IP hosts', () => {
    expect(parseUrl('javascript:alert(1)')?.findings).toContain('nonHttp');
    expect(parseUrl('http://192.0.2.1/')?.findings).toEqual(['ipHost', 'plainHttp']);
  });

  it('rejects relative or oversized input', () => {
    expect(parseUrl('/relative/path')).toBeNull();
    expect(parseUrl(`https://a.example/${'x'.repeat(20_000)}`)).toBeNull();
  });
});

describe('header analysis', () => {
  const raw = [
    'HTTP/1.1 200 OK',
    'Server: nginx/1.18.0',
    'Strict-Transport-Security: max-age=300',
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
    'X-Content-Type-Options: nosniff',
    'Set-Cookie: session=abc; Path=/; HttpOnly',
    'Set-Cookie: pref=1; Secure; HttpOnly; SameSite=Lax',
    'X-Powered-By: PHP/8.1',
    'X-Custom: first',
    '  folded continuation',
    'bad header line',
  ].join('\r\n');
  const { status, headers } = parseHeaders(raw);
  const checks = Object.fromEntries(analyzeHeaders(headers).map((check) => [check.id, check]));

  it('parses status, names and folded values', () => {
    expect(status).toBe('HTTP/1.1 200 OK');
    expect(headers.find((header) => header.name === 'x-custom')?.value).toBe('first folded continuation');
    expect(headers).toHaveLength(8);
  });

  it('reports facts per header', () => {
    expect(checks.hsts).toMatchObject({ state: 'weak', notes: ['hstsShort'] });
    expect(checks.csp).toMatchObject({ state: 'weak', notes: ['cspUnsafeInline', 'cspNoObjectSrc'] });
    expect(checks.frameProtection?.state).toBe('absent');
    expect(checks.contentTypeOptions?.state).toBe('present');
    expect(checks.referrerPolicy?.state).toBe('absent');
    expect(checks.serverDisclosure).toMatchObject({ state: 'weak', notes: ['serverVersion'] });
    expect(checks.poweredBy?.state).toBe('weak');
    expect(checks.cookies?.notes).toEqual(['cookieNoSecure:session', 'cookieNoSameSite:session']);
  });

  it('accepts frame-ancestors as frame protection', () => {
    const result = analyzeHeaders(parseHeaders("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; object-src 'none'").headers);
    expect(result.find((check) => check.id === 'frameProtection')?.state).toBe('present');
    expect(result.find((check) => check.id === 'csp')?.state).toBe('present');
  });
});

describe('analyzePassword', () => {
  it.each(['Password1!', 'P@ssw0rd2024', 'Qwerty123!', 'Azerty2026$', 'Summer2024!', 'Letmein!!!!', 'Admin12345!', 'abcdABCD1234!'])(
    'never rates the guessable password %j above weak',
    (password) => {
      expect(analyzePassword(password).verdict).toBe('weak');
    },
  );

  it('names the patterns it finds', () => {
    expect(analyzePassword('password').findings).toEqual(expect.arrayContaining(['common', 'short', 'singleClass']));
    expect(analyzePassword('P@ssw0rd!').findings).toContain('commonWithAffixes');
    expect(analyzePassword('P4ssw0rd').findings).toEqual(expect.arrayContaining(['commonWithAffixes', 'leet']));
    expect(analyzePassword('Password1!').findings).not.toContain('leet');
    expect(analyzePassword('aaaaaaaaaaaaaaaa').findings).toContain('repeated');
    expect(analyzePassword('xk9-Tq2#mZ7!vL4@').findings).toEqual([]);
  });

  it('reports an upper bound on entropy, not a strength guarantee', () => {
    const result = analyzePassword('xk9-Tq2#mZ7!vL4@');
    expect(result.upperBoundBits).toBeCloseTo(16 * Math.log2(95), 5);
    expect(result.verdict).toBe('noKnownWeakness');
    expect(analyzePassword('').upperBoundBits).toBe(0);
  });
});
