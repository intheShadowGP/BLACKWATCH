import { describe, expect, it } from 'vitest';
import { MAX_IOC_INPUT_CHARS, classifyIpv4, defang, extractIocs, parseIpv4, parseIpv6, refang, validateIoc } from './ioc';

const values = (text: string, type: string) =>
  extractIocs(text).iocs.filter((ioc) => ioc.type === type).map((ioc) => ioc.value);

describe('refang / defang', () => {
  it('reverses common defanging', () => {
    expect(refang('hxxps://evil[.]example[.]com/a')).toBe('https://evil.example.com/a');
    expect(refang('user[at]example(.)org 10[.]0[.]0[.]1 2001[:]db8[:][:]1')).toBe('user@example.org 10.0.0.1 2001:db8::1');
  });

  it('defangs by type', () => {
    expect(defang({ type: 'url', value: 'https://a.example/x' })).toBe('hxxps://a[.]example/x');
    expect(defang({ type: 'ipv4', value: '8.8.8.8' })).toBe('8[.]8[.]8[.]8');
    expect(defang({ type: 'email', value: 'a@b.example' })).toBe('a[@]b[.]example');
    expect(defang({ type: 'sha256', value: 'ab'.repeat(32) })).toBe('ab'.repeat(32));
  });
});

describe('IPv4', () => {
  it('parses valid addresses only', () => {
    expect(parseIpv4('192.168.1.10')).toEqual([192, 168, 1, 10]);
    for (const invalid of ['256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', '1.2.3.-4', 'a.b.c.d', '']) {
      expect(parseIpv4(invalid), invalid).toBeNull();
    }
  });

  it.each([
    ['8.8.8.8', 'public'],
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['172.32.0.1', 'public'],
    ['192.168.0.1', 'private'],
    ['127.0.0.1', 'loopback'],
    ['169.254.169.254', 'linkLocal'],
    ['100.64.0.1', 'sharedAddressSpace'],
    ['192.0.2.1', 'documentation'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'reserved'],
    ['0.0.0.0', 'unspecified'],
  ])('classifies %s as %s', (address, expected) => {
    expect(classifyIpv4(parseIpv4(address) as number[])).toBe(expected);
  });
});

describe('IPv6', () => {
  it.each(['::1', '::', '2001:db8::1', 'fe80::1ff:fe23:4567:890a', '2001:0db8:0000:0000:0000:ff00:0042:8329', '::ffff:192.0.2.1', '64:ff9b::192.0.2.33', '1:2:3:4:5:6:7:8'])(
    'accepts %s',
    (address) => {
      expect(parseIpv6(address)).toHaveLength(8);
    },
  );

  it.each(['', ':', ':::', '1::2::3', '12345::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', 'g::1', '::ffff:999.0.2.1', '12:30:45', 'fe80::1%eth0'])(
    'rejects %s',
    (address) => {
      expect(parseIpv6(address)).toBeNull();
    },
  );

  it('expands the embedded IPv4 form', () => {
    expect(parseIpv6('::ffff:192.0.2.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201]);
  });
});

describe('validateIoc', () => {
  it.each([
    ['8.8.8.8', 'ipv4'],
    ['2001:db8::1', 'ipv6'],
    ['Example.COM', 'domain'],
    ['hxxp://example[.]com/path?q=1', 'url'],
    ['Analyst@Example.org', 'email'],
    ['d41d8cd98f00b204e9800998ecf8427e', 'md5'],
    ['DA39A3EE5E6B4B0D3255BFEF95601890AFD80709', 'sha1'],
    ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256'],
    ['a'.repeat(128), 'sha512'],
  ])('%s is %s', (input, type) => {
    expect(validateIoc(input)?.type).toBe(type);
  });

  it('normalises case where the type is case-insensitive', () => {
    expect(validateIoc('Example.COM')?.value).toBe('example.com');
    expect(validateIoc('Analyst@Example.org')?.value).toBe('Analyst@example.org');
    expect(validateIoc('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709')?.value).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  });

  it.each([
    '',
    '   ',
    'not an indicator',
    'example.notarealtld',
    '-bad.example.com',
    'javascript:alert(1)',
    'ftp://example.com/file',
    'https://user:secret@example.com/',
    'https://',
    'abc123',
    'a@b',
    '<script>alert(1)</script>',
    `https://example.com/${'a'.repeat(3000)}`,
  ])('rejects %j', (input) => {
    expect(validateIoc(input)).toBeNull();
  });
});

describe('extractIocs', () => {
  it('extracts and classifies indicators from mixed text', () => {
    const text = `
      Beacon to hxxps://c2.badness-example[.]com/gate.php?id=7 from 10.0.0.5 and 203.0.113.9.
      Sender: phisher@mail.example.org. Payload sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,
      md5 d41d8cd98f00b204e9800998ecf8427e. Resolver 2001:db8::53. Also seen: update.example.net, 10.0.0.5.`;
    const { iocs, truncated } = extractIocs(text);
    expect(truncated).toBe(false);
    expect(values(text, 'url')).toEqual(['https://c2.badness-example.com/gate.php?id=7']);
    expect(values(text, 'email')).toEqual(['phisher@mail.example.org']);
    expect(values(text, 'sha256')).toHaveLength(1);
    expect(values(text, 'md5')).toHaveLength(1);
    expect(values(text, 'ipv6')).toEqual(['2001:db8::53']);
    expect(values(text, 'domain')).toEqual(['update.example.net']);
    const internal = iocs.find((ioc) => ioc.value === '10.0.0.5');
    expect(internal).toMatchObject({ type: 'ipv4', addressClass: 'private', count: 2 });
    expect(iocs.find((ioc) => ioc.value === '203.0.113.9')?.addressClass).toBe('documentation');
  });

  it('does not report the host of a URL or of an e-mail address a second time', () => {
    expect(values('see https://portal.example.com/login and admin@corp.example.com', 'domain')).toEqual([]);
  });

  it('strips trailing punctuation from URLs', () => {
    expect(values('Visit https://example.com/a.', 'url')).toEqual(['https://example.com/a']);
    expect(values('(https://example.com/b), then', 'url')).toEqual(['https://example.com/b)']);
  });

  it('ignores file names, code scope operators, times and out-of-range addresses', () => {
    const text = 'Dropped invoice.pdf and run.sh; called std::string and Foo::bar at 12:30:45; version 999.1.1.1; MAC 00:1a:2b:3c:4d:5e';
    expect(extractIocs(text).iocs).toEqual([]);
  });

  it('does not treat a longer hexadecimal run as a hash', () => {
    expect(extractIocs('a'.repeat(33)).iocs).toEqual([]);
    expect(extractIocs('a'.repeat(65)).iocs).toEqual([]);
  });

  it('never returns markup as an indicator', () => {
    const { iocs } = extractIocs('<script src="https://cdn.example.com/x.js"></script><img src=x onerror=alert(1)>');
    expect(iocs.map((ioc) => ioc.value)).toEqual(['https://cdn.example.com/x.js']);
  });

  it('rejects URLs that embed credentials', () => {
    expect(values('https://admin:hunter2@intranet.example.com/', 'url')).toEqual([]);
  });

  it('truncates oversized input and reports it', () => {
    const text = `${'x '.repeat(MAX_IOC_INPUT_CHARS / 2)} 8.8.8.8`;
    const result = extractIocs(text);
    expect(result.truncated).toBe(true);
    expect(result.iocs).toEqual([]);
  });

  it('handles pathological input quickly', () => {
    const started = performance.now();
    extractIocs(`${'a.'.repeat(50000)} ${':'.repeat(50000)} ${'1.'.repeat(50000)} ${'@'.repeat(20000)}`);
    expect(performance.now() - started).toBeLessThan(3000);
  });
});
