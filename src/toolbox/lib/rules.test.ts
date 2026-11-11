import { describe, expect, it } from 'vitest';
import { detectSignatures, FILE_SIGNATURES, SIGNATURE_HEAD_BYTES } from './reference';
import { parseSigma, parseYara } from './rules';

// Synthetic rules written for these tests.
const YARA = `
import "pe"
include "common.yar"

/* block comment with { braces } and "quotes" */
private rule Demo_Rule : tag_one TagTwo
{
    meta:
        author = "BLACKWATCH tests" // trailing comment
        score = 70
        offset = -1
        enabled = true
    strings:
        $text = "brace } and // not a comment" nocase wide ascii
        $hex = { 4D 5A [2-4] ( 90 | 00 ) ?? }
        $re = /https?:\\/\\/[a-z]{3,}\\.example/i
        $x = "key" xor(0x01-0xff) base64
    condition:
        uint16(0) == 0x5A4D and (any of ($text, $hex) or #re > 2) and filesize < 2MB
}

rule second { condition: true }
`;

describe('parseYara', () => {
  it('extracts imports, rules, tags, meta, strings and condition', () => {
    const result = parseYara(YARA);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.imports).toEqual(['pe']);
    expect(result.includes).toEqual(['common.yar']);
    expect(result.rules.map((rule) => rule.name)).toEqual(['Demo_Rule', 'second']);
    const [rule] = result.rules;
    expect(rule).toMatchObject({ modifiers: ['private'], tags: ['tag_one', 'TagTwo'], line: 6 });
    expect(rule?.meta).toEqual([
      { key: 'author', value: 'BLACKWATCH tests' },
      { key: 'score', value: '70' },
      { key: 'offset', value: '-1' },
      { key: 'enabled', value: 'true' },
    ]);
    expect(rule?.strings.map((entry) => [entry.identifier, entry.kind, entry.modifiers])).toEqual([
      ['$text', 'text', ['nocase', 'wide', 'ascii']],
      ['$hex', 'hex', []],
      ['$re', 'regex', []],
      ['$x', 'text', ['xor(0x01-0xff)', 'base64']],
    ]);
    expect(rule?.strings[0]?.value).toBe('"brace } and // not a comment"');
    expect(rule?.condition).toContain('uint16(0) == 0x5A4D');
    expect(result.rules[1]?.condition).toBe('true');
  });

  it.each([
    ['rule a { condition: true', 'not closed'],
    ['rule { condition: true }', 'rule name'],
    ['rule a { strings: $s = "x" }', 'no condition'],
    ['rule a { strings: $s = "unterminated }', 'Unterminated string'],
    ['/* never closed', 'Unterminated comment'],
    ['banana', "Expected 'rule'"],
  ])('reports %j as invalid', (source, message) => {
    const result = parseYara(source);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message).toContain(message);
  });

  it('refuses oversized input', () => {
    expect(parseYara('x'.repeat(1_000_001)).ok).toBe(false);
  });
});

const SIGMA = `
title: Synthetic suspicious encoded command
id: 00000000-0000-4000-8000-000000000001
status: experimental
description: Test rule written for BLACKWATCH.
author: BLACKWATCH tests
date: 2026-01-10
references:
  - https://example.com/reference
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: '\\powershell.exe'
  selection_cli:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: all of selection_*
falsepositives:
  - Administrative scripts
level: high
---
title: Second
logsource: { product: linux }
detection:
  keywords: [ 'sudo' ]
  condition: keywords
`;

describe('parseSigma', () => {
  it('extracts metadata, ATT&CK techniques and detection blocks from several documents', async () => {
    const result = await parseSigma(SIGMA);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.rules).toHaveLength(2);
    const [rule] = result.rules;
    expect(rule).toMatchObject({ title: 'Synthetic suspicious encoded command', status: 'experimental', level: 'high', date: '2026-01-10', techniques: ['T1059.001'], logsource: { product: 'windows', category: 'process_creation' }, condition: ['all of selection_*'], falsepositives: ['Administrative scripts'] });
    expect(rule?.detection.map((block) => block.name)).toEqual(['selection_img', 'selection_cli']);
    expect(rule?.detection[1]?.body).toContain('CommandLine|contains');
  });

  it.each([
    ['title: [unclosed', 'column'],
    ['just a string', 'mapping'],
    ['title: x\ndetection: nope', "'detection'"],
    ['a: 1\na: 2\ntitle: t\ndetection: {condition: x}', 'unique'],
    ['', 'No rule'],
  ])('rejects %j', async (source, fragment) => {
    const result = await parseSigma(source);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.message.toLowerCase()).toContain(fragment.toLowerCase());
  });

  it('bounds alias expansion', async () => {
    const bomb = ['a: &a ["x","x","x","x","x","x","x","x","x","x"]', ...Array.from({ length: 8 }, (_, level) => `${String.fromCharCode(98 + level)}: &${String.fromCharCode(98 + level)} [${Array(10).fill(`*${String.fromCharCode(97 + level)}`).join(',')}]`), 'title: t', 'detection: {condition: x}'].join('\n');
    const result = await parseSigma(bomb);
    expect(result.ok).toBe(false);
  });
});

describe('file signatures', () => {
  const bytesOf = (...values: number[]) => new Uint8Array(values);

  it.each([
    ['pe', bytesOf(0x4d, 0x5a, 0x90, 0x00)],
    ['elf', bytesOf(0x7f, 0x45, 0x4c, 0x46, 0x02)],
    ['pdf', new TextEncoder().encode('%PDF-1.7')],
    ['zip', bytesOf(0x50, 0x4b, 0x03, 0x04)],
    ['png', bytesOf(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)],
    ['riffWebp', new TextEncoder().encode('RIFF\u0000\u0000\u0000\u0000WEBPVP8 ')],
  ])('detects %s', (id, head) => {
    expect(detectSignatures(head).map((signature) => signature.id)).toContain(id);
  });

  it('detects signatures at an offset', () => {
    const tar = new Uint8Array(512);
    tar.set(new TextEncoder().encode('ustar'), 257);
    expect(detectSignatures(tar).map((signature) => signature.id)).toEqual(['tar']);
  });

  it('returns nothing for unknown or short input', () => {
    expect(detectSignatures(new TextEncoder().encode('hello world'))).toEqual([]);
    expect(detectSignatures(new Uint8Array())).toEqual([]);
  });

  it('defines every signature with a reference and a reachable head size', () => {
    for (const signature of FILE_SIGNATURES) {
      expect(signature.reference.url, signature.id).toMatch(/^https:\/\//);
      expect(signature.offset + signature.bytes.length).toBeLessThanOrEqual(SIGNATURE_HEAD_BYTES);
    }
    expect(new Set(FILE_SIGNATURES.map((signature) => signature.id)).size).toBe(FILE_SIGNATURES.length);
  });
});
