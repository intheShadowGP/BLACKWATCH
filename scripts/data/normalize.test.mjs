import { describe, expect, it } from 'vitest';
import { attackDatasetSchema, certfrDatasetSchema, cveDatasetSchema, kevDatasetSchema } from '../../src/data/schemas.ts';
import { cleanDescription, decodeXml, normalizeAttack, normalizeCertfr, normalizeCve, normalizeCveList, normalizeKev, toIso } from './normalize.mjs';

describe('toIso', () => {
  it('reads dates, zoned timestamps and NVD timestamps without a zone as UTC', () => {
    expect(toIso('2026-11-10')).toBe('2026-11-10T00:00:00.000Z');
    expect(toIso('2026-11-10T18:17:23.490')).toBe('2026-11-10T18:17:23.490Z');
    expect(toIso('Thu, 29 Oct 2026 00:00:00 +0000')).toBe('2026-10-29T00:00:00.000Z');
  });

  it.each(['', '   ', 'not a date', '2026-13-45', null, undefined, 42, {}])('returns null for %j', (value) => {
    expect(toIso(value)).toBeNull();
  });
});

describe('normalizeKev', () => {
  const raw = {
    catalogVersion: '2026.11.10',
    dateReleased: '2026-11-10T19:03:29.8375Z',
    vulnerabilities: [
      { cveID: 'CVE-2026-0001', vendorProject: ' Vendor ', product: 'Product', vulnerabilityName: 'Name', dateAdded: '2026-11-01', shortDescription: 'Desc', requiredAction: 'Patch', dueDate: '2026-11-22', knownRansomwareCampaignUse: 'Known', cwes: ['CWE-78', 'bogus', 'CWE-78'] },
      { cveID: 'CVE-2026-0002', vendorProject: 'V', product: 'P', vulnerabilityName: 'N', dateAdded: '2026-11-09', shortDescription: 'D', requiredAction: 'A', dueDate: '', knownRansomwareCampaignUse: 'maybe' },
      { cveID: 'CVE-2026-0001', vendorProject: 'duplicate', dateAdded: '2026-10-01' },
      { cveID: 'NOT-A-CVE', dateAdded: '2026-11-01' },
      { cveID: 'CVE-2026-0003', dateAdded: 'invalid' },
      null,
      'string entry',
    ],
  };

  it('keeps valid entries, most recent first, without duplicates', () => {
    const data = normalizeKev(raw);
    expect(data.items.map((item) => item.cve)).toEqual(['CVE-2026-0002', 'CVE-2026-0001']);
    expect(data.items[1]).toMatchObject({ vendor: 'Vendor', ransomware: 'Known', cwes: ['CWE-78'], dueDate: '2026-11-22T00:00:00.000Z' });
    expect(data.items[0]).toMatchObject({ ransomware: 'Unknown', dueDate: null, cwes: [] });
    expect(kevDatasetSchema.safeParse(data).success).toBe(true);
  });

  it.each([null, undefined, 'text', 42, [], { vulnerabilities: 'nope' }])('yields no item for malformed input %j', (input) => {
    expect(normalizeKev(input).items).toEqual([]);
  });
});

describe('normalizeCve', () => {
  const wrapper = {
    cve: {
      id: 'CVE-2026-1234',
      published: '2026-11-08T02:16:36.183',
      lastModified: '2026-11-10T18:17:23.490',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'es', value: 'Descripción' }, { lang: 'en', value: '  English description <b>bold</b>  ' }],
      metrics: {
        cvssMetricV31: [
          { source: 'cna@example.com', type: 'Secondary', cvssData: { version: '3.1', vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', baseScore: 7.8, baseSeverity: 'HIGH' } },
          { source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: 9.8, baseSeverity: 'CRITICAL' } },
        ],
        cvssMetricV40: [{ source: 'cna@example.com', type: 'Secondary', cvssData: { vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', baseScore: 9.3, baseSeverity: 'CRITICAL' } }],
      },
      weaknesses: [{ description: [{ lang: 'en', value: 'CWE-287' }, { lang: 'en', value: 'NVD-CWE-noinfo' }] }],
      configurations: [{ nodes: [{ cpeMatch: [
        { vulnerable: true, criteria: 'cpe:2.3:a:ExampleVendor:Example_Product:*:*:*:*:*:*:*:*' },
        { vulnerable: false, criteria: 'cpe:2.3:o:os_vendor:os:*:*:*:*:*:*:*:*' },
        { vulnerable: true, criteria: 'garbage' },
      ] }] }],
      affected: [{ affectedData: [{ vendor: 'go-vendor', product: 'thing' }, { vendor: '', product: 'x' }] }],
      references: [
        { url: 'https://vendor.example/advisory', tags: ['Patch', 'Vendor Advisory'] },
        { url: 'javascript:alert(1)', tags: ['Exploit'] },
        { url: 'ftp://files.example/x' },
        { url: 'https://ok.example/"onmouseover="x' },
      ],
    },
  };

  it('selects fields without altering published values', () => {
    const item = normalizeCve(wrapper);
    expect(item).toMatchObject({
      id: 'CVE-2026-1234',
      published: '2026-11-08T02:16:36.183Z',
      status: 'Analyzed',
      description: 'English description <b>bold</b>',
      cwes: ['CWE-287'],
      products: ['examplevendor:example_product', 'go-vendor:thing'],
    });
    expect(item.cvss3).toEqual({ version: '3.1', score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', source: 'nvd@nist.gov' });
    expect(item.cvss4).toMatchObject({ version: '4.0', score: 9.3, source: 'cna@example.com' });
  });

  it('drops references that are not plain http(s) URLs', () => {
    expect(normalizeCve(wrapper).references).toEqual([{ url: 'https://vendor.example/advisory', tags: ['Patch', 'Vendor Advisory'] }]);
  });

  it('keeps remediation references first within the limit and records the total', () => {
    const references = [
      ...Array.from({ length: 14 }, (_, index) => ({ url: `https://info.example/${index}`, tags: ['Third Party Advisory'] })),
      { url: 'https://vendor.example/fix', tags: ['Patch'] },
      { url: 'https://vendor.example/advisory', tags: ['Vendor Advisory'] },
    ];
    const item = normalizeCve({ cve: { ...wrapper.cve, references } });
    expect(item.referenceCount).toBe(16);
    expect(item.references).toHaveLength(12);
    expect(item.references.slice(0, 2).map((reference) => reference.url)).toEqual(['https://vendor.example/fix', 'https://vendor.example/advisory']);
    expect(item.references[2].url).toBe('https://info.example/0');
  });

  it('leaves scores empty when none is published', () => {
    const item = normalizeCve({ cve: { id: 'CVE-2026-1', published: '2026-01-01', lastModified: '2026-01-01' } });
    expect(item).toBeNull();
    const bare = normalizeCve({ cve: { id: 'CVE-2026-10000', published: '2026-01-01', lastModified: '2026-01-02' } });
    expect(bare).toMatchObject({ cvss3: null, cvss4: null, description: '', cwes: [], products: [], references: [] });
  });

  it.each([null, undefined, {}, { cve: null }, { cve: { id: 'CVE-2026-1234' } }, { cve: { id: 'CVE-2026-1234', published: 'x', lastModified: 'y' } }])(
    'rejects malformed record %j',
    (input) => {
      expect(normalizeCve(input)).toBeNull();
    },
  );

  it('deduplicates on the most recently modified record and validates', () => {
    const older = { cve: { ...wrapper.cve, lastModified: '2026-11-09T00:00:00.000', vulnStatus: 'Received' } };
    const data = normalizeCveList([older, wrapper, null, { cve: { id: 'bad' } }], { scope: 'test', publishedFrom: null, publishedTo: null });
    expect(data.items).toHaveLength(1);
    expect(data.items[0].status).toBe('Analyzed');
    expect(cveDatasetSchema.safeParse(data).success).toBe(true);
  });
});

describe('cleanDescription', () => {
  it('removes citations and Markdown links', () => {
    expect(cleanDescription('Uses [PowerShell](https://attack.mitre.org/techniques/T1059/001) often.(Citation: Report 2020) Then <code>cmd</code>.')).toBe(
      'Uses PowerShell often. Then `cmd`.',
    );
  });

  it('shortens long text at a sentence boundary and marks the cut', () => {
    const text = `${'First sentence is here. '.repeat(60)}`;
    const cleaned = cleanDescription(text, 200);
    expect(cleaned.length).toBeLessThanOrEqual(206);
    expect(cleaned.endsWith('. […]')).toBe(true);
  });

  it('tolerates non-string input', () => {
    expect(cleanDescription(undefined)).toBe('');
    expect(cleanDescription(null)).toBe('');
  });
});

describe('normalizeAttack', () => {
  const ref = (id, extra = {}) => ({ external_references: [{ source_name: 'mitre-attack', external_id: id }], ...extra });
  const bundle = {
    objects: [
      { type: 'x-mitre-collection', id: 'x-mitre-collection--1', x_mitre_version: '20.1', modified: '2026-11-05T15:11:27.678Z' },
      { type: 'x-mitre-matrix', id: 'x-mitre-matrix--1', tactic_refs: ['x-mitre-tactic--b', 'x-mitre-tactic--a'] },
      { type: 'x-mitre-tactic', id: 'x-mitre-tactic--a', name: 'Execution', x_mitre_shortname: 'execution', ...ref('TA0002') },
      { type: 'x-mitre-tactic', id: 'x-mitre-tactic--b', name: 'Initial Access', x_mitre_shortname: 'initial-access', ...ref('TA0001') },
      { type: 'attack-pattern', id: 'attack-pattern--1', name: 'Scripting', description: 'Desc.(Citation: X)', kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }, { kill_chain_name: 'other', phase_name: 'ignored' }], x_mitre_platforms: ['Windows'], ...ref('T1059') },
      { type: 'attack-pattern', id: 'attack-pattern--2', name: 'PowerShell', kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }], ...ref('T1059.001') },
      { type: 'attack-pattern', id: 'attack-pattern--3', name: 'Revoked', revoked: true, ...ref('T1000') },
      { type: 'attack-pattern', id: 'attack-pattern--4', name: 'Deprecated', x_mitre_deprecated: true, ...ref('T1001') },
      { type: 'attack-pattern', id: 'attack-pattern--5', name: 'No external id' },
      { type: 'intrusion-set', id: 'intrusion-set--1', name: 'Group', aliases: ['Group', 'Alias'], ...ref('G0001') },
      { type: 'malware', id: 'malware--1', name: 'Mal', ...ref('S0001') },
      { type: 'tool', id: 'tool--1', name: 'Tool', ...ref('S0002') },
      { type: 'campaign', id: 'campaign--1', name: 'Camp', first_seen: '2020-01-01T00:00:00.000Z', last_seen: 'invalid', ...ref('C0001') },
      { type: 'course-of-action', id: 'course-of-action--1', name: 'Mit', ...ref('M1001') },
      { type: 'course-of-action', id: 'course-of-action--2', name: 'Old style', ...ref('T1059') },
      { type: 'x-mitre-detection-strategy', id: 'x-mitre-detection-strategy--1', name: 'Det', ...ref('DET0001') },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--1', target_ref: 'attack-pattern--2' },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--1', target_ref: 'attack-pattern--2' },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--1', target_ref: 'attack-pattern--3' },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--1', target_ref: 'malware--1' },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'tool--1', target_ref: 'attack-pattern--1' },
      { type: 'relationship', relationship_type: 'mitigates', source_ref: 'course-of-action--1', target_ref: 'attack-pattern--1' },
      { type: 'relationship', relationship_type: 'detects', source_ref: 'x-mitre-detection-strategy--1', target_ref: 'attack-pattern--1' },
      { type: 'relationship', relationship_type: 'attributed-to', source_ref: 'campaign--1', target_ref: 'intrusion-set--1' },
      { type: 'relationship', relationship_type: 'uses', source_ref: 'campaign--1', target_ref: 'attack-pattern--1', revoked: true },
      { type: 'relationship', relationship_type: 'revoked-by', source_ref: 'attack-pattern--3', target_ref: 'attack-pattern--1' },
    ],
  };
  const data = normalizeAttack(bundle);

  it('produces a dataset accepted by the schema', () => {
    expect(attackDatasetSchema.safeParse(data).success).toBe(true);
    expect(data.version).toBe('20.1');
  });

  it('orders tactics as in the matrix', () => {
    expect(data.tactics.map((tactic) => tactic.id)).toEqual(['TA0001', 'TA0002']);
  });

  it('excludes revoked, deprecated and unidentified objects', () => {
    expect(data.techniques.map((technique) => technique.id)).toEqual(['T1059', 'T1059.001']);
    expect(data.mitigations.map((mitigation) => mitigation.id)).toEqual(['M1001']);
  });

  it('derives parents, kinds and cleaned descriptions', () => {
    expect(data.techniques[1].parent).toBe('T1059');
    expect(data.techniques[0]).toMatchObject({ description: 'Desc.', tactics: ['execution'], platforms: ['Windows'], parent: null });
    expect(data.software.map((item) => [item.id, item.kind])).toEqual([['S0001', 'malware'], ['S0002', 'tool']]);
    expect(data.groups[0].aliases).toEqual(['Alias']);
    expect(data.campaigns[0]).toMatchObject({ firstSeen: '2020-01-01T00:00:00.000Z', lastSeen: null });
  });

  it('keeps each relationship once and only between active objects', () => {
    expect(data.relations.groupTechnique).toEqual([['G0001', 'T1059.001']]);
    expect(data.relations.groupSoftware).toEqual([['G0001', 'S0001']]);
    expect(data.relations.softwareTechnique).toEqual([['S0002', 'T1059']]);
    expect(data.relations.mitigationTechnique).toEqual([['M1001', 'T1059']]);
    expect(data.relations.detectionTechnique).toEqual([['DET0001', 'T1059']]);
    expect(data.relations.campaignGroup).toEqual([['C0001', 'G0001']]);
    expect(data.relations.campaignTechnique).toEqual([]);
  });

  it('fails schema validation instead of inventing a version for an empty bundle', () => {
    expect(attackDatasetSchema.safeParse(normalizeAttack({})).success).toBe(false);
    expect(attackDatasetSchema.safeParse(normalizeAttack(null)).success).toBe(false);
  });
});

describe('normalizeCertfr', () => {
  const item = (link, title = 'Titre', date = 'Thu, 29 Oct 2026 00:00:00 +0000') =>
    `<item><title>${title}</title><link>${link}</link><description><![CDATA[Résumé <b>gras</b> &amp; suite]]></description><pubDate>${date}</pubDate></item>`;
  const feed = (...items) => `<?xml version='1.0'?><rss><channel><title>CERT-FR</title>${items.join('')}</channel></rss>`;

  it('extracts advisories and alerts as plain text', () => {
    const data = normalizeCertfr([
      feed(item('https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1420/', 'Multiples vuln&#233;rabilit&eacute;s &lt;script&gt;alert(1)&lt;/script&gt; dans X')),
      feed(item('https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-0007/', 'Alerte', 'Mon, 02 Nov 2026 00:00:00 +0000')),
    ]);
    expect(data.items.map((entry) => [entry.id, entry.kind])).toEqual([['CERTFR-2026-ALE-0007', 'alerte'], ['CERTFR-2026-AVI-1420', 'avis']]);
    expect(data.items[1].summary).toBe('Résumé gras & suite');
    expect(data.items[1].title).not.toMatch(/<script/i);
    expect(certfrDatasetSchema.safeParse(data).success).toBe(true);
  });

  it('rejects items from other hosts, without https, without an identifier or with a bad date', () => {
    const data = normalizeCertfr([
      feed(
        item('https://evil.example/avis/CERTFR-2026-AVI-0001/'),
        item('http://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0002/'),
        item('https://www.cert.cyber.gouv.fr/actualite/quelque-chose/'),
        item('https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0003/', 'T', 'not a date'),
        item('javascript:alert(1)//CERTFR-2026-AVI-0004'),
        item('https://www.cert.cyber.gouv.fr/ioc/CERTFR-2026-IOC-0001/'),
      ),
    ]);
    expect(data.items).toEqual([]);
  });

  it.each([[[]], [['']], [['<rss>']], [[null, 42]], [undefined], ['<item>']])('tolerates malformed feeds %j', (input) => {
    expect(normalizeCertfr(input).items).toEqual([]);
  });

  it('decodes numeric entities safely', () => {
    expect(decodeXml('&#x41;&#66;&amp;&#0;&#x110000;&unknown;')).toBe('AB&&unknown;');
  });
});
