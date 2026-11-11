// Small synthetic datasets for tests. Identifiers and text are invented for
// testing only; they are never shipped with the application.

import type { AttackDataset, CertfrDataset, CveDataset, CveItem, KevDataset, Manifest, ManifestEntry } from '../data/schemas';

export const HOSTILE = '<img src=x onerror=alert(1)><script>alert(2)</script>';

const RETRIEVED = '2026-01-10T06:00:00.000Z';

function cve(id: string, overrides: Partial<CveItem> = {}): CveItem {
  return {
    id,
    published: '2026-01-08T10:00:00.000Z',
    lastModified: '2026-01-09T10:00:00.000Z',
    status: 'Analyzed',
    description: `Synthetic description for ${id}.`,
    cvss3: { version: '3.1', score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', source: 'nvd@nist.gov' },
    cvss4: null,
    cwes: ['CWE-79'],
    products: ['examplevendor:exampleproduct'],
    references: [{ url: 'https://vendor.example/advisory-1', tags: ['Patch', 'Vendor Advisory'] }],
    ...overrides,
  };
}

export const nvdRecent: CveDataset = {
  scope: 'test',
  publishedFrom: '2026-01-03T06:00:00.000Z',
  publishedTo: RETRIEVED,
  items: [
    cve('CVE-2026-10001'),
    cve('CVE-2026-10002', {
      description: `Hostile markup ${HOSTILE}`,
      cvss3: { version: '3.1', score: 6.1, severity: 'MEDIUM', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', source: 'nvd@nist.gov' },
      references: [],
    }),
    cve('CVE-2026-10003', { cvss3: null, status: 'Awaiting Analysis', cwes: [], products: [], references: [] }),
  ],
};

export const nvdKev: CveDataset = {
  scope: 'test',
  publishedFrom: null,
  publishedTo: null,
  items: [
    cve('CVE-2025-20001', {
      published: '2025-06-01T00:00:00.000Z',
      cvss3: { version: '3.1', score: 7.8, severity: 'HIGH', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', source: 'nvd@nist.gov' },
      cvss4: { version: '4.0', score: 8.5, severity: 'HIGH', vector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', source: 'vendor@example.com' },
    }),
  ],
};

export const kev: KevDataset = {
  catalogVersion: '2026.01.10',
  dateReleased: RETRIEVED,
  items: [
    { cve: 'CVE-2025-20001', vendor: 'ExampleVendor', product: 'ExampleProduct', name: 'ExampleVendor ExampleProduct Privilege Escalation Vulnerability', dateAdded: '2026-01-05T00:00:00.000Z', description: 'Synthetic KEV description.', requiredAction: 'Apply mitigations per vendor instructions.', dueDate: '2026-01-26T00:00:00.000Z', ransomware: 'Known', cwes: ['CWE-269'] },
    { cve: 'CVE-2024-30001', vendor: 'OtherVendor', product: 'OtherProduct', name: 'OtherVendor OtherProduct Command Injection Vulnerability', dateAdded: '2025-11-20T00:00:00.000Z', description: 'Entry without an NVD record in the test data.', requiredAction: 'Apply updates.', dueDate: null, ransomware: 'Unknown', cwes: [] },
  ],
};

export const attack: AttackDataset = {
  domain: 'enterprise-attack',
  version: '99.0',
  modified: '2026-01-01T00:00:00.000Z',
  descriptionsTruncatedAt: 900,
  tactics: [
    { id: 'TA0001', shortname: 'initial-access', name: 'Initial Access', description: 'Getting in.' },
    { id: 'TA0002', shortname: 'execution', name: 'Execution', description: 'Running code.' },
  ],
  techniques: [
    { id: 'T1059', name: 'Command and Scripting Interpreter', description: 'Abuse of interpreters.', tactics: ['execution'], platforms: ['Windows', 'Linux'], parent: null },
    { id: 'T1059.001', name: 'PowerShell', description: 'Abuse of PowerShell.', tactics: ['execution'], platforms: ['Windows'], parent: 'T1059' },
    { id: 'T1566', name: 'Phishing', description: `Phishing ${HOSTILE}`, tactics: ['initial-access'], platforms: ['Linux', 'macOS', 'Windows'], parent: null },
  ],
  groups: [{ id: 'G9001', name: 'Test Group', aliases: ['TG-Alias'], description: 'A synthetic group.' }],
  software: [{ id: 'S9001', name: 'TestTool', kind: 'tool', platforms: ['Windows'], description: 'A synthetic tool.' }],
  campaigns: [{ id: 'C9001', name: 'Operation Test', description: 'A synthetic campaign.', firstSeen: '2024-03-01T00:00:00.000Z', lastSeen: '2024-06-01T00:00:00.000Z' }],
  mitigations: [{ id: 'M9001', name: 'Test Mitigation', description: 'A synthetic mitigation.' }],
  detections: [{ id: 'DET9001', name: 'Test Detection Strategy' }],
  relations: {
    groupTechnique: [['G9001', 'T1059.001'], ['G9001', 'T1566'], ['G9001', 'T9999']],
    groupSoftware: [['G9001', 'S9001']],
    softwareTechnique: [['S9001', 'T1059']],
    campaignTechnique: [['C9001', 'T1566']],
    campaignSoftware: [['C9001', 'S9001']],
    campaignGroup: [['C9001', 'G9001']],
    mitigationTechnique: [['M9001', 'T1059']],
    detectionTechnique: [['DET9001', 'T1059']],
  },
};

export const certfr: CertfrDataset = {
  items: [
    { id: 'CERTFR-2026-AVI-0001', kind: 'avis', title: 'Vulnérabilité dans un produit de test', summary: 'Résumé de test.', url: 'https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0001/', published: '2026-01-09T00:00:00.000Z' },
    { id: 'CERTFR-2026-ALE-0001', kind: 'alerte', title: 'Alerte de test', summary: 'Résumé d’alerte.', url: 'https://www.cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-0001/', published: '2026-01-07T00:00:00.000Z' },
  ],
};

function entry(id: ManifestEntry['id'], count: number, overrides: Partial<ManifestEntry> = {}): ManifestEntry {
  return {
    id,
    file: `${id}.json`,
    status: 'fresh',
    retrievedAt: RETRIEVED,
    publisher: `Publisher of ${id}`,
    sourceUrl: 'https://source.example/',
    licence: 'Test licence',
    licenceUrl: 'https://source.example/licence',
    notice: `Notice for ${id}.`,
    version: id === 'attack' ? '99.0' : null,
    count,
    sha256: null,
    ...overrides,
  };
}

export const manifest: Manifest = {
  schemaVersion: 1,
  generatedAt: RETRIEVED,
  datasets: [
    entry('kev', kev.items.length),
    entry('nvd-recent', nvdRecent.items.length),
    entry('nvd-kev', nvdKev.items.length),
    entry('attack', attack.techniques.length),
    entry('certfr', certfr.items.length),
  ],
};

/** File name to JSON body, as served under data/. */
export const DATA_FILES: Record<string, unknown> = {
  'manifest.json': manifest,
  'kev.json': kev,
  'nvd-recent.json': nvdRecent,
  'nvd-kev.json': nvdKev,
  'attack.json': attack,
  'certfr.json': certfr,
};
