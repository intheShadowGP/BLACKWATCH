import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../app/AppRoutes';
import { PreferencesProvider } from '../app/PreferencesProvider';
import { dictionaries } from '../i18n';
import { db } from '../lib/db';
import * as exportLib from '../lib/export';
import { deleteAllData } from '../lib/storage';
import { HOSTILE, manifest } from '../test/fixtures';
import { mockDatasets } from '../test/mock-data';

const en = dictionaries.en;

function renderAt(path: string) {
  return render(
    <PreferencesProvider>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </PreferencesProvider>,
  );
}

beforeEach(() => {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(['en-US']);
  mockDatasets();
});

afterEach(async () => {
  await deleteAllData(db);
});

/** Asserts that hostile dataset text was rendered as text, never as markup. */
function expectNoInjectedMarkup() {
  const main = screen.getByRole('main');
  expect(main.querySelector('script')).toBeNull();
  expect(main.querySelector('img')).toBeNull();
  expect(main.querySelector('[onerror]')).toBeNull();
}

describe('overview with datasets', () => {
  it('shows figures computed from the published datasets and their freshness', async () => {
    renderAt('/');
    const kevLabel = await screen.findByText(en['overview.kpi.kevTotal']);
    await waitFor(() => expect(kevLabel.nextElementSibling?.textContent).toBe('2'));
    expect(screen.getByText(en['overview.kpi.cveRecent']).nextElementSibling?.textContent).toBe('3');
    expect(screen.getByText(en['overview.kpi.cveCritical']).nextElementSibling?.textContent).toBe('1');
    for (const entry of manifest.datasets) {
      expect(screen.getByText(entry.publisher)).toBeInTheDocument();
    }
  });

  it('reports a failed dataset update as such', async () => {
    mockDatasets({ 'manifest.json': { ...manifest, datasets: manifest.datasets.map((entry) => (entry.id === 'kev' ? { ...entry, status: 'stale' } : entry)) } });
    renderAt('/');
    expect(await screen.findByText(en['data.status.stale'])).toBeInTheDocument();
  });

  it('does not claim that no dataset exists when the download fails', async () => {
    mockDatasets({ 'manifest.json': 'network-error' });
    renderAt('/');
    expect((await screen.findAllByText(en['data.error.network'])).length).toBeGreaterThan(0);
    expect(screen.queryByText(en['overview.data.empty'])).toBeNull();
  });
});

describe('vulnerability center', () => {
  it('lists recent CVEs, filters by severity and renders hostile text inertly', async () => {
    const user = userEvent.setup();
    renderAt('/vulnerabilities');
    expect(await screen.findByRole('link', { name: 'CVE-2026-10001' })).toBeInTheDocument();
    expect(screen.getByText(/Hostile markup/)).toBeInTheDocument();
    expectNoInjectedMarkup();

    await user.selectOptions(screen.getByLabelText(en['vuln.filter.severity']), 'CRITICAL');
    expect(screen.getByRole('link', { name: 'CVE-2026-10001' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'CVE-2026-10002' })).toBeNull();
  });

  it('shows KEV entries, including those without an NVD record', async () => {
    const user = userEvent.setup();
    renderAt('/vulnerabilities');
    await user.click(await screen.findByRole('tab', { name: /Known exploited/ }));
    expect(await screen.findByRole('link', { name: 'CVE-2025-20001' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'CVE-2024-30001' })).toBeInTheDocument();
  });

  it('exports the filtered rows as CSV', async () => {
    const user = userEvent.setup();
    const download = vi.spyOn(exportLib, 'downloadText').mockImplementation(() => undefined);
    renderAt('/vulnerabilities');
    await screen.findByRole('link', { name: 'CVE-2026-10001' });
    await user.click(screen.getByRole('button', { name: en['common.exportCsv'] }));
    const [name, content, type] = download.mock.calls[0] as [string, string, string];
    expect(name).toMatch(/^blackwatch-vulnerabilities-recent-[\w-]+\.csv$/);
    expect(type).toContain('text/csv');
    expect(content.split('\r\n')[0]).toContain('CVE,Priority');
    expect(content).toContain('CVE-2026-10003');
  });

  it('shows a CVE with its KEV data, explained priority and decoded vectors', async () => {
    renderAt('/vulnerabilities/cve-2025-20001');
    expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2025-20001' })).toBeInTheDocument();
    expect(await screen.findByText(en['priority.factor.kev'])).toBeInTheDocument();
    expect(screen.getByText(en['priority.factor.ransomware'])).toBeInTheDocument();
    expect(screen.getByText(en['vuln.cvss.v4note'])).toBeInTheDocument();
    expect(screen.getByText(/recomputed locally from the vector: 7.8 \(matches/)).toBeInTheDocument();
    expect(screen.getByText('Apply mitigations per vendor instructions.')).toBeInTheDocument();
  });

  it('never invents a score for an unscored CVE', async () => {
    renderAt('/vulnerabilities/CVE-2026-10003');
    expect(await screen.findByText(en['vuln.cvss.none'])).toBeInTheDocument();
    expect(screen.getByText(en['priority.factor.unscored'])).toBeInTheDocument();
    expect(screen.getByText(en['vuln.remediation.none'])).toBeInTheDocument();
  });

  it('adds a CVE to the watchlist and keeps it in local storage', async () => {
    const user = userEvent.setup();
    renderAt('/vulnerabilities/CVE-2026-10001');
    await user.click(await screen.findByRole('button', { name: en['vuln.watch.add'] }));
    expect(screen.getByRole('button', { name: en['vuln.watch.remove'] })).toBeInTheDocument();
    await waitFor(async () => expect(await db.favorites.get('cve:CVE-2026-10001')).toBeDefined());
  });

  it('says plainly when a CVE is outside the published datasets', async () => {
    renderAt('/vulnerabilities/CVE-1999-0001');
    expect(await screen.findByText(en['vuln.detail.notInDatasets'])).toBeInTheDocument();
  });

  it('treats a malformed CVE id as an unknown page', async () => {
    renderAt(`/vulnerabilities/${encodeURIComponent(HOSTILE)}`);
    expect(await screen.findByRole('heading', { level: 1, name: en['notFound.title'] })).toBeInTheDocument();
    expectNoInjectedMarkup();
  });

  it('explains a missing dataset instead of showing an empty table', async () => {
    mockDatasets({ 'nvd-recent.json': 'not-found' });
    renderAt('/vulnerabilities');
    expect(await screen.findByText(en['data.missing'])).toBeInTheDocument();
  });

  it('discards a corrupted dataset', async () => {
    mockDatasets({ 'nvd-recent.json': { rawBody: '{"items": [{"id": ' } });
    renderAt('/vulnerabilities');
    expect(await screen.findByText(en['data.error.invalid'])).toBeInTheDocument();
  });
});

describe('MITRE ATT&CK explorer', () => {
  it('renders the matrix with the dataset version and filters by platform', async () => {
    const user = userEvent.setup();
    renderAt('/attack');
    expect(await screen.findByText(/ATT&CK v99.0/)).toBeInTheDocument();
    const matrix = screen.getByRole('group', { name: en['attack.matrix.label'] });
    expect(within(matrix).getByRole('link', { name: /Phishing/ })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText(en['attack.platform']), 'macOS');
    expect(within(matrix).queryByRole('link', { name: /Command and Scripting/ })).toBeNull();
    expect(within(matrix).getByRole('link', { name: /Phishing/ })).toBeInTheDocument();
  });

  it('shows a technique with its relationships and renders hostile text inertly', async () => {
    renderAt('/attack/T1566');
    expect(await screen.findByRole('heading', { level: 1, name: 'Phishing' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /G9001 Test Group/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /C9001 Operation Test/ })).toBeInTheDocument();
    expectNoInjectedMarkup();
  });

  it('links a group to its techniques, software and campaigns', async () => {
    renderAt('/attack/g9001');
    expect(await screen.findByRole('heading', { level: 1, name: 'Test Group' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /T1059.001 PowerShell/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /S9001 TestTool/ })).toBeInTheDocument();
    expect(screen.queryByText('T9999')).toBeNull();
  });

  it('reports identifiers absent from the dataset version', async () => {
    renderAt('/attack/T1000');
    expect(await screen.findByText(/No active object with this identifier exists in ATT&CK v99.0/)).toBeInTheDocument();
  });
});

describe('threat intelligence', () => {
  it('merges CERT-FR and KEV items in the feed', async () => {
    renderAt('/threat-intel');
    expect(await screen.findByText('Vulnérabilité dans un produit de test')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'ExampleVendor ExampleProduct Privilege Escalation Vulnerability' })).toBeInTheDocument();
  });

  it('extracts indicators locally, defanged, without any network request', async () => {
    const user = userEvent.setup();
    const fetchMock = mockDatasets();
    renderAt('/threat-intel?tab=ioc');
    const input = await screen.findByLabelText(en['intel.ioc.input']);
    await user.click(input);
    await user.paste(`C2 hxxps://bad.example[.]com/x from 10.0.0.5 ${HOSTILE}`);
    await user.click(screen.getByRole('button', { name: en['intel.ioc.extract'] }));
    expect(await screen.findByText('hxxps://bad[.]example[.]com/x')).toBeInTheDocument();
    expect(screen.getByText('10[.]0[.]0[.]5')).toBeInTheDocument();
    expect(screen.getByText(en['ioc.class.private'])).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
    expectNoInjectedMarkup();
  });

  it('refuses files above the size limit', async () => {
    const user = userEvent.setup();
    renderAt('/threat-intel?tab=ioc');
    const big = new File(['x'.repeat(5 * 1024 * 1024 + 1)], '../../etc/passwd<img src=x>.txt', { type: 'text/plain' });
    await user.upload(await screen.findByLabelText(en['intel.ioc.importFile']), big);
    expect(await screen.findByRole('alert')).toHaveTextContent('5 MB');
  });

  it('shows an imported file name as text only', async () => {
    const user = userEvent.setup();
    renderAt('/threat-intel?tab=ioc');
    const file = new File(['beacon 8.8.8.8'], `<img src=x onerror=alert(1)>.log`, { type: 'text/plain' });
    await user.upload(await screen.findByLabelText(en['intel.ioc.importFile']), file);
    expect(await screen.findByText(/source: <img src=x onerror=alert\(1\)>\.log/)).toBeInTheDocument();
    expectNoInjectedMarkup();
  });

  it('saves, edits and deletes notes after confirmation', async () => {
    const user = userEvent.setup();
    renderAt('/threat-intel?tab=notes');
    await user.type(await screen.findByLabelText(en['intel.notes.new']), 'First note');
    await user.click(screen.getByRole('button', { name: en['common.save'] }));
    expect(await screen.findByText('First note')).toBeInTheDocument();
    expect(await db.notes.count()).toBe(1);

    await user.click(screen.getByRole('button', { name: en['common.delete'] }));
    const dialog = screen.getByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: en['common.cancel'] }));
    expect(await db.notes.count()).toBe(1);

    await user.click(screen.getByRole('button', { name: en['common.delete'] }));
    await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: en['common.delete'] }));
    await waitFor(async () => expect(await db.notes.count()).toBe(0));
  });
});
