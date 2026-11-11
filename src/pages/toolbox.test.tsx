import { createHash } from 'node:crypto';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from '../app/AppRoutes';
import { PreferencesProvider } from '../app/PreferencesProvider';
import { dictionaries } from '../i18n';
import { base64Encode, utf8Encode } from '../toolbox/lib/bytes';
import { SPECIFICATION_COVERAGE, TOOLS } from '../toolbox/registry';

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
});

const b64url = (value: unknown) => base64Encode(utf8Encode(JSON.stringify(value)), true);

describe('toolbox registry', () => {
  it('covers the 23 utilities of the specification with registered tools', () => {
    expect(Object.keys(SPECIFICATION_COVERAGE)).toHaveLength(23);
    const ids = new Set(TOOLS.map((tool) => tool.id));
    for (const [requirement, toolId] of Object.entries(SPECIFICATION_COVERAGE)) {
      expect(ids.has(toolId), requirement).toBe(true);
    }
  });

  it('has unique ids and a translated title, summary and limits text for each tool', () => {
    expect(new Set(TOOLS.map((tool) => tool.id)).size).toBe(TOOLS.length);
    for (const tool of TOOLS) {
      for (const key of [tool.titleKey, tool.summaryKey, tool.limitsKey]) {
        expect(dictionaries.en[key], key).toBeTruthy();
        expect(dictionaries.fr[key], key).toBeTruthy();
      }
    }
  });
});

describe('toolbox pages', () => {
  it('lists every tool on the index', async () => {
    renderAt('/toolbox');
    for (const tool of TOOLS) {
      expect(await screen.findByRole('link', { name: new RegExp(en[tool.titleKey].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) })).toBeInTheDocument();
    }
  });

  it('renders each tool with its limits', async () => {
    for (const tool of TOOLS) {
      const view = renderAt(`/toolbox/${tool.id}`);
      expect(await screen.findByRole('heading', { level: 1, name: en[tool.titleKey] })).toBeInTheDocument();
      expect(screen.getByText(en[tool.limitsKey])).toBeInTheDocument();
      view.unmount();
    }
  });

  it('treats an unknown tool as an unknown page', async () => {
    renderAt('/toolbox/%3Cscript%3E');
    expect(await screen.findByRole('heading', { level: 1, name: en['notFound.title'] })).toBeInTheDocument();
  });

  it('hashes text as the user types', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/hash-text');
    await user.type(await screen.findByLabelText(en['tb.text']), 'abc');
    expect(await screen.findByText(createHash('sha256').update('abc').digest('hex'))).toBeInTheDocument();
    expect(screen.getByText('900150983cd24fb0d6963f7d28e17f72')).toBeInTheDocument();
  });

  it('shows non-text Base64 output as a hex dump', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/base64');
    await user.click(await screen.findByRole('radio', { name: en['tb.decode'] }));
    await user.type(screen.getByLabelText(en['toolbox.input']), '/wD+');
    expect(await screen.findByText(en['tb.decodedBinary'])).toBeInTheDocument();
    expect(screen.getByText(/ff 00 fe/)).toBeInTheDocument();
  });

  it('marks a decoded JWT as not verified and flags alg none', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/jwt');
    await user.click(await screen.findByLabelText('JWT'));
    await user.paste(`${b64url({ alg: 'none' })}.${b64url({ sub: '<img src=x onerror=alert(1)>' })}.`);
    expect(await screen.findByText(en['tb.jwt.notVerified'])).toBeInTheDocument();
    expect(screen.getByText(en['tb.jwt.warn.algNone'])).toBeInTheDocument();
    expect(screen.getByRole('main').querySelector('img')).toBeNull();
  });

  it('reports duplicate keys before formatting JSON', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/json');
    await user.click(await screen.findByLabelText('JSON'));
    await user.paste('{"a": 1, "a": 2}');
    expect(await screen.findByText(/duplicate key "a"/)).toBeInTheDocument();
    expect(screen.getAllByText(/"a": 2/).length).toBeGreaterThan(0);
  });

  it('rates a guessable password as weak and keeps it out of the URL and storage', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/password');
    await user.type(await screen.findByLabelText(en['tb.password.input']), 'Password1!');
    expect(await screen.findByText(en['tb.password.verdict.weak'])).toBeInTheDocument();
    expect(window.location.href).not.toContain('Password1');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('reports the regex tester as unavailable without background workers', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/regex');
    await user.type(await screen.findByLabelText(en['tb.regex.pattern']), 'a+');
    await user.click(screen.getByRole('button', { name: en['tb.regex.run'] }));
    expect(await screen.findByText(en['tb.regex.unavailable'])).toBeInTheDocument();
  });

  it('inspects a file locally and flags an extension mismatch', async () => {
    const user = userEvent.setup();
    const fetchMock = vi.mocked(fetch);
    renderAt('/toolbox/file-meta');
    const content = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03]);
    const file = new File([content], 'invoice.pdf', { type: 'application/pdf' });
    await user.upload(await screen.findByLabelText(en['toolbox.chooseFile']), file);
    expect(await screen.findByText('Windows PE / MS-DOS executable')).toBeInTheDocument();
    expect(screen.getByText(en['tb.file.mismatch'])).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(createHash('sha256').update(content).digest('hex'))).toBeInTheDocument());
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('analyses headers without fetching anything', async () => {
    const user = userEvent.setup();
    renderAt('/toolbox/headers');
    await user.click(await screen.findByLabelText(en['tb.headers.input']));
    await user.paste('HTTP/1.1 200 OK\nX-Powered-By: PHP/8.1\nSet-Cookie: sid=1');
    expect(await screen.findByText(en['tb.headers.note.techDisclosure'])).toBeInTheDocument();
    expect(screen.getByText('Cookie sid: no Secure attribute.')).toBeInTheDocument();
  });
});
