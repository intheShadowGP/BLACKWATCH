import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { db } from '../lib/db';
import * as storage from '../lib/storage';
import { AppRoutes } from './AppRoutes';
import { MODULES, PLANNED_MODULES } from './modules';
import { PreferencesProvider } from './PreferencesProvider';
import { dictionaries } from '../i18n';

const en = dictionaries.en;
const fr = dictionaries.fr;

function renderApp(path = '/') {
  return render(
    <PreferencesProvider>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </PreferencesProvider>,
  );
}

function setBrowserLanguages(languages: string[]) {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(languages);
}

beforeEach(() => {
  setBrowserLanguages(['en-US']);
});

afterEach(async () => {
  await storage.deleteAllData(db);
});

describe('module registry', () => {
  it('has unique ids and paths', () => {
    expect(new Set(MODULES.map((module) => module.id)).size).toBe(MODULES.length);
    expect(new Set(MODULES.map((module) => module.path)).size).toBe(MODULES.length);
  });

  it('describes the scope of every planned module', () => {
    for (const module of PLANNED_MODULES) {
      expect(module.scopeKey, module.id).toBeDefined();
      expect(module.milestone, module.id).toBeGreaterThan(0);
    }
  });
});

describe('application shell', () => {
  it('renders the overview with navigation to every module', async () => {
    renderApp();
    expect(await screen.findByRole('heading', { level: 1, name: en['overview.title'] })).toBeInTheDocument();
    const nav = screen.getAllByRole('navigation', { name: en['nav.primary'] })[0];
    expect(nav).toBeDefined();
    expect(within(nav as HTMLElement).getAllByRole('link')).toHaveLength(MODULES.length);
    expect(document.title).toBe(`${en['overview.title']} — BLACKWATCH`);
  });

  it('shows no intelligence figures while no dataset is published', async () => {
    renderApp();
    expect(await screen.findByText(en['overview.data.empty'])).toBeInTheDocument();
  });

  it('navigates to each planned module and labels it as unavailable', async () => {
    const user = userEvent.setup();
    renderApp();
    const nav = (await screen.findAllByRole('navigation', { name: en['nav.primary'] }))[0] as HTMLElement;
    for (const module of PLANNED_MODULES) {
      await user.click(within(nav).getByRole('link', { name: new RegExp(en[module.titleKey].replace('&', '&')) }));
      expect(await screen.findByRole('heading', { level: 1, name: en[module.titleKey] })).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 2, name: en['planned.title'] })).toBeInTheDocument();
    }
  });

  it('moves focus to the main region after navigation', async () => {
    const user = userEvent.setup();
    renderApp();
    const nav = (await screen.findAllByRole('navigation', { name: en['nav.primary'] }))[0] as HTMLElement;
    await user.click(within(nav).getByRole('link', { name: en['nav.settings'] }));
    await screen.findByRole('heading', { level: 1, name: en['settings.title'] });
    expect(screen.getByRole('main')).toHaveFocus();
  });

  it('opens and closes the mobile navigation drawer', async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(await screen.findByRole('button', { name: en['nav.openMenu'] }));
    const drawer = screen.getByRole('dialog', { name: en['nav.menuTitle'] });
    expect(drawer).toHaveAttribute('open');
    await user.click(within(drawer).getByRole('link', { name: en['nav.settings'] }));
    await screen.findByRole('heading', { level: 1, name: en['settings.title'] });
    expect(screen.queryByRole('dialog', { name: en['nav.menuTitle'] })).not.toBeInTheDocument();
  });
});

describe('internationalisation', () => {
  it('starts in French for a French browser', async () => {
    setBrowserLanguages(['fr-FR', 'en']);
    renderApp();
    expect(await screen.findByRole('heading', { level: 1, name: fr['overview.title'] })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('fr');
  });

  it('switches language from the header and persists the choice', async () => {
    const user = userEvent.setup();
    const first = renderApp();
    await user.click(await screen.findByRole('button', { name: en['lang.fr'] }));
    expect(await screen.findByRole('heading', { level: 1, name: fr['overview.title'] })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('fr');
    await waitFor(async () => {
      expect((await storage.loadPreferences({} as never, db)).preferences.language).toBe('fr');
    });

    first.unmount();
    renderApp();
    expect(await screen.findByRole('heading', { level: 1, name: fr['overview.title'] })).toBeInTheDocument();
  });
});

describe('settings', () => {
  it('applies theme, density and motion to the document', async () => {
    const user = userEvent.setup();
    renderApp('/settings');
    await user.click(await screen.findByRole('radio', { name: en['settings.theme.light'] }));
    await user.click(screen.getByRole('radio', { name: en['settings.density.compact'] }));
    await user.click(screen.getByRole('radio', { name: en['settings.motion.reduced'] }));
    const root = document.documentElement;
    expect(root.dataset.theme).toBe('light');
    expect(root.dataset.density).toBe('compact');
    expect(root.dataset.motion).toBe('reduced');
  });

  it('requires confirmation before deleting local data, and can be cancelled', async () => {
    const user = userEvent.setup();
    await db.notes.put({ id: 'n1', scope: 's', body: 'b', updatedAt: 'now' });
    renderApp('/settings');
    await user.click(await screen.findByRole('button', { name: en['settings.data.delete'] }));
    const dialog = screen.getByRole('alertdialog', { name: en['settings.data.deleteConfirmTitle'] });
    await user.click(within(dialog).getByRole('button', { name: en['common.cancel'] }));
    expect(await db.notes.count()).toBe(1);
  });

  it('deletes local data and resets preferences once confirmed', async () => {
    const user = userEvent.setup();
    await db.notes.put({ id: 'n1', scope: 's', body: 'b', updatedAt: 'now' });
    renderApp('/settings');
    await user.click(await screen.findByRole('radio', { name: en['settings.theme.light'] }));
    await user.click(screen.getByRole('button', { name: en['settings.data.delete'] }));
    const dialog = screen.getByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: en['settings.data.deleteConfirm'] }));
    expect(await screen.findByText(en['settings.data.deleted'])).toBeInTheDocument();
    expect(await db.notes.count()).toBe(0);
    expect(await db.kv.count()).toBe(0);
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('exports local data as a JSON download', async () => {
    const user = userEvent.setup();
    const download = vi.spyOn(storage, 'downloadJson').mockImplementation(() => undefined);
    renderApp('/settings');
    await user.click(await screen.findByRole('button', { name: en['settings.data.export'] }));
    await waitFor(() => expect(download).toHaveBeenCalledTimes(1));
    const [fileName, bundle] = download.mock.calls[0] as [string, storage.ExportBundle];
    expect(fileName).toMatch(/^blackwatch-export-[\w-]+\.json$/);
    expect(bundle.application).toBe('BLACKWATCH');
  });
});

describe('failure handling', () => {
  it('keeps working in memory and warns when storage is unavailable', async () => {
    vi.spyOn(storage, 'loadPreferences').mockResolvedValue({
      preferences: { language: 'en', theme: 'dark', density: 'comfortable', motion: 'system' },
      persistent: false,
    });
    vi.spyOn(storage, 'countRecords').mockRejectedValue(new Error('blocked'));
    renderApp();
    expect(await screen.findByText(en['storage.banner'])).toBeInTheDocument();
    expect(await screen.findByText(en['overview.storage.unavailable'])).toBeInTheDocument();
  });

  it('renders an unknown route as text, without interpreting markup in the path', async () => {
    const hostile = '/<img src=x onerror=alert(1)><script>alert(2)</script>';
    renderApp(hostile);
    expect(await screen.findByRole('heading', { level: 1, name: en['notFound.title'] })).toBeInTheDocument();
    expect(screen.getByText(/No page matches/).textContent).toContain('<img src=x onerror=alert(1)>');
    const main = screen.getByRole('main');
    expect(main.querySelector('img')).toBeNull();
    expect(main.querySelector('script')).toBeNull();
  });

  it('truncates very long unknown paths', async () => {
    renderApp(`/${'a'.repeat(5000)}`);
    const message = await screen.findByText(/No page matches/);
    expect(message.textContent?.length).toBeLessThan(200);
  });
});
