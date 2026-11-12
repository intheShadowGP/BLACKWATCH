import { Suspense, useEffect, useId, useRef, useState, useSyncExternalStore } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Brand } from '../components/ui';
import { LANGUAGES } from '../i18n';
import { applyUpdate, getUpdateState, subscribeUpdate } from '../pwa/register';
import { MODULES } from './modules';
import { useI18n, usePreferences } from './preferences-context';

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useI18n();
  return (
    <ul className="flex flex-col gap-0.5">
      {MODULES.map((module) => (
        <li key={module.id}>
          <NavLink
            to={`/${module.path}`}
            end={module.path === ''}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 border-l-2 px-4 py-2 text-sm transition-colors ${
                isActive
                  ? 'border-accent bg-raised text-fg'
                  : 'border-transparent text-muted hover:bg-raised hover:text-fg'
              }`
            }
          >
            <Icon name={module.icon} className="shrink-0" />
            <span className="min-w-0 flex-1 leading-snug">{t(module.titleKey)}</span>
            {module.status === 'planned' ? (
              <span className="text-[0.625rem] uppercase tracking-wider text-subtle">
                {t('status.planned')}
              </span>
            ) : null}
          </NavLink>
        </li>
      ))}
    </ul>
  );
}

function LanguageSwitch() {
  const { t } = useI18n();
  const { preferences, update } = usePreferences();
  return (
    <div role="group" aria-label={t('lang.label')} className="inline-flex rounded-sm border border-line-strong">
      {LANGUAGES.map((language) => (
        <button
          key={language}
          type="button"
          lang={language}
          aria-pressed={preferences.language === language}
          onClick={() => update({ language })}
          className={`min-h-8 border-r border-line-strong px-2.5 text-xs font-semibold uppercase tracking-wider last:border-r-0 ${
            preferences.language === language ? 'bg-raised text-fg' : 'text-muted hover:text-fg'
          }`}
        >
          {language}
          {/* The accessible name starts with the visible code (WCAG 2.5.3). */}
          <span className="sr-only"> {t(`lang.${language}`)}</span>
        </button>
      ))}
    </div>
  );
}

/** Offered, never forced: reloading discards work held in memory, such as an SOC import. */
function UpdateNotice() {
  const { t } = useI18n();
  const update = useSyncExternalStore(subscribeUpdate, getUpdateState);
  if (update.status === 'none') return null;
  return (
    <div role="status" className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-2 text-sm text-fg">
      <span>{t(update.status === 'waiting' ? 'pwa.update' : 'pwa.replaced')}</span>
      <button type="button" onClick={applyUpdate} className="min-h-8 rounded-sm border border-line-strong px-3 text-xs font-semibold hover:bg-raised">
        {t('pwa.reload')}
      </button>
    </div>
  );
}

export function Shell() {
  const { t } = useI18n();
  const { persistent } = usePreferences();
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuTitleId = useId();

  // Move focus to the new view after navigation so keyboard and screen reader users land on it.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus();
    window.scrollTo(0, 0);
  }, [location.pathname]);

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[16rem_minmax(0,1fr)]">
      <a
        href="#main"
        onClick={(event) => {
          // The hash is owned by the router: move focus without touching the URL.
          event.preventDefault();
          mainRef.current?.focus();
        }}
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-sm focus:border focus:border-gold focus:bg-surface focus:px-3 focus:py-2 focus:text-sm"
      >
        {t('nav.skip')}
      </a>

      <aside className="sticky top-0 hidden h-dvh print:!hidden flex-col border-r border-line bg-surface lg:flex">
        <div className="flex h-14 items-center border-b border-line px-4">
          <Brand className="text-sm" />
        </div>
        <nav aria-label={t('nav.primary')} className="flex-1 overflow-y-auto py-3">
          <NavList />
        </nav>
        <p className="border-t border-line px-4 py-3 font-mono text-[0.6875rem] text-subtle">v{__APP_VERSION__}</p>
      </aside>

      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-10 flex h-14 print:hidden items-center gap-3 border-b border-line bg-bg/95 px-4 backdrop-blur-sm">
          <button
            type="button"
            aria-label={t('nav.openMenu')}
            aria-haspopup="dialog"
            onClick={() => setMenuOpen(true)}
            className="-ml-1.5 inline-flex size-9 items-center justify-center rounded-sm text-muted hover:bg-raised hover:text-fg lg:hidden"
          >
            <Icon name="menu" />
          </button>
          <Brand className="text-sm lg:hidden" />
          <p className="hidden min-w-0 truncate text-xs uppercase tracking-[0.14em] text-subtle lg:block">
            {t('app.tagline')}
          </p>
          <div className="ml-auto">
            <LanguageSwitch />
          </div>
        </header>

        {!persistent ? (
          <p role="status" className="border-b border-line bg-surface px-4 py-2 text-sm text-gold">
            {t('storage.banner')}
          </p>
        ) : null}
        <UpdateNotice />

        <main id="main" ref={mainRef} tabIndex={-1} className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <ErrorBoundary resetKey={location.pathname}>
            <Suspense fallback={<p className="text-sm text-muted">{t('app.loading')}</p>}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>

      <Modal
        open={menuOpen}
        onClose={() => setMenuOpen(false)}
        labelledBy={menuTitleId}
        className="fixed inset-y-0 left-0 m-0 h-dvh max-h-none w-[min(18rem,85vw)] max-w-none"
      >
        <div className="flex h-full flex-col border-r border-line-strong bg-surface">
          <div className="flex h-14 items-center justify-between border-b border-line px-4">
            <h2 id={menuTitleId} className="sr-only">
              {t('nav.menuTitle')}
            </h2>
            <Brand className="text-sm" />
            <button
              type="button"
              aria-label={t('nav.closeMenu')}
              onClick={() => setMenuOpen(false)}
              className="-mr-1.5 inline-flex size-9 items-center justify-center rounded-sm text-muted hover:bg-raised hover:text-fg"
            >
              <Icon name="close" />
            </button>
          </div>
          <nav aria-label={t('nav.primary')} className="flex-1 overflow-y-auto py-3">
            <NavList onNavigate={() => setMenuOpen(false)} />
          </nav>
          <p className="border-t border-line px-4 py-3 font-mono text-[0.6875rem] text-subtle">v{__APP_VERSION__}</p>
        </div>
      </Modal>
    </div>
  );
}
