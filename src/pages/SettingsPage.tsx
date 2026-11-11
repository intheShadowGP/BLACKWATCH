import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useI18n, usePreferences } from '../app/preferences-context';
import { ConfirmDialog } from '../components/Modal';
import { Button, PageHeader, Panel, Segmented } from '../components/ui';
import { LANGUAGES, type MessageKey } from '../i18n';
import { SCHEMA_VERSION, TABLE_NAMES } from '../lib/db';
import type { FavoriteRecord } from '../lib/db';
import { listFavorites, removeFavorite, type FavoriteKind } from '../lib/favorites';
import { DENSITIES, MOTIONS, THEMES } from '../lib/preferences';
import {
  countRecords,
  deleteAllData,
  downloadJson,
  exportAllData,
  exportFileName,
  type RecordCounts,
} from '../lib/storage';

type Feedback = { tone: 'info' | 'error'; text: string } | null;

function LocalDataPanel() {
  const { t } = useI18n();
  const { reset } = usePreferences();
  const [counts, setCounts] = useState<RecordCounts | 'unavailable' | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);

  const refresh = useCallback(async () => {
    try {
      setCounts(await countRecords());
    } catch {
      setCounts('unavailable');
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    countRecords()
      .then((result) => {
        if (!cancelled) setCounts(result);
      })
      .catch(() => {
        if (!cancelled) setCounts('unavailable');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleExport = async () => {
    setBusy(true);
    try {
      const bundle = await exportAllData(__APP_VERSION__);
      const file = exportFileName(new Date(bundle.exportedAt));
      downloadJson(file, bundle);
      setFeedback({ tone: 'info', text: t('settings.data.exported', { file }) });
    } catch {
      setFeedback({ tone: 'error', text: t('settings.data.error') });
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async () => {
    setConfirming(false);
    setBusy(true);
    try {
      await deleteAllData();
      reset();
      setFeedback({ tone: 'info', text: t('settings.data.deleted') });
    } catch {
      setFeedback({ tone: 'error', text: t('settings.data.error') });
    } finally {
      setBusy(false);
      await refresh();
    }
  };

  const unavailable = counts === 'unavailable';

  return (
    <Panel title={t('settings.data.title')}>
      <p className="text-sm text-muted">{t('settings.data.help')}</p>

      {unavailable ? (
        <p className="mt-4 text-sm text-gold">{t('settings.data.unavailable')}</p>
      ) : (
        <table className="mt-4 w-full max-w-md text-left text-sm">
          <thead>
            <tr className="border-b border-line text-xs uppercase tracking-wider text-subtle">
              <th scope="col" className="py-1.5 font-medium">
                {t('settings.data.table')}
              </th>
              <th scope="col" className="py-1.5 text-right font-medium">
                {t('settings.data.count')}
              </th>
            </tr>
          </thead>
          <tbody>
            {TABLE_NAMES.map((name) => (
              <tr key={name} className="border-b border-line last:border-b-0">
                <th scope="row" className="py-1.5 font-normal text-fg">
                  {t(`settings.data.store.${name}` satisfies MessageKey)}
                </th>
                <td className="py-1.5 text-right font-mono text-muted">{counts ? counts[name] : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="mt-5 flex flex-wrap gap-2">
        <Button onClick={() => void handleExport()} disabled={busy || unavailable}>
          {t('settings.data.export')}
        </Button>
        <Button variant="danger" onClick={() => setConfirming(true)} disabled={busy || unavailable}>
          {t('settings.data.delete')}
        </Button>
      </div>

      <p role="status" className={`mt-3 min-h-5 text-sm ${feedback?.tone === 'error' ? 'text-accent' : 'text-gold'}`}>
        {feedback?.text}
      </p>

      <ConfirmDialog
        open={confirming}
        title={t('settings.data.deleteConfirmTitle')}
        body={t('settings.data.deleteConfirmBody')}
        confirmLabel={t('settings.data.deleteConfirm')}
        onConfirm={() => void handleDelete()}
        onCancel={() => setConfirming(false)}
      />
    </Panel>
  );
}

function FavoritesPanel() {
  const { t } = useI18n();
  const [favorites, setFavorites] = useState<FavoriteRecord[] | 'unavailable' | null>(null);

  useEffect(() => {
    let cancelled = false;
    listFavorites()
      .then((records) => {
        if (!cancelled) setFavorites(records);
      })
      .catch(() => {
        if (!cancelled) setFavorites('unavailable');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const remove = async (favorite: FavoriteRecord) => {
    try {
      await removeFavorite(favorite.kind as FavoriteKind, favorite.ref);
      setFavorites(await listFavorites());
    } catch {
      setFavorites('unavailable');
    }
  };

  return (
    <Panel title={t('settings.favorites.title')}>
      {favorites === null ? (
        <p className="text-sm text-muted">{t('app.loading')}</p>
      ) : favorites === 'unavailable' ? (
        <p className="text-sm text-gold">{t('settings.data.unavailable')}</p>
      ) : favorites.length === 0 ? (
        <p className="text-sm text-muted">{t('settings.favorites.empty')}</p>
      ) : (
        <ul className="-my-2 divide-y divide-line">
          {favorites.map((favorite) => (
            <li key={favorite.id} className="flex items-center justify-between gap-3 py-2 text-sm">
              <span className="min-w-0">
                {favorite.kind === 'cve' ? (
                  <Link to={`/vulnerabilities/${favorite.ref}`} className="font-mono text-accent hover:underline">
                    {favorite.ref}
                  </Link>
                ) : (
                  <span className="font-mono text-fg">{favorite.ref}</span>
                )}
                {favorite.label !== favorite.ref ? <span className="ml-2 text-muted">{favorite.label}</span> : null}
              </span>
              <Button variant="ghost" aria-label={t('settings.favorites.remove', { label: favorite.ref })} onClick={() => void remove(favorite)}>
                {t('common.delete')}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function SettingsPage() {
  const { t } = useI18n();
  const { preferences, update } = usePreferences();

  return (
    <>
      <PageHeader title={t('settings.title')} intro={t('settings.intro')} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title={t('settings.appearance.title')}>
          <div className="-my-3 divide-y divide-line">
            <Segmented
              legend={t('settings.language.title')}
              name="language"
              value={preferences.language}
              options={LANGUAGES.map((value) => ({ value, label: t(`lang.${value}`) }))}
              onChange={(language) => update({ language })}
            />
            <Segmented
              legend={t('settings.theme.title')}
              name="theme"
              value={preferences.theme}
              options={THEMES.map((value) => ({ value, label: t(`settings.theme.${value}`) }))}
              onChange={(theme) => update({ theme })}
            />
            <Segmented
              legend={t('settings.density.title')}
              name="density"
              value={preferences.density}
              options={DENSITIES.map((value) => ({ value, label: t(`settings.density.${value}`) }))}
              onChange={(density) => update({ density })}
            />
            <Segmented
              legend={t('settings.motion.title')}
              name="motion"
              value={preferences.motion}
              options={MOTIONS.map((value) => ({ value, label: t(`settings.motion.${value}`) }))}
              onChange={(motion) => update({ motion })}
            />
          </div>
        </Panel>

        <LocalDataPanel />

        <FavoritesPanel />

        <Panel title={t('settings.privacy.title')}>
          <div className="space-y-3 text-sm text-muted">
            <p>{t('settings.privacy.p1')}</p>
            <p>{t('settings.privacy.p2')}</p>
            <p>{t('settings.privacy.p3')}</p>
          </div>
        </Panel>

        <div className="flex flex-col gap-4">
          <Panel title={t('settings.version.title')}>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm">
              <dt className="text-muted">{t('settings.version.app')}</dt>
              <dd className="font-mono text-fg">{__APP_VERSION__}</dd>
              <dt className="text-muted">{t('settings.version.schema')}</dt>
              <dd className="font-mono text-fg">{SCHEMA_VERSION}</dd>
            </dl>
          </Panel>
          <Panel title={t('settings.pending.title')}>
            <p className="text-sm text-muted">{t('settings.pending.body')}</p>
          </Panel>
        </div>
      </div>
    </>
  );
}
