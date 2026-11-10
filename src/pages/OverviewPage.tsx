import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { MODULES } from '../app/modules';
import { useI18n, usePreferences } from '../app/preferences-context';
import { Icon } from '../components/Icon';
import { PageHeader, Panel, StatusBadge } from '../components/ui';
import { countRecords } from '../lib/storage';

type StorageState = { status: 'loading' } | { status: 'ok'; total: number } | { status: 'unavailable' };

function LocalStoragePanel() {
  const { t } = useI18n();
  const { persistent } = usePreferences();
  const [storage, setStorage] = useState<StorageState>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    countRecords()
      .then((counts) => {
        const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
        if (!cancelled) setStorage({ status: 'ok', total });
      })
      .catch(() => {
        if (!cancelled) setStorage({ status: 'unavailable' });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const available = persistent && storage.status === 'ok';
  return (
    <Panel title={t('overview.storage.title')}>
      {storage.status === 'loading' ? (
        <p className="text-sm text-muted">{t('app.loading')}</p>
      ) : available ? (
        <>
          <p className="text-sm text-muted">{t('overview.storage.ok')}</p>
          <p className="mt-3 font-mono text-sm text-fg">
            {t('overview.storage.records', { n: storage.total })}
          </p>
        </>
      ) : (
        <p className="text-sm text-gold">{t('overview.storage.unavailable')}</p>
      )}
    </Panel>
  );
}

export default function OverviewPage() {
  const { t } = useI18n();
  const modules = MODULES.filter((module) => module.id !== 'overview');

  return (
    <>
      <PageHeader title={t('overview.title')} intro={t('overview.intro')} />

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title={t('overview.modules.title')} className="lg:col-span-2">
          <ul className="-my-2 divide-y divide-line">
            {modules.map((module) => (
              <li key={module.id}>
                <Link
                  to={`/${module.path}`}
                  className="group flex items-center gap-3 py-2.5 text-sm hover:text-fg"
                >
                  <Icon name={module.icon} className="shrink-0 text-subtle group-hover:text-fg" />
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium text-fg">{t(module.titleKey)}</span>
                    {module.summaryKey ? (
                      <span className="block truncate text-muted">{t(module.summaryKey)}</span>
                    ) : null}
                  </span>
                  <StatusBadge status={module.status} milestone={module.milestone} />
                </Link>
              </li>
            ))}
          </ul>
          <p className="mt-4 border-t border-line pt-3 text-xs text-subtle">{t('overview.modules.note')}</p>
        </Panel>

        <div className="flex flex-col gap-4">
          <Panel title={t('overview.data.title')}>
            <p className="text-sm text-muted">{t('overview.data.empty')}</p>
          </Panel>
          <LocalStoragePanel />
          <Panel title={t('overview.privacy.title')}>
            <p className="text-sm text-muted">{t('overview.privacy.body')}</p>
          </Panel>
        </div>
      </div>
    </>
  );
}
