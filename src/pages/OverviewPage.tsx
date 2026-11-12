import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { MODULES } from '../app/modules';
import { useI18n, usePreferences } from '../app/preferences-context';
import { BarChart, DatasetState, ExternalLink, FreshnessTag, SeverityBadge, TableScroll, Tag } from '../components/data';
import { Icon } from '../components/Icon';
import { PageHeader, Panel, StatusBadge } from '../components/ui';
import { freshness } from '../data/loader';
import { useDataset, useManifest, useOverview } from '../data/useDataset';
import type { MessageKey } from '../i18n';
import { formatAge, formatDate, formatDateTime, formatNumber } from '../lib/format';
import { countRecords } from '../lib/storage';

function Kpi({ label, value, source, to }: { label: string; value: string; source: string; to?: string }) {
  const body = (
    <>
      <p className="text-xs uppercase tracking-wider text-subtle">{label}</p>
      <p className="mt-1 font-mono text-2xl font-semibold text-fg">{value}</p>
      <p className="mt-1 text-xs text-subtle">{source}</p>
    </>
  );
  return to ? (
    <Link to={to} className="block rounded-sm border border-line bg-surface p-4 hover:border-line-strong">
      {body}
    </Link>
  ) : (
    <div className="rounded-sm border border-line bg-surface p-4">{body}</div>
  );
}

function PanelLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="mt-3 inline-flex items-center gap-2 text-sm text-accent hover:underline">
      {children}
      <Icon name="arrow" />
    </Link>
  );
}

function LocalStoragePanel() {
  const { t } = useI18n();
  const { persistent } = usePreferences();
  const [total, setTotal] = useState<number | 'unavailable' | null>(null);

  useEffect(() => {
    let cancelled = false;
    countRecords()
      .then((counts) => {
        if (!cancelled) setTotal(Object.values(counts).reduce((sum, count) => sum + count, 0));
      })
      .catch(() => {
        if (!cancelled) setTotal('unavailable');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Panel title={t('overview.storage.title')}>
      {total === null ? (
        <p className="text-sm text-muted">{t('app.loading')}</p>
      ) : persistent && total !== 'unavailable' ? (
        <>
          <p className="text-sm text-muted">{t('overview.storage.ok')}</p>
          <p className="mt-3 font-mono text-sm text-fg">{t('overview.storage.records', { n: total })}</p>
        </>
      ) : (
        <p className="text-sm text-gold">{t('overview.storage.unavailable')}</p>
      )}
    </Panel>
  );
}

export default function OverviewPage() {
  const { t, language } = useI18n();
  const manifest = useManifest();
  const overview = useOverview();
  const loading = { status: 'loading' } as const;
  const kev = 'kev' in overview ? overview.kev : loading;
  const recent = 'recent' in overview ? overview.recent : loading;
  const certfr = useDataset('certfr');
  const kevStats = kev.status === 'ready' ? kev.data : null;
  const recentStats = recent.status === 'ready' ? recent.data : null;

  const attackEntry = manifest.status === 'ready' ? manifest.manifest.datasets.find((entry) => entry.id === 'attack') : undefined;
  const modules = MODULES.filter((module) => module.id !== 'overview');
  const dash = '—';

  return (
    <>
      <PageHeader title={t('overview.title')} intro={t('overview.intro')} />

      {manifest.status === 'missing' ? (
        <div className="mb-4 rounded-sm border border-line-strong bg-surface p-4 text-sm text-gold">{t('overview.data.empty')}</div>
      ) : manifest.status === 'error' ? (
        <div className="mb-4">
          <DatasetState state={manifest} />
        </div>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label={t('overview.kpi.kevTotal')} value={kevStats ? formatNumber(kevStats.total, language) : dash} source="CISA KEV" to="/vulnerabilities?tab=kev" />
        <Kpi label={t('overview.kpi.kevRecent')} value={kevStats ? formatNumber(kevStats.added30, language) : dash} source="CISA KEV" to="/vulnerabilities?tab=kev" />
        <Kpi label={t('overview.kpi.cveRecent')} value={recentStats ? formatNumber(recentStats.total, language) : dash} source="NVD" to="/vulnerabilities" />
        <Kpi label={t('overview.kpi.cveCritical')} value={recentStats ? formatNumber(recentStats.buckets.CRITICAL, language) : dash} source="NVD" to="/vulnerabilities" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title={t('overview.chart.severity')}>
          {recentStats ? (
            <>
              <BarChart
                caption={t('overview.chart.severity')}
                data={[
                  { label: t('severity.CRITICAL'), value: recentStats.buckets.CRITICAL, tone: 'accent' },
                  { label: t('severity.HIGH'), value: recentStats.buckets.HIGH, tone: 'accent' },
                  { label: t('severity.MEDIUM'), value: recentStats.buckets.MEDIUM, tone: 'gold' },
                  { label: t('severity.LOW'), value: recentStats.buckets.LOW },
                  { label: t('severity.NONE'), value: recentStats.buckets.NONE },
                  { label: t('severity.UNSCORED'), value: recentStats.buckets.UNSCORED },
                ]}
              />
              <p className="mt-3 text-xs text-subtle">{t('overview.chart.severityNote', { kev: recentStats.inKev })}</p>
            </>
          ) : (
            // Reserves roughly the chart's height so the panels below do not move when it arrives.
            <div className="min-h-52">
              <DatasetState state={recent} />
            </div>
          )}
        </Panel>
        <Panel title={t('overview.chart.kevMonthly')}>
          {kevStats ? (
            <>
              <BarChart caption={t('overview.chart.kevMonthly')} data={kevStats.months.map((month) => ({ ...month, tone: 'gold' as const }))} />
              <p className="mt-3 text-xs text-subtle">{t('overview.chart.kevNote', { n: formatNumber(kevStats.ransomware, language) })}</p>
            </>
          ) : (
            <div className="min-h-[22rem]">
              <DatasetState state={kev} />
            </div>
          )}
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title={t('overview.list.kev')}>
          {kevStats ? (
            <>
              <ul className="-my-2 divide-y divide-line">
                {kevStats.latest.map((item) => (
                  <li key={item.cve} className="py-2 text-sm">
                    <Link to={`/vulnerabilities/${item.cve}`} className="font-mono text-accent hover:underline">{item.cve}</Link>
                    <span className="ml-2 text-xs text-subtle">{formatDate(item.dateAdded, language)}</span>
                    <span className="mt-0.5 line-clamp-2 text-muted">{item.name}</span>
                  </li>
                ))}
              </ul>
              <PanelLink to="/vulnerabilities?tab=kev">{t('overview.list.all')}</PanelLink>
            </>
          ) : (
            <DatasetState state={kev} />
          )}
        </Panel>

        <Panel title={t('overview.list.critical')}>
          {recentStats ? (
            recentStats.critical.length > 0 ? (
              <>
                <ul className="-my-2 divide-y divide-line">
                  {recentStats.critical.map((item) => (
                    <li key={item.id} className="py-2 text-sm">
                      <span className="flex flex-wrap items-center gap-2">
                        <Link to={`/vulnerabilities/${item.id}`} className="font-mono text-accent hover:underline">{item.id}</Link>
                        <SeverityBadge severity={item.cvss.severity} score={item.cvss.score} />
                      </span>
                      <span className="mt-0.5 line-clamp-2 text-muted">{item.description}</span>
                    </li>
                  ))}
                </ul>
                <PanelLink to="/vulnerabilities">{t('overview.list.all')}</PanelLink>
              </>
            ) : (
              <p className="text-sm text-muted">{t('overview.list.noCritical')}</p>
            )
          ) : (
            <DatasetState state={recent} />
          )}
        </Panel>

        <Panel title={t('overview.list.advisories')}>
          {certfr.status === 'ready' ? (
            <>
              <ul className="-my-2 divide-y divide-line">
                {certfr.data.items.slice(0, 6).map((item) => (
                  <li key={item.id} className="py-2 text-sm">
                    <span className="font-mono text-xs text-subtle">{item.id} · {formatDate(item.published, language)}</span>
                    <span className="mt-0.5 block" lang="fr">
                      <ExternalLink href={item.url}>{item.title}</ExternalLink>
                    </span>
                  </li>
                ))}
              </ul>
              <PanelLink to="/threat-intel">{t('overview.list.all')}</PanelLink>
            </>
          ) : (
            <DatasetState state={certfr} />
          )}
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title={t('overview.data.title')} className="lg:col-span-2">
          {manifest.status === 'ready' ? (
            <>
              <TableScroll label={t('overview.data.title')}>
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-line text-xs uppercase tracking-wider text-subtle">
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('overview.data.dataset')}</th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('overview.data.status')}</th>
                      <th scope="col" className="py-1.5 pr-3 font-medium">{t('overview.data.retrieved')}</th>
                      <th scope="col" className="py-1.5 text-right font-medium">{t('settings.data.count')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {manifest.manifest.datasets.map((entry) => (
                      <tr key={entry.id}>
                        <th scope="row" className="py-1.5 pr-3 font-normal text-fg">
                          {t(`dataset.${entry.id}` as MessageKey)}
                          <span className="block text-xs text-subtle">{entry.publisher}</span>
                        </th>
                        <td className="py-1.5 pr-3"><FreshnessTag entry={entry} /></td>
                        <td className="whitespace-nowrap py-1.5 pr-3 text-muted">
                          {entry.retrievedAt ? (
                            <>
                              {formatAge(freshness(entry).ageHours, language)}
                              <span className="block text-xs text-subtle">{formatDateTime(entry.retrievedAt, language)}</span>
                            </>
                          ) : dash}
                        </td>
                        <td className="py-1.5 text-right font-mono text-muted">{formatNumber(entry.count, language)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
              <p className="mt-3 text-xs text-subtle">{t('overview.data.note')}</p>
              {attackEntry?.version ? (
                <p className="mt-2 text-xs text-subtle">
                  <Tag tone="gold">{t('attack.versionShort', { version: attackEntry.version })}</Tag>
                </p>
              ) : null}
            </>
          ) : manifest.status === 'missing' ? (
            <p className="text-sm text-muted">{t('overview.data.empty')}</p>
          ) : (
            <DatasetState state={manifest} />
          )}
        </Panel>

        <div className="flex flex-col gap-4">
          <Panel title={t('overview.modules.title')}>
            <ul className="-my-2 divide-y divide-line">
              {modules.map((module) => (
                <li key={module.id}>
                  <Link to={`/${module.path}`} className="group flex items-center gap-3 py-2 text-sm">
                    <Icon name={module.icon} className="shrink-0 text-subtle group-hover:text-fg" />
                    <span className="min-w-0 flex-1 text-fg group-hover:underline">{t(module.titleKey)}</span>
                    <StatusBadge status={module.status} milestone={module.milestone} />
                  </Link>
                </li>
              ))}
            </ul>
            <p className="mt-3 border-t border-line pt-3 text-xs text-subtle">{t('overview.modules.note')}</p>
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
