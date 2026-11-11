import { useDeferredValue, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import {
  DatasetState,
  EmptyState,
  Pagination,
  PriorityBadge,
  SelectField,
  SeverityBadge,
  SourceNote,
  Tabs,
  Tag,
  TextField,
  paginate,
} from '../components/data';
import { Button, PageHeader } from '../components/ui';
import type { ManifestEntry } from '../data/schemas';
import { useDataset } from '../data/useDataset';
import { downloadText, fileStamp, toCsv } from '../lib/export';
import { useFavorites } from '../lib/favorites';
import { formatDate, formatNumber } from '../lib/format';
import { filterRows, toRow, type SeverityFilter, type SortKey, type VulnRow } from '../lib/vulnerabilities';

const TABS = ['recent', 'kev', 'watchlist'] as const;
type TabId = (typeof TABS)[number];
const PAGE_SIZE = 25;
const SEVERITIES: SeverityFilter[] = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];
const SORTS: SortKey[] = ['date', 'score', 'priority'];

function exportCsv(rows: readonly VulnRow[], tab: TabId) {
  const csv = toCsv(
    ['CVE', 'Priority', 'CVSS version', 'CVSS score', 'Severity', 'Date', 'In CISA KEV', 'KEV date added', 'KEV ransomware use', 'CWE', 'Products', 'Summary'],
    rows.map((row) => [
      row.id,
      `P${row.priority.level}`,
      row.cvss?.version ?? '',
      row.cvss?.score ?? '',
      row.cvss?.severity ?? '',
      row.date.slice(0, 10),
      row.kev ? 'yes' : 'no',
      row.kev?.dateAdded.slice(0, 10) ?? '',
      row.kev?.ransomware ?? '',
      (row.cve?.cwes ?? row.kev?.cwes ?? []).join(' '),
      row.cve?.products.join(' ') ?? (row.kev ? `${row.kev.vendor}:${row.kev.product}` : ''),
      row.summary,
    ]),
  );
  downloadText(`blackwatch-vulnerabilities-${tab}-${fileStamp()}.csv`, csv, 'text/csv;charset=utf-8');
}

export default function VulnerabilitiesPage() {
  const { t, language } = useI18n();
  const [params, setParams] = useSearchParams();
  const tab = TABS.find((id) => id === params.get('tab')) ?? 'recent';

  const recent = useDataset('nvd-recent');
  const kev = useDataset('kev');
  const nvdKev = useDataset('nvd-kev');
  const watchlist = useFavorites('cve');

  const [text, setText] = useState('');
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [sort, setSort] = useState<SortKey>('date');
  const [page, setPage] = useState(1);
  const deferredText = useDeferredValue(text);

  const { recentRows, kevRows, lookup } = useMemo(() => {
    const kevById = new Map(kev.status === 'ready' ? kev.data.items.map((item) => [item.cve, item]) : []);
    const nvdKevById = new Map(nvdKev.status === 'ready' ? nvdKev.data.items.map((item) => [item.id, item]) : []);
    const recentList = (recent.status === 'ready' ? recent.data.items : [])
      .map((item) => toRow(item, kevById.get(item.id) ?? null))
      .filter((row): row is VulnRow => row !== null);
    const kevList = (kev.status === 'ready' ? kev.data.items : [])
      .map((item) => toRow(nvdKevById.get(item.cve) ?? null, item))
      .filter((row): row is VulnRow => row !== null);
    const byId = new Map<string, VulnRow>();
    for (const row of kevList) byId.set(row.id, row);
    for (const row of recentList) byId.set(row.id, row);
    return { recentRows: recentList, kevRows: kevList, lookup: byId };
  }, [recent, kev, nvdKev]);

  const watchRows = useMemo(
    () => watchlist.refs.map((ref) => lookup.get(ref)).filter((row): row is VulnRow => row !== undefined),
    [watchlist.refs, lookup],
  );
  const unresolved = watchlist.refs.filter((ref) => !lookup.has(ref));

  const source = tab === 'recent' ? recentRows : tab === 'kev' ? kevRows : watchRows;
  const filtered = useMemo(
    () => filterRows(source, { text: deferredText, severity, sort }),
    [source, deferredText, severity, sort],
  );
  const { slice, pageCount, page: currentPage } = paginate(filtered, page, PAGE_SIZE);

  const primary = tab === 'kev' ? kev : recent;
  const entries: ManifestEntry[] = [recent, kev, nvdKev].flatMap((result) => (result.status === 'ready' ? [result.entry] : []));
  const panelId = 'vulnerabilities-panel';
  const resetPage = <T,>(setter: (value: T) => void) => (value: T) => {
    setter(value);
    setPage(1);
  };

  return (
    <>
      <PageHeader title={t('nav.vulnerabilities')} intro={t('vuln.intro')} />

      <Tabs
        label={t('nav.vulnerabilities')}
        panelId={panelId}
        active={tab}
        onChange={(id) => {
          setParams(id === 'recent' ? {} : { tab: id }, { replace: true });
          setPage(1);
        }}
        tabs={[
          { id: 'recent', label: t('vuln.tab.recent'), count: recentRows.length },
          { id: 'kev', label: t('vuln.tab.kev'), count: kevRows.length },
          { id: 'watchlist', label: t('vuln.tab.watchlist'), count: watchlist.refs.length },
        ]}
      />

      <div id={panelId} role="tabpanel" aria-labelledby={`${panelId}-tab-${tab}`}>
        {tab !== 'watchlist' && primary.status !== 'ready' ? (
          <DatasetState state={primary} />
        ) : (
          <>
            <p className="mb-4 max-w-3xl text-sm text-muted">{t(`vuln.scope.${tab}`)}</p>

            <div className="mb-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_11rem_11rem_auto] sm:items-end print:hidden">
              <TextField label={t('common.search')} value={text} onChange={resetPage(setText)} placeholder={t('vuln.searchPlaceholder')} />
              <SelectField
                label={t('vuln.filter.severity')}
                value={severity}
                onChange={resetPage(setSeverity)}
                options={SEVERITIES.map((value) => ({ value, label: value === 'all' ? t('common.all') : t(`severity.${value}`) }))}
              />
              <SelectField
                label={t('common.sort')}
                value={sort}
                onChange={resetPage(setSort)}
                options={SORTS.map((value) => ({ value, label: t(`vuln.sort.${value}`) }))}
              />
              <div className="flex gap-2">
                <Button onClick={() => exportCsv(filtered, tab)} disabled={filtered.length === 0}>
                  {t('common.exportCsv')}
                </Button>
                <Button onClick={() => window.print()} disabled={filtered.length === 0}>
                  {t('common.print')}
                </Button>
              </div>
            </div>

            <p className="mb-2 text-sm text-muted" role="status">
              {t('common.results', { n: formatNumber(filtered.length, language), total: formatNumber(source.length, language) })}
            </p>

            {filtered.length === 0 ? (
              <EmptyState>{tab === 'watchlist' && source.length === 0 ? t('vuln.watchlist.empty') : t('common.noResults')}</EmptyState>
            ) : (
              <div className="overflow-x-auto rounded-sm border border-line">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface text-xs uppercase tracking-wider text-subtle">
                    <tr>
                      <th scope="col" className="px-3 py-2 font-medium">CVE</th>
                      <th scope="col" className="px-3 py-2 font-medium">{t('vuln.col.priority')}</th>
                      <th scope="col" className="px-3 py-2 font-medium">{t('vuln.col.severity')}</th>
                      <th scope="col" className="hidden px-3 py-2 font-medium sm:table-cell">{t('vuln.col.date')}</th>
                      <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">{t('vuln.col.summary')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {slice.map((row) => (
                      <tr key={row.id} className="align-top hover:bg-surface">
                        <th scope="row" className="whitespace-nowrap px-3 py-2 font-normal">
                          <Link to={`/vulnerabilities/${row.id}`} className="font-mono text-accent hover:underline">
                            {row.id}
                          </Link>
                          {row.kev ? (
                            <div className="mt-1 flex gap-1">
                              <Tag tone="alert">KEV</Tag>
                              {row.kev.ransomware === 'Known' ? <Tag tone="alert">{t('vuln.ransomware')}</Tag> : null}
                            </div>
                          ) : null}
                        </th>
                        <td className="px-3 py-2">
                          <PriorityBadge level={row.priority.level} />
                        </td>
                        <td className="px-3 py-2">
                          <SeverityBadge severity={row.cvss?.severity ?? null} score={row.cvss?.score} />
                        </td>
                        <td className="hidden whitespace-nowrap px-3 py-2 text-muted sm:table-cell">{formatDate(row.date, language)}</td>
                        <td className="hidden px-3 py-2 text-muted md:table-cell">
                          <span className="line-clamp-2">{row.kev?.name ? `${row.kev.name} — ` : ''}{row.summary}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pagination page={currentPage} pageCount={pageCount} onChange={setPage} />

            {tab === 'watchlist' && unresolved.length > 0 ? (
              <p className="mt-4 text-sm text-muted">
                {t('vuln.watchlist.unresolved')}{' '}
                {unresolved.map((ref, index) => (
                  <span key={ref}>
                    {index > 0 ? ', ' : ''}
                    <Link to={`/vulnerabilities/${ref}`} className="font-mono text-accent hover:underline">{ref}</Link>
                  </span>
                ))}
              </p>
            ) : null}
            {tab === 'watchlist' && !watchlist.persistent ? <p className="mt-3 text-sm text-gold">{t('storage.banner')}</p> : null}
          </>
        )}
      </div>

      <SourceNote entries={entries} />
    </>
  );
}
