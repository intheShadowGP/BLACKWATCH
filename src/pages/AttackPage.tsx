import { useDeferredValue, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { DatasetState, EmptyState, Pagination, SelectField, SourceNote, Tabs, Tag, TextField, paginate } from '../components/data';
import { PageHeader } from '../components/ui';
import { useDataset } from '../data/useDataset';
import { buildAttackIndex, matchesQuery, type AttackIndex } from '../lib/attack';
import { formatDate } from '../lib/format';

const TABS = ['matrix', 'groups', 'software', 'campaigns', 'mitigations'] as const;
const PAGE_SIZE = 30;

function Matrix({ index, query, platform }: { index: AttackIndex; query: string; platform: string }) {
  const { t } = useI18n();
  const columns = useMemo(
    () =>
      index.data.tactics.map((tactic) => ({
        tactic,
        techniques: index.techniquesOfTactic(tactic.shortname).filter((technique) => {
          const family = [technique, ...index.subTechniques(technique.id)];
          return family.some(
            (member) =>
              (platform === 'all' || member.platforms.includes(platform)) && matchesQuery(query, member.id, member.name),
          );
        }),
      })),
    [index, query, platform],
  );
  const total = columns.reduce((sum, column) => sum + column.techniques.length, 0);

  if (total === 0) return <EmptyState>{t('common.noResults')}</EmptyState>;
  return (
    <div className="overflow-x-auto pb-2" tabIndex={0} role="group" aria-label={t('attack.matrix.label')}>
      <div className="grid w-max grid-flow-col auto-cols-[11.5rem] gap-2">
        {columns.map(({ tactic, techniques }) => (
          <section key={tactic.id} aria-labelledby={`tactic-${tactic.id}`} className="rounded-sm border border-line bg-surface">
            <h2 id={`tactic-${tactic.id}`} className="border-b border-line px-2.5 py-2 text-xs font-semibold text-fg">
              <Link to={`/attack/${tactic.id}`} className="hover:underline">{tactic.name}</Link>
              <span className="mt-0.5 block font-mono font-normal text-subtle">
                {tactic.id} · {techniques.length}
              </span>
            </h2>
            <ul className="divide-y divide-line">
              {techniques.map((technique) => {
                const subs = index.subTechniques(technique.id).length;
                return (
                  <li key={technique.id}>
                    <Link to={`/attack/${technique.id}`} className="block px-2.5 py-1.5 text-xs text-muted hover:bg-raised hover:text-fg">
                      {technique.name}
                      <span className="mt-0.5 block font-mono text-[0.625rem] text-subtle">
                        {technique.id}
                        {subs > 0 ? ` · ${t('attack.subCount', { n: subs })}` : ''}
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>
    </div>
  );
}

interface ListRow {
  id: string;
  name: string;
  meta: string[];
  description: string;
  search: string[];
}

function ObjectList({ rows, query, page, onPage }: { rows: ListRow[]; query: string; page: number; onPage: (page: number) => void }) {
  const { t, language } = useI18n();
  const filtered = useMemo(() => rows.filter((row) => matchesQuery(query, row.id, row.name, row.search)), [rows, query]);
  const { slice, pageCount, page: current } = paginate(filtered, page, PAGE_SIZE);
  return (
    <>
      <p className="mb-2 text-sm text-muted" role="status">
        {t('common.results', { n: filtered.length.toLocaleString(language), total: rows.length.toLocaleString(language) })}
      </p>
      {filtered.length === 0 ? (
        <EmptyState>{t('common.noResults')}</EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-sm border border-line">
          {slice.map((row) => (
            <li key={row.id}>
              <Link to={`/attack/${row.id}`} className="block px-3 py-2.5 hover:bg-surface">
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-mono text-xs text-accent">{row.id}</span>
                  <span className="text-sm font-medium text-fg">{row.name}</span>
                  {row.meta.map((item) => (
                    <Tag key={item}>{item}</Tag>
                  ))}
                </span>
                <span className="mt-1 line-clamp-2 text-sm text-muted">{row.description}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <Pagination page={current} pageCount={pageCount} onChange={onPage} />
    </>
  );
}

export default function AttackPage() {
  const { t, language } = useI18n();
  const [params, setParams] = useSearchParams();
  const tab = TABS.find((id) => id === params.get('tab')) ?? 'matrix';
  const dataset = useDataset('attack');
  const [text, setText] = useState('');
  const [platform, setPlatform] = useState('all');
  const [page, setPage] = useState(1);
  const query = useDeferredValue(text);

  const index = useMemo(() => (dataset.status === 'ready' ? buildAttackIndex(dataset.data) : null), [dataset]);
  const platforms = useMemo(
    () => (index ? [...new Set(index.data.techniques.flatMap((technique) => technique.platforms))].sort() : []),
    [index],
  );

  const rows = useMemo((): ListRow[] => {
    if (!index) return [];
    const { data } = index;
    if (tab === 'groups') {
      return data.groups.map((group) => ({ id: group.id, name: group.name, meta: [], description: group.aliases.length > 0 ? `${t('attack.aliases')}: ${group.aliases.join(', ')}. ${group.description}` : group.description, search: group.aliases }));
    }
    if (tab === 'software') {
      return data.software.map((item) => ({ id: item.id, name: item.name, meta: [t(`attack.kind.${item.kind}`)], description: item.description, search: item.platforms }));
    }
    if (tab === 'campaigns') {
      return [...data.campaigns]
        .sort((a, b) => (b.firstSeen ?? '').localeCompare(a.firstSeen ?? ''))
        .map((campaign) => ({ id: campaign.id, name: campaign.name, meta: campaign.firstSeen ? [`${formatDate(campaign.firstSeen, language)} → ${formatDate(campaign.lastSeen, language)}`] : [], description: campaign.description, search: [] }));
    }
    if (tab === 'mitigations') {
      return data.mitigations.map((mitigation) => ({ id: mitigation.id, name: mitigation.name, meta: [], description: mitigation.description, search: [] }));
    }
    return [];
  }, [index, tab, t, language]);

  const panelId = 'attack-panel';
  const data = index?.data;

  return (
    <>
      <PageHeader
        title={t('nav.attack')}
        intro={t('attack.intro')}
        aside={dataset.status === 'ready' ? <Tag tone="gold">{t('attack.version', { version: dataset.data.version, date: formatDate(dataset.data.modified, language) })}</Tag> : undefined}
      />

      {!index || !data ? (
        <DatasetState state={dataset} />
      ) : (
        <>
          <Tabs
            label={t('nav.attack')}
            panelId={panelId}
            active={tab}
            onChange={(id) => {
              setParams(id === 'matrix' ? {} : { tab: id }, { replace: true });
              setPage(1);
            }}
            tabs={[
              { id: 'matrix', label: t('attack.tab.matrix'), count: data.techniques.length },
              { id: 'groups', label: t('attack.tab.groups'), count: data.groups.length },
              { id: 'software', label: t('attack.tab.software'), count: data.software.length },
              { id: 'campaigns', label: t('attack.tab.campaigns'), count: data.campaigns.length },
              { id: 'mitigations', label: t('attack.tab.mitigations'), count: data.mitigations.length },
            ]}
          />
          <div id={panelId} role="tabpanel" aria-labelledby={`${panelId}-tab-${tab}`}>
            <div className="mb-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_14rem] sm:items-end">
              <TextField
                label={t('common.search')}
                value={text}
                onChange={(value) => {
                  setText(value);
                  setPage(1);
                }}
                placeholder={t('attack.searchPlaceholder')}
              />
              {tab === 'matrix' ? (
                <SelectField
                  label={t('attack.platform')}
                  value={platform}
                  onChange={setPlatform}
                  options={[{ value: 'all', label: t('common.all') }, ...platforms.map((value) => ({ value, label: value }))]}
                />
              ) : null}
            </div>
            {tab === 'matrix' ? (
              <>
                <p className="mb-3 text-xs text-subtle">{t('attack.matrix.note')}</p>
                <Matrix index={index} query={query} platform={platform} />
              </>
            ) : (
              <ObjectList rows={rows} query={query} page={page} onPage={setPage} />
            )}
          </div>
          <p className="mt-4 text-xs text-subtle">{t('attack.truncationNote', { n: data.descriptionsTruncatedAt })}</p>
          {dataset.status === 'ready' ? <SourceNote entries={[dataset.entry]} /> : null}
        </>
      )}
    </>
  );
}
