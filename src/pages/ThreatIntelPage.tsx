import { useEffect, useId, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { DatasetState, EmptyState, ExternalLink, Pagination, SelectField, SourceNote, Tabs, Tag, TextField, paginate } from '../components/data';
import { IocExplorer } from '../components/IocExplorer';
import { ConfirmDialog } from '../components/Modal';
import { Button, PageHeader } from '../components/ui';
import type { ManifestEntry } from '../data/schemas';
import { useDataset } from '../data/useDataset';
import { matchesQuery } from '../lib/attack';
import type { NoteRecord } from '../lib/db';
import { formatDate, formatDateTime } from '../lib/format';
import { MAX_NOTE_LENGTH, deleteNote, listNotes, saveNote } from '../lib/notes';

const TABS = ['feed', 'ioc', 'actors', 'campaigns', 'notes'] as const;
type TabId = (typeof TABS)[number];
const PAGE_SIZE = 25;
const NOTES_SCOPE = 'threat-intel';

// ── Feed ────────────────────────────────────────────────────────────────────

interface FeedItem {
  key: string;
  source: 'certfr' | 'kev';
  date: string;
  title: string;
  summary: string;
  lang: 'fr' | 'en';
  external: string | null;
  internal: string | null;
  tags: string[];
}

function Feed() {
  const { t, language } = useI18n();
  const certfr = useDataset('certfr');
  const kev = useDataset('kev');
  const [text, setText] = useState('');
  const [source, setSource] = useState<'all' | 'certfr' | 'kev'>('all');
  const [page, setPage] = useState(1);

  const items = useMemo(() => {
    const list: FeedItem[] = [];
    if (certfr.status === 'ready') {
      for (const item of certfr.data.items) {
        list.push({ key: item.id, source: 'certfr', date: item.published, title: item.title, summary: item.summary, lang: 'fr', external: item.url, internal: null, tags: [item.id, t(`intel.certfr.${item.kind}`)] });
      }
    }
    if (kev.status === 'ready') {
      for (const item of kev.data.items.slice(0, 150)) {
        list.push({ key: `kev-${item.cve}`, source: 'kev', date: item.dateAdded, title: item.name, summary: item.description, lang: 'en', external: null, internal: `/vulnerabilities/${item.cve}`, tags: [item.cve, ...(item.ransomware === 'Known' ? [t('vuln.ransomware')] : [])] });
      }
    }
    return list.sort((a, b) => b.date.localeCompare(a.date) || a.key.localeCompare(b.key));
  }, [certfr, kev, t]);

  const filtered = useMemo(
    () => items.filter((item) => (source === 'all' || item.source === source) && matchesQuery(text, item.title, item.summary, item.tags)),
    [items, source, text],
  );
  const { slice, pageCount, page: current } = paginate(filtered, page, PAGE_SIZE);
  const entries: ManifestEntry[] = [certfr, kev].flatMap((result) => (result.status === 'ready' ? [result.entry] : []));

  if (certfr.status === 'loading' || kev.status === 'loading') return <DatasetState state={{ status: 'loading' }} />;
  if (entries.length === 0) return <DatasetState state={certfr.status === 'ready' ? { status: 'missing' } : certfr} />;

  return (
    <>
      <p className="mb-4 max-w-3xl text-sm text-muted">{t('intel.feed.scope')}</p>
      <div className="mb-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_14rem] sm:items-end">
        <TextField label={t('common.search')} value={text} onChange={(value) => { setText(value); setPage(1); }} />
        <SelectField
          label={t('intel.feed.source')}
          value={source}
          onChange={(value) => { setSource(value); setPage(1); }}
          options={[
            { value: 'all', label: t('common.all') },
            { value: 'certfr', label: 'CERT-FR' },
            { value: 'kev', label: 'CISA KEV' },
          ]}
        />
      </div>
      {[certfr, kev].some((result) => result.status === 'error' || result.status === 'missing') ? (
        <p className="mb-3 text-sm text-gold">{t('intel.feed.partial')}</p>
      ) : null}
      {filtered.length === 0 ? (
        <EmptyState>{t('common.noResults')}</EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-sm border border-line">
          {slice.map((item) => (
            <li key={item.key} className="px-3 py-3">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-subtle">
                <time dateTime={item.date}>{formatDate(item.date, language)}</time>
                <Tag tone={item.source === 'kev' ? 'alert' : 'gold'}>{item.source === 'kev' ? 'CISA KEV' : 'CERT-FR'}</Tag>
                {item.tags.map((tag) => (
                  <span key={tag} className="font-mono">{tag}</span>
                ))}
              </div>
              <p className="mt-1 text-sm font-medium text-fg" lang={item.lang}>
                {item.internal ? (
                  <Link to={item.internal} className="hover:underline">{item.title}</Link>
                ) : item.external ? (
                  <ExternalLink href={item.external} className="!text-fg">{item.title}</ExternalLink>
                ) : (
                  item.title
                )}
              </p>
              <p className="mt-1 line-clamp-3 text-sm text-muted" lang={item.lang}>{item.summary}</p>
            </li>
          ))}
        </ul>
      )}
      <Pagination page={current} pageCount={pageCount} onChange={setPage} />
      <SourceNote entries={entries} />
    </>
  );
}

// ── Threat actors and campaigns (from MITRE ATT&CK) ─────────────────────────

function Actors() {
  const { t } = useI18n();
  const attack = useDataset('attack');
  const [text, setText] = useState('');
  const [page, setPage] = useState(1);
  const groups = useMemo(
    () => (attack.status === 'ready' ? attack.data.groups.filter((group) => matchesQuery(text, group.id, group.name, group.aliases)) : []),
    [attack, text],
  );
  if (attack.status !== 'ready') return <DatasetState state={attack} />;
  const { slice, pageCount, page: current } = paginate(groups, page, PAGE_SIZE);
  const techniqueCount = new Map<string, number>();
  for (const [group] of attack.data.relations.groupTechnique) techniqueCount.set(group, (techniqueCount.get(group) ?? 0) + 1);

  return (
    <>
      <p className="mb-4 max-w-3xl text-sm text-muted">{t('intel.actors.scope')}</p>
      <TextField className="mb-4 max-w-md" label={t('common.search')} value={text} onChange={(value) => { setText(value); setPage(1); }} placeholder={t('intel.actors.placeholder')} />
      {groups.length === 0 ? (
        <EmptyState>{t('common.noResults')}</EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-sm border border-line">
          {slice.map((group) => (
            <li key={group.id}>
              <Link to={`/attack/${group.id}`} className="block px-3 py-2.5 hover:bg-surface">
                <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-mono text-xs text-accent">{group.id}</span>
                  <span className="text-sm font-medium text-fg">{group.name}</span>
                  <span className="text-xs text-subtle">{t('intel.actors.techniques', { n: techniqueCount.get(group.id) ?? 0 })}</span>
                </span>
                {group.aliases.length > 0 ? <span className="mt-1 block text-xs text-muted">{t('attack.aliases')}: {group.aliases.join(', ')}</span> : null}
                <span className="mt-1 line-clamp-2 text-sm text-muted">{group.description}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <Pagination page={current} pageCount={pageCount} onChange={setPage} />
      <SourceNote entries={[attack.entry]} />
    </>
  );
}

function Campaigns() {
  const { t, language } = useI18n();
  const attack = useDataset('attack');
  if (attack.status !== 'ready') return <DatasetState state={attack} />;
  const groupsOf = new Map<string, string[]>();
  for (const [campaign, group] of attack.data.relations.campaignGroup) groupsOf.set(campaign, [...(groupsOf.get(campaign) ?? []), group]);
  const groupName = new Map(attack.data.groups.map((group) => [group.id, group.name]));
  const campaigns = [...attack.data.campaigns].sort((a, b) => (b.firstSeen ?? '').localeCompare(a.firstSeen ?? ''));
  const years = [...new Set(campaigns.map((campaign) => campaign.firstSeen?.slice(0, 4) ?? '—'))];

  return (
    <>
      <p className="mb-4 max-w-3xl text-sm text-muted">{t('intel.campaigns.scope')}</p>
      <ol className="space-y-6">
        {years.map((year) => (
          <li key={year}>
            <h2 className="mb-2 border-b border-line pb-1 font-mono text-sm font-semibold text-gold">{year}</h2>
            <ul className="space-y-2 border-l border-line-strong pl-4">
              {campaigns
                .filter((campaign) => (campaign.firstSeen?.slice(0, 4) ?? '—') === year)
                .map((campaign) => (
                  <li key={campaign.id} className="text-sm">
                    <Link to={`/attack/${campaign.id}`} className="font-medium text-fg hover:underline">
                      <span className="font-mono text-xs text-accent">{campaign.id}</span> {campaign.name}
                    </Link>
                    <span className="ml-2 text-xs text-subtle">
                      {formatDate(campaign.firstSeen, language)} → {formatDate(campaign.lastSeen, language)}
                    </span>
                    {(groupsOf.get(campaign.id) ?? []).map((group) => (
                      <Link key={group} to={`/attack/${group}`} className="ml-2 text-xs text-muted hover:text-fg hover:underline">
                        {groupName.get(group) ?? group}
                      </Link>
                    ))}
                  </li>
                ))}
            </ul>
          </li>
        ))}
      </ol>
      <SourceNote entries={[attack.entry]} />
    </>
  );
}

// ── Investigation notes ─────────────────────────────────────────────────────

function Notes() {
  const { t, language } = useI18n();
  const inputId = useId();
  const [notes, setNotes] = useState<NoteRecord[] | 'unavailable' | null>(null);
  const [draft, setDraft] = useState('');
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const refresh = () =>
    listNotes(NOTES_SCOPE)
      .then(setNotes)
      .catch(() => setNotes('unavailable'));

  useEffect(() => {
    let cancelled = false;
    listNotes(NOTES_SCOPE)
      .then((list) => { if (!cancelled) setNotes(list); })
      .catch(() => { if (!cancelled) setNotes('unavailable'); });
    return () => { cancelled = true; };
  }, []);

  const save = async () => {
    try {
      await saveNote(NOTES_SCOPE, draft.trim(), editing ?? undefined);
      setDraft('');
      setEditing(null);
      await refresh();
    } catch {
      setNotes('unavailable');
    }
  };

  if (notes === 'unavailable') return <p className="text-sm text-gold">{t('settings.data.unavailable')}</p>;

  return (
    <div className="max-w-3xl">
      <p className="mb-4 text-sm text-muted">{t('intel.notes.scope')}</p>
      <label htmlFor={inputId} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
        {editing ? t('intel.notes.edit') : t('intel.notes.new')}
      </label>
      <textarea id={inputId} value={draft} onChange={(event) => setDraft(event.target.value)} maxLength={MAX_NOTE_LENGTH} rows={5} className="w-full rounded-sm border border-line-strong bg-bg p-2.5 text-sm text-fg" />
      <div className="mt-2 flex gap-2">
        <Button variant="danger" onClick={() => void save()} disabled={draft.trim() === ''}>{t('common.save')}</Button>
        {editing ? <Button onClick={() => { setEditing(null); setDraft(''); }}>{t('common.cancel')}</Button> : null}
      </div>

      <h2 className="mb-2 mt-6 text-xs font-semibold uppercase tracking-wider text-subtle">{t('intel.notes.saved', { n: notes?.length ?? 0 })}</h2>
      {notes === null ? (
        <p className="text-sm text-muted">{t('app.loading')}</p>
      ) : notes.length === 0 ? (
        <EmptyState>{t('intel.notes.empty')}</EmptyState>
      ) : (
        <ul className="space-y-3">
          {notes.map((note) => (
            <li key={note.id} className="rounded-sm border border-line bg-surface p-3">
              <p className="whitespace-pre-wrap break-words text-sm text-fg">{note.body}</p>
              <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-subtle">{formatDateTime(note.updatedAt, language)}</span>
                <span className="flex gap-2">
                  <Button variant="ghost" onClick={() => { setEditing(note.id); setDraft(note.body); }}>{t('common.edit')}</Button>
                  <Button variant="ghost" onClick={() => setDeleting(note.id)}>{t('common.delete')}</Button>
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={deleting !== null}
        title={t('intel.notes.deleteTitle')}
        body={t('intel.notes.deleteBody')}
        confirmLabel={t('common.delete')}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          const id = deleting;
          setDeleting(null);
          if (id) void deleteNote(id).then(refresh, () => setNotes('unavailable'));
        }}
      />
    </div>
  );
}

export default function ThreatIntelPage() {
  const { t } = useI18n();
  const [params, setParams] = useSearchParams();
  const tab: TabId = TABS.find((id) => id === params.get('tab')) ?? 'feed';
  const panelId = 'intel-panel';

  return (
    <>
      <PageHeader title={t('nav.threatIntel')} intro={t('intel.intro')} />
      <Tabs
        label={t('nav.threatIntel')}
        panelId={panelId}
        active={tab}
        onChange={(id) => setParams(id === 'feed' ? {} : { tab: id }, { replace: true })}
        tabs={TABS.map((id) => ({ id, label: t(`intel.tab.${id}`) }))}
      />
      <div id={panelId} role="tabpanel" aria-labelledby={`${panelId}-tab-${tab}`}>
        {tab === 'feed' ? <Feed /> : tab === 'ioc' ? <IocExplorer /> : tab === 'actors' ? <Actors /> : tab === 'campaigns' ? <Campaigns /> : <Notes />}
      </div>
      <p className="mt-6 text-xs text-subtle">{t('intel.notImplemented')}</p>
    </>
  );
}
