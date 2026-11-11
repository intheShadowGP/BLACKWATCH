import { useState } from 'react';
import { useI18n } from '../app/preferences-context';
import { EmptyState, Tabs } from '../components/data';
import { PageHeader } from '../components/ui';
import { useSoc } from '../soc/SocContext';
import { EntitiesView, EventsView, FilesPanel, FindingsView, ImportPanel, InvestigationView, SigmaView, TimelineView, TimeSettingsPanel } from '../soc/views';

const TABS = ['findings', 'events', 'timeline', 'entities', 'sigma', 'report'] as const;
type TabId = (typeof TABS)[number];

export default function SocPage() {
  const { t } = useI18n();
  const soc = useSoc();
  const [tab, setTab] = useState<TabId>('findings');
  const [focus, setFocus] = useState<number[] | null>(null);
  const showEvents = (ids: number[]) => {
    setFocus(ids);
    setTab('events');
  };
  const panelId = 'soc-panel';
  const counts: Partial<Record<TabId, number>> = soc.result ? { findings: soc.result.detections.findings.length, events: soc.result.events.length } : {};

  return (
    <>
      <PageHeader title={t('nav.soc')} intro={t('soc.intro')} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ImportPanel />
        <TimeSettingsPanel />
      </div>
      {soc.status === 'working' ? <p role="status" className="mt-4 text-sm text-muted">{t('soc.working')}</p> : null}
      {soc.status === 'error' ? <p role="alert" className="mt-4 text-sm text-accent">{t('soc.error')}</p> : null}
      {soc.status === 'idle' ? (
        <div className="mt-4">
          <EmptyState>{t('soc.empty')}</EmptyState>
        </div>
      ) : null}
      {soc.result && soc.status !== 'working' ? (
        <div className="mt-4 space-y-4">
          <FilesPanel />
          <Tabs
            label={t('nav.soc')}
            panelId={panelId}
            active={tab}
            onChange={(id) => {
              setTab(id);
              if (id !== 'events') setFocus(null);
            }}
            tabs={TABS.map((id) => ({ id, label: t(`soc.tab.${id}`), count: counts[id] }))}
          />
          <div id={panelId} role="tabpanel" aria-labelledby={`${panelId}-tab-${tab}`}>
            {tab === 'findings' ? <FindingsView onShowEvents={showEvents} /> : null}
            {tab === 'events' ? <EventsView focus={focus} onClearFocus={() => setFocus(null)} /> : null}
            {tab === 'timeline' ? <TimelineView onShowEvents={showEvents} /> : null}
            {tab === 'entities' ? <EntitiesView onShowEvents={showEvents} /> : null}
            {tab === 'sigma' ? <SigmaView onShowEvents={showEvents} /> : null}
            {tab === 'report' ? <InvestigationView /> : null}
          </div>
        </div>
      ) : null}
      {soc.status === 'idle' ? (
        <div className="mt-4">
          <InvestigationView />
        </div>
      ) : null}
    </>
  );
}
