import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { DatasetState, ExternalLink, SourceNote, Tag } from '../components/data';
import { Icon } from '../components/Icon';
import { Button, PageHeader, Panel } from '../components/ui';
import { useDataset } from '../data/useDataset';
import type { MessageKey } from '../i18n';
import { attackUrl, buildAttackIndex, kindOfAttackId, type AttackIndex } from '../lib/attack';
import { formatDate } from '../lib/format';
import NotFoundPage from './NotFoundPage';

const COLLAPSED = 24;

function RelatedList({ title, ids, index }: { title: string; ids: readonly string[]; index: AttackIndex }) {
  const { t } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const sorted = useMemo(
    () => [...new Set(ids)].sort((a, b) => a.localeCompare(b, 'en', { numeric: true })),
    [ids],
  );
  if (sorted.length === 0) return null;
  const visible = expanded ? sorted : sorted.slice(0, COLLAPSED);
  return (
    <Panel title={`${title} (${sorted.length})`}>
      <ul className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-2">
        {visible.map((id) => {
          const object = index.get(id);
          const external = object?.kind === 'detection' ? attackUrl(id) : null;
          return (
            <li key={id} className="min-w-0">
              {external ? (
                <ExternalLink href={external}>
                  <span className="font-mono text-xs">{id}</span> {object?.name}
                </ExternalLink>
              ) : (
                <Link to={`/attack/${id}`} className="text-muted hover:text-fg hover:underline">
                  <span className="font-mono text-xs text-accent">{id}</span> {object?.name}
                </Link>
              )}
            </li>
          );
        })}
      </ul>
      {sorted.length > COLLAPSED ? (
        <Button variant="ghost" className="mt-3" onClick={() => setExpanded(!expanded)} aria-expanded={expanded}>
          {expanded ? t('common.showLess') : t('common.showAll', { n: sorted.length })}
        </Button>
      ) : null}
    </Panel>
  );
}

export default function AttackDetailPage() {
  const { t, language } = useI18n();
  const { attackId = '' } = useParams();
  const id = attackId.toUpperCase();
  const dataset = useDataset('attack');
  const index = useMemo(() => (dataset.status === 'ready' ? buildAttackIndex(dataset.data) : null), [dataset]);
  const kind = kindOfAttackId(id);

  if (!kind) return <NotFoundPage />;

  const back = (
    <Link to="/attack" className="mb-4 inline-flex items-center gap-2 text-sm text-muted hover:text-fg">
      <Icon name="arrow" className="rotate-180" />
      {t('nav.attack')}
    </Link>
  );

  if (!index) {
    return (
      <>
        {back}
        <PageHeader title={id} />
        <DatasetState state={dataset} />
      </>
    );
  }

  const object = index.get(id);
  const url = attackUrl(id);
  if (!object) {
    return (
      <>
        {back}
        <PageHeader title={id} />
        <p className="text-sm text-muted">{t('attack.detail.notFound', { version: index.data.version })}</p>
        {url ? (
          <p className="mt-3 text-sm">
            <ExternalLink href={url}>{t('attack.detail.openMitre')}</ExternalLink>
          </p>
        ) : null}
      </>
    );
  }

  const { data } = index;
  const technique = kind === 'technique' ? data.techniques.find((item) => item.id === id) : undefined;
  const group = kind === 'group' ? data.groups.find((item) => item.id === id) : undefined;
  const software = kind === 'software' ? data.software.find((item) => item.id === id) : undefined;
  const campaign = kind === 'campaign' ? data.campaigns.find((item) => item.id === id) : undefined;
  const tacticNames = technique
    ? technique.tactics.map((shortname) => data.tactics.find((tactic) => tactic.shortname === shortname)).filter((tactic) => tactic !== undefined)
    : [];
  const title = (key: string) => t(`attack.rel.${key}` as MessageKey);

  return (
    <>
      {back}
      <PageHeader
        title={`${object.name}`}
        aside={
          <div className="flex flex-wrap items-center gap-2">
            <Tag tone="gold">{id}</Tag>
            <Tag>{t(`attack.kindName.${kind}` as MessageKey)}</Tag>
            {software ? <Tag>{t(`attack.kind.${software.kind}`)}</Tag> : null}
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="flex flex-col gap-4 lg:col-span-2">
          <Panel title={t('attack.detail.description')}>
            <p className="whitespace-pre-line text-sm text-fg">{object.description || t('attack.detail.noDescription')}</p>
            {url ? (
              <p className="mt-3 text-sm">
                <ExternalLink href={url}>{t('attack.detail.openMitre')}</ExternalLink>
              </p>
            ) : null}
          </Panel>

          {kind === 'tactic' ? (
            <RelatedList title={title('techniques')} index={index} ids={index.techniquesOfTactic(data.tactics.find((tactic) => tactic.id === id)?.shortname ?? '').map((item) => item.id)} />
          ) : null}
          {technique ? (
            <>
              <RelatedList title={title('subTechniques')} index={index} ids={index.subTechniques(id).map((item) => item.id)} />
              <RelatedList title={title('mitigations')} index={index} ids={index.relatedTo('mitigationTechnique', id)} />
              <RelatedList title={title('detections')} index={index} ids={index.relatedTo('detectionTechnique', id)} />
              <RelatedList title={title('groups')} index={index} ids={index.relatedTo('groupTechnique', id)} />
              <RelatedList title={title('software')} index={index} ids={index.relatedTo('softwareTechnique', id)} />
              <RelatedList title={title('campaigns')} index={index} ids={index.relatedTo('campaignTechnique', id)} />
            </>
          ) : null}
          {group ? (
            <>
              <RelatedList title={title('techniques')} index={index} ids={index.related('groupTechnique', id)} />
              <RelatedList title={title('software')} index={index} ids={index.related('groupSoftware', id)} />
              <RelatedList title={title('campaigns')} index={index} ids={index.relatedTo('campaignGroup', id)} />
            </>
          ) : null}
          {software ? (
            <>
              <RelatedList title={title('techniques')} index={index} ids={index.related('softwareTechnique', id)} />
              <RelatedList title={title('groups')} index={index} ids={index.relatedTo('groupSoftware', id)} />
              <RelatedList title={title('campaigns')} index={index} ids={index.relatedTo('campaignSoftware', id)} />
            </>
          ) : null}
          {campaign ? (
            <>
              <RelatedList title={title('groups')} index={index} ids={index.related('campaignGroup', id)} />
              <RelatedList title={title('techniques')} index={index} ids={index.related('campaignTechnique', id)} />
              <RelatedList title={title('software')} index={index} ids={index.related('campaignSoftware', id)} />
            </>
          ) : null}
          {kind === 'mitigation' ? <RelatedList title={title('techniques')} index={index} ids={index.related('mitigationTechnique', id)} /> : null}
        </div>

        <div className="flex flex-col gap-4">
          {technique ? (
            <Panel title={t('attack.detail.context')}>
              <dl className="space-y-3 text-sm">
                <div>
                  <dt className="text-xs uppercase tracking-wider text-subtle">{t('attack.detail.tactics')}</dt>
                  <dd className="mt-1 flex flex-wrap gap-1.5">
                    {tacticNames.map((tactic) => (
                      <Link key={tactic.id} to={`/attack/${tactic.id}`} className="text-accent hover:underline">
                        {tactic.name}
                      </Link>
                    ))}
                  </dd>
                </div>
                {technique.parent ? (
                  <div>
                    <dt className="text-xs uppercase tracking-wider text-subtle">{t('attack.detail.parent')}</dt>
                    <dd className="mt-1">
                      <Link to={`/attack/${technique.parent}`} className="text-accent hover:underline">
                        <span className="font-mono text-xs">{technique.parent}</span> {index.get(technique.parent)?.name}
                      </Link>
                    </dd>
                  </div>
                ) : null}
                <div>
                  <dt className="text-xs uppercase tracking-wider text-subtle">{t('attack.platform')}</dt>
                  <dd className="mt-1 flex flex-wrap gap-1.5">
                    {technique.platforms.map((platform) => (
                      <Tag key={platform}>{platform}</Tag>
                    ))}
                  </dd>
                </div>
              </dl>
            </Panel>
          ) : null}
          {group && group.aliases.length > 0 ? (
            <Panel title={t('attack.aliases')}>
              <ul className="flex flex-wrap gap-1.5">
                {group.aliases.map((alias) => (
                  <li key={alias}><Tag>{alias}</Tag></li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-subtle">{t('attack.aliasesNote')}</p>
            </Panel>
          ) : null}
          {software && software.platforms.length > 0 ? (
            <Panel title={t('attack.platform')}>
              <ul className="flex flex-wrap gap-1.5">
                {software.platforms.map((platform) => (
                  <li key={platform}><Tag>{platform}</Tag></li>
                ))}
              </ul>
            </Panel>
          ) : null}
          {campaign ? (
            <Panel title={t('attack.detail.period')}>
              <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
                <dt className="text-muted">{t('attack.detail.firstSeen')}</dt>
                <dd>{formatDate(campaign.firstSeen, language)}</dd>
                <dt className="text-muted">{t('attack.detail.lastSeen')}</dt>
                <dd>{formatDate(campaign.lastSeen, language)}</dd>
              </dl>
              <p className="mt-3 text-xs text-subtle">{t('attack.detail.periodNote')}</p>
            </Panel>
          ) : null}
          <Panel title={t('attack.detail.dataset')}>
            <p className="text-sm text-muted">
              {t('attack.version', { version: data.version, date: formatDate(data.modified, language) })}
            </p>
            <p className="mt-2 text-xs text-subtle">{t('attack.truncationNote', { n: data.descriptionsTruncatedAt })}</p>
          </Panel>
        </div>
      </div>

      {dataset.status === 'ready' ? <SourceNote entries={[dataset.entry]} /> : null}
    </>
  );
}
