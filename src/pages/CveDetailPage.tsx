import { Link, useParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { DatasetState, ExternalLink, PriorityBadge, SeverityBadge, SourceNote, Tag } from '../components/data';
import { Icon } from '../components/Icon';
import { Button, PageHeader, Panel } from '../components/ui';
import type { Cvss, ManifestEntry } from '../data/schemas';
import { useDataset } from '../data/useDataset';
import type { MessageKey } from '../i18n';
import { computeCvss3BaseScore, decodeVector } from '../lib/cvss';
import { useFavorites } from '../lib/favorites';
import { formatDate } from '../lib/format';
import { CVE_ID_PATTERN, toRow } from '../lib/vulnerabilities';
import NotFoundPage from './NotFoundPage';

const REMEDIATION_TAGS = ['Patch', 'Vendor Advisory', 'Mitigation'];

function CvssBlock({ cvss }: { cvss: Cvss }) {
  const { t } = useI18n();
  const decoded = decodeVector(cvss.vector);
  const recomputed = cvss.version === '4.0' ? null : computeCvss3BaseScore(cvss.vector);
  return (
    <div className="border-t border-line pt-4 first:border-t-0 first:pt-0">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold text-fg">CVSS {cvss.version}</h3>
        <SeverityBadge severity={cvss.severity} score={cvss.score} />
        <span className="text-xs text-subtle">{t('vuln.cvss.source', { source: cvss.source })}</span>
      </div>
      <p className="mt-2 break-all font-mono text-xs text-muted">{cvss.vector}</p>
      {decoded ? (
        <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
          {decoded.base.map((metric) => (
            <div key={metric.metric} className="contents">
              <dt className="text-muted">{metric.metricName}</dt>
              <dd className="text-fg">{metric.valueName}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="mt-2 text-sm text-gold">{t('vuln.cvss.undecodable')}</p>
      )}
      <p className="mt-3 text-xs text-subtle">
        {cvss.version === '4.0'
          ? t('vuln.cvss.v4note')
          : recomputed === null
            ? t('vuln.cvss.undecodable')
            : t(recomputed === cvss.score ? 'vuln.cvss.recomputedMatch' : 'vuln.cvss.recomputedDiffer', { score: recomputed.toFixed(1) })}
      </p>
    </div>
  );
}

export default function CveDetailPage() {
  const { t, language } = useI18n();
  const { cveId = '' } = useParams();
  const id = cveId.toUpperCase();
  const recent = useDataset('nvd-recent');
  const nvdKev = useDataset('nvd-kev');
  const kev = useDataset('kev');
  const watchlist = useFavorites('cve');

  if (!CVE_ID_PATTERN.test(id)) return <NotFoundPage />;

  const results = [recent, nvdKev, kev];
  const loading = results.some((result) => result.status === 'loading');
  const cve =
    (recent.status === 'ready' ? recent.data.items.find((item) => item.id === id) : undefined) ??
    (nvdKev.status === 'ready' ? nvdKev.data.items.find((item) => item.id === id) : undefined) ??
    null;
  const kevItem = (kev.status === 'ready' ? kev.data.items.find((item) => item.cve === id) : undefined) ?? null;
  const row = toRow(cve, kevItem);
  const entries: ManifestEntry[] = results.flatMap((result) => (result.status === 'ready' ? [result.entry] : []));
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${id}`;

  const back = (
    <Link to="/vulnerabilities" className="mb-4 inline-flex items-center gap-2 text-sm text-muted hover:text-fg print:hidden">
      <Icon name="arrow" className="rotate-180" />
      {t('nav.vulnerabilities')}
    </Link>
  );

  if (!row) {
    const failed = results.find((result) => result.status === 'error' || result.status === 'missing');
    return (
      <>
        {back}
        <PageHeader title={id} />
        {loading ? (
          <DatasetState state={{ status: 'loading' }} />
        ) : failed && entries.length === 0 ? (
          <DatasetState state={failed} />
        ) : (
          <div className="space-y-3 text-sm text-muted">
            <p>{t('vuln.detail.notInDatasets')}</p>
            <p>
              <ExternalLink href={nvdUrl}>{t('vuln.detail.openNvd')}</ExternalLink>
            </p>
          </div>
        )}
        {watchlist.has(id) ? (
          <Button className="mt-4" onClick={() => watchlist.toggle(id, id)}>
            {t('vuln.watch.remove')}
          </Button>
        ) : null}
      </>
    );
  }

  const remediation = cve?.references.filter((reference) => reference.tags.some((tag) => REMEDIATION_TAGS.includes(tag))) ?? [];
  const watched = watchlist.has(id);

  return (
    <>
      {back}
      <PageHeader
        title={id}
        intro={kevItem?.name}
        aside={
          <div className="flex flex-wrap gap-2 print:hidden">
            <Button onClick={() => watchlist.toggle(id, kevItem?.name ?? id)} aria-pressed={watched}>
              {watched ? t('vuln.watch.remove') : t('vuln.watch.add')}
            </Button>
            <Button onClick={() => window.print()}>{t('common.print')}</Button>
          </div>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <PriorityBadge level={row.priority.level} />
        <SeverityBadge severity={row.cvss?.severity ?? null} score={row.cvss?.score} />
        {kevItem ? <Tag tone="alert">{t('vuln.kev.listed')}</Tag> : null}
        {kevItem?.ransomware === 'Known' ? <Tag tone="alert">{t('vuln.ransomware')}</Tag> : null}
        {cve ? <Tag>{cve.status}</Tag> : null}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="flex flex-col gap-4 lg:col-span-2">
          <Panel title={t('vuln.detail.description')}>
            <p className="whitespace-pre-line text-sm text-fg">{row.summary || t('vuln.detail.noDescription')}</p>
            {cve ? (
              <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-sm">
                <dt className="text-muted">{t('vuln.detail.published')}</dt>
                <dd>{formatDate(cve.published, language)}</dd>
                <dt className="text-muted">{t('vuln.detail.modified')}</dt>
                <dd>{formatDate(cve.lastModified, language)}</dd>
              </dl>
            ) : (
              <p className="mt-3 text-sm text-gold">{t('vuln.detail.noNvdRecord')}</p>
            )}
            <p className="mt-3 text-sm">
              <ExternalLink href={nvdUrl}>{t('vuln.detail.openNvd')}</ExternalLink>
            </p>
          </Panel>

          {kevItem ? (
            <Panel title={t('vuln.kev.title')}>
              <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm">
                <dt className="text-muted">{t('vuln.kev.product')}</dt>
                <dd>{kevItem.vendor} — {kevItem.product}</dd>
                <dt className="text-muted">{t('vuln.kev.dateAdded')}</dt>
                <dd>{formatDate(kevItem.dateAdded, language)}</dd>
                <dt className="text-muted">{t('vuln.kev.dueDate')}</dt>
                <dd>{formatDate(kevItem.dueDate, language)}</dd>
                <dt className="text-muted">{t('vuln.kev.ransomware')}</dt>
                <dd>{t(kevItem.ransomware === 'Known' ? 'vuln.kev.ransomwareKnown' : 'vuln.kev.ransomwareUnknown')}</dd>
              </dl>
              <h3 className="mt-4 text-xs font-semibold uppercase tracking-wider text-subtle">{t('vuln.kev.requiredAction')}</h3>
              <p className="mt-1 text-sm text-fg">{kevItem.requiredAction}</p>
              <p className="mt-3 text-xs text-subtle">{t('vuln.kev.dueDateNote')}</p>
            </Panel>
          ) : null}

          <Panel title={t('vuln.cvss.title')}>
            {cve?.cvss3 || cve?.cvss4 ? (
              <div className="space-y-4">
                {cve.cvss4 ? <CvssBlock cvss={cve.cvss4} /> : null}
                {cve.cvss3 ? <CvssBlock cvss={cve.cvss3} /> : null}
              </div>
            ) : (
              <p className="text-sm text-muted">{t('vuln.cvss.none')}</p>
            )}
          </Panel>

          <Panel title={t('vuln.detail.references')}>
            {cve && cve.referenceCount > cve.references.length ? (
              <p className="mb-3 text-xs text-subtle">{t('vuln.detail.referencesPartial', { shown: cve.references.length, total: cve.referenceCount })}</p>
            ) : null}
            {cve && cve.references.length > 0 ? (
              <ul className="space-y-2 text-sm">
                {cve.references.map((reference) => (
                  <li key={reference.url} className="break-all">
                    <ExternalLink href={reference.url}>{reference.url}</ExternalLink>
                    {reference.tags.length > 0 ? <span className="ml-2 text-xs text-subtle">{reference.tags.join(' · ')}</span> : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">{t('vuln.detail.noReferences')}</p>
            )}
          </Panel>
        </div>

        <div className="flex flex-col gap-4">
          <Panel title={t('vuln.priority.title')}>
            <p className="flex items-center gap-2 text-sm text-fg">
              <PriorityBadge level={row.priority.level} />
              {t(`priority.level.${row.priority.level}` as MessageKey)}
            </p>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted">
              {row.priority.factors.map((factor) => (
                <li key={factor}>{t(`priority.factor.${factor}` as MessageKey, { score: row.cvss?.score.toFixed(1) ?? '', version: row.cvss?.version ?? '' })}</li>
              ))}
            </ul>
            <p className="mt-3 text-xs text-subtle">{t('priority.method')}</p>
          </Panel>

          <Panel title={t('vuln.remediation.title')}>
            {remediation.length > 0 ? (
              <ul className="space-y-2 text-sm">
                {remediation.map((reference) => (
                  <li key={reference.url} className="break-all">
                    <ExternalLink href={reference.url}>{reference.url}</ExternalLink>
                    <span className="ml-2 text-xs text-subtle">{reference.tags.filter((tag) => REMEDIATION_TAGS.includes(tag)).join(' · ')}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">{t('vuln.remediation.none')}</p>
            )}
            <p className="mt-3 text-xs text-subtle">{t('vuln.remediation.note')}</p>
          </Panel>

          <Panel title={t('vuln.detail.weaknesses')}>
            {(cve?.cwes ?? kevItem?.cwes ?? []).length > 0 ? (
              <ul className="flex flex-wrap gap-2 text-sm">
                {(cve?.cwes ?? kevItem?.cwes ?? []).map((cwe) => (
                  <li key={cwe}>
                    <ExternalLink href={`https://cwe.mitre.org/data/definitions/${cwe.slice(4)}.html`} className="font-mono">{cwe}</ExternalLink>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">{t('vuln.detail.noWeaknesses')}</p>
            )}
          </Panel>

          <Panel title={t('vuln.detail.products')}>
            {cve && cve.products.length > 0 ? (
              <ul className="space-y-1 break-all font-mono text-xs text-muted">
                {cve.products.map((product) => (
                  <li key={product}>{product}</li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">{t('vuln.detail.noProducts')}</p>
            )}
            <p className="mt-3 text-xs text-subtle">{t('vuln.detail.productsNote')}</p>
          </Panel>
        </div>
      </div>

      <SourceNote entries={entries} />
    </>
  );
}
