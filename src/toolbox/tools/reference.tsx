import { useI18n } from '../../app/preferences-context';
import { ExternalLink, Tag } from '../../components/data';
import { Panel } from '../../components/ui';
import type { MessageKey } from '../../i18n';
import { TLS_RULES, TLS_SUITES, TLS_VERSIONS, type Citation } from '../lib/reference';

function Cites({ items }: { items: readonly Citation[] }) {
  return (
    <span className="flex flex-wrap gap-x-2 gap-y-1">
      {items.map((item) => (
        <ExternalLink key={item.label} href={item.url} className="whitespace-nowrap text-xs">
          {item.label}
        </ExternalLink>
      ))}
    </span>
  );
}

const STATUS_TONE = { prohibited: 'alert', deprecated: 'alert', required: 'gold', recommended: 'gold' } as const;

export function TlsTool() {
  const { t } = useI18n();
  return (
    <div className="space-y-4">
      <Panel title={t('tb.tls.versions')}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-subtle">
              <tr>
                <th scope="col" className="py-1.5 pr-3 font-medium">{t('tb.tls.version')}</th>
                <th scope="col" className="py-1.5 pr-3 font-medium">{t('tb.tls.status')}</th>
                <th scope="col" className="py-1.5 pr-3 font-medium">{t('tb.tls.spec')}</th>
                <th scope="col" className="py-1.5 font-medium">{t('tb.tls.basis')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {TLS_VERSIONS.map((row) => (
                <tr key={row.version} className="align-top">
                  <th scope="row" className="whitespace-nowrap py-2 pr-3 text-left font-medium text-fg">{row.version}</th>
                  <td className="py-2 pr-3"><Tag tone={STATUS_TONE[row.status]}>{t(`tb.tls.status.${row.status}` as MessageKey)}</Tag></td>
                  <td className="py-2 pr-3"><Cites items={[row.specification]} /></td>
                  <td className="py-2"><Cites items={row.basis} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <Panel title={t('tb.tls.suites')}>
        <ul className="divide-y divide-line text-sm">
          {TLS_SUITES.map((suite) => (
            <li key={suite.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5">
              <span className="break-all font-mono text-xs text-fg">{suite.name}</span>
              <Tag>{suite.version}</Tag>
              <Cites items={[suite.basis]} />
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-subtle">{t('tb.tls.suitesNote')}</p>
      </Panel>
      <Panel title={t('tb.tls.rules')}>
        <ul className="divide-y divide-line text-sm">
          {TLS_RULES.map((rule) => (
            <li key={rule.id} className="py-2">
              <p className="text-fg">{t(`tb.tls.rule.${rule.id}` as MessageKey)}</p>
              <Cites items={rule.basis} />
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
