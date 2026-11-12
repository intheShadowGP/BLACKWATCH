import { useEffect, useMemo, useState } from 'react';
import { useI18n } from '../../app/preferences-context';
import { EmptyState, SelectField, TableScroll } from '../../components/data';
import type { MessageKey } from '../../i18n';
import { formatDate, formatNumber } from '../../lib/format';
import { ipv4Info, ipv4Subnet, ipv6Info, splitSubnet } from '../lib/net';
import { KeyValues, Message, TextLine } from '../ui';

export function Ipv4Tool() {
  const { t } = useI18n();
  const [input, setInput] = useState('');
  const info = input.trim() ? ipv4Info(input) : null;
  return (
    <div className="space-y-4">
      <TextLine label={t('tb.net.address')} value={input} onChange={setInput} maxLength={64} placeholder="192.168.1.10" />
      {input.trim() === '' ? null : info === null ? (
        <Message tone="error">{t('tb.net.invalid')}</Message>
      ) : (
        <KeyValues
          rows={[
            { label: t('tb.net.class'), value: t(`ioc.class.${info.addressClass}` as MessageKey) },
            { label: t('tb.net.integer'), value: String(info.integer), copy: String(info.integer) },
            { label: t('tb.net.hex'), value: info.hex, copy: info.hex },
            { label: t('tb.net.binary'), value: info.binary, copy: info.binary },
            { label: t('tb.net.octal'), value: info.octal },
            { label: t('tb.net.reverse'), value: info.reverseDns, copy: info.reverseDns },
          ]}
        />
      )}
    </div>
  );
}

export function Ipv6Tool() {
  const { t } = useI18n();
  const [input, setInput] = useState('');
  const info = input.trim() ? ipv6Info(input) : null;
  return (
    <div className="space-y-4">
      <TextLine label={t('tb.net.address')} value={input} onChange={setInput} maxLength={64} placeholder="2001:db8::1/64" />
      {input.trim() === '' ? null : info === null ? (
        <Message tone="error">{t('tb.net.invalid')}</Message>
      ) : (
        <KeyValues
          rows={[
            { label: t('tb.net.compressed'), value: info.compressed, copy: info.compressed },
            { label: t('tb.net.expanded'), value: info.expanded, copy: info.expanded },
            { label: t('tb.net.class'), value: t(`ioc.class.${info.addressClass}` as MessageKey) },
            ...(info.mappedIpv4 ? [{ label: t('tb.net.mapped'), value: info.mappedIpv4 }] : []),
            ...(info.network
              ? [
                  { label: t('tb.net.network'), value: `${info.network}/${info.prefix}`, copy: `${info.network}/${info.prefix}` },
                  { label: t('tb.net.lastAddress'), value: info.lastAddress ?? '' },
                  { label: t('tb.net.size'), value: info.size ?? '' },
                ]
              : []),
            { label: t('tb.net.reverse'), value: info.reverseDns, copy: info.reverseDns },
          ]}
        />
      )}
    </div>
  );
}

export function CidrTool() {
  const { t, language } = useI18n();
  const [input, setInput] = useState('');
  const [split, setSplit] = useState('');
  const subnet = input.trim() ? ipv4Subnet(input) : null;
  const children = subnet && split ? splitSubnet(subnet, Number(split)) : null;
  const n = (value: number) => formatNumber(value, language);
  return (
    <div className="space-y-4">
      <TextLine label={t('tb.net.block')} value={input} onChange={setInput} maxLength={64} placeholder="192.168.1.0/24" />
      {input.trim() === '' ? null : subnet === null ? (
        <Message tone="error">{t('tb.net.invalid')}</Message>
      ) : (
        <>
          {subnet.hostBitsSet ? <Message tone="warning">{t('tb.net.hostBits', { network: subnet.network })}</Message> : null}
          <KeyValues
            rows={[
              { label: t('tb.net.network'), value: `${subnet.network}/${subnet.prefix}`, copy: `${subnet.network}/${subnet.prefix}` },
              { label: t('tb.net.broadcast'), value: subnet.broadcast },
              { label: t('tb.net.mask'), value: subnet.mask, copy: subnet.mask },
              { label: t('tb.net.wildcard'), value: subnet.wildcard, copy: subnet.wildcard },
              { label: t('tb.net.firstHost'), value: subnet.firstHost },
              { label: t('tb.net.lastHost'), value: subnet.lastHost },
              { label: t('tb.net.total'), value: n(subnet.total) },
              { label: t('tb.net.usable'), value: n(subnet.usable) },
              { label: t('tb.net.class'), value: t(`ioc.class.${subnet.addressClass}` as MessageKey) },
            ]}
          />
          {subnet.prefix < 32 ? (
            <SelectField
              className="max-w-xs"
              label={t('tb.net.split', { prefix: '…' })}
              value={split}
              onChange={setSplit}
              options={[{ value: '', label: '—' }, ...Array.from({ length: Math.min(32 - subnet.prefix, 16) }, (_, index) => String(subnet.prefix + index + 1)).map((value) => ({ value, label: t('tb.net.split', { prefix: value }) }))]}
            />
          ) : null}
          {children ? (
            <ol className="max-h-80 overflow-auto rounded-sm border border-line bg-surface p-3 font-mono text-xs text-fg">
              {children.map((child) => (
                <li key={child.network}>
                  {child.network}/{split} — {child.broadcast}
                </li>
              ))}
            </ol>
          ) : null}
        </>
      )}
    </div>
  );
}

interface PortReference {
  registry: string;
  licence: string;
  licenceUrl: string;
  retrievedAt: string;
  entries: [number, string, string, string][];
}

export function PortsTool() {
  const { t, language } = useI18n();
  const [data, setData] = useState<PortReference | 'error' | null>(null);
  const [query, setQuery] = useState('');

  useEffect(() => {
    let cancelled = false;
    fetch(new URL('reference/iana-ports.json', document.baseURI), { credentials: 'omit' })
      .then((response) => (response.ok ? (response.json() as Promise<PortReference>) : Promise.reject(new Error(String(response.status)))))
      .then((body) => {
        if (!cancelled) setData(Array.isArray(body.entries) ? body : 'error');
      })
      .catch(() => {
        if (!cancelled) setData('error');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const matches = useMemo(() => {
    if (!data || data === 'error') return [];
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    const port = /^\d{1,5}$/.test(needle) ? Number(needle) : null;
    return data.entries
      .filter((entry) => (port !== null ? entry[0] === port : entry[2].toLowerCase().includes(needle) || entry[3].toLowerCase().includes(needle)))
      .slice(0, 200);
  }, [data, query]);

  if (data === null) return <Message>{t('app.loading')}</Message>;
  if (data === 'error') return <Message tone="error">{t('data.error.network')}</Message>;

  return (
    <div className="space-y-4">
      <TextLine label={t('tb.ports.search')} value={query} onChange={setQuery} maxLength={64} placeholder="3389, ssh, ldap…" />
      {query.trim() === '' ? null : matches.length === 0 ? (
        <EmptyState>{t('common.noResults')}</EmptyState>
      ) : (
        <>
          <p className="text-xs text-subtle">{t('tb.ports.count', { n: matches.length })}</p>
          <TableScroll label={t('common.resultsTable')} className="rounded-sm border border-line">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface text-xs uppercase tracking-wider text-subtle">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">{t('tb.ports.port')}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{t('tb.ports.proto')}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{t('tb.ports.service')}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{t('tb.ports.description')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {matches.map(([port, proto, service, description]) => (
                  <tr key={`${port}-${proto}-${service}`}>
                    <td className="px-3 py-1.5 font-mono text-fg">{port}</td>
                    <td className="px-3 py-1.5 text-muted">{proto}</td>
                    <td className="px-3 py-1.5 font-mono text-fg">{service}</td>
                    <td className="px-3 py-1.5 text-muted">{description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        </>
      )}
      <p className="text-xs text-subtle">{t('tb.ports.source', { registry: data.registry, date: formatDate(data.retrievedAt, language), licence: data.licence })}</p>
    </div>
  );
}
