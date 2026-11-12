import { useId, useMemo, useState } from 'react';
import { useI18n } from '../app/preferences-context';
import type { MessageKey } from '../i18n';
import { downloadText, fileStamp, toCsv } from '../lib/export';
import { IOC_TYPES, MAX_IOC_INPUT_CHARS, defang, extractIocs, type ExtractionResult, type IocType } from '../lib/ioc';
import { TLD_SNAPSHOT } from '../lib/tlds';
import { EmptyState, Pagination, SelectField, TableScroll, paginate } from './data';
import { Button, Panel } from './ui';

const MAX_FILE_BYTES = 5 * 1024 * 1024;

export function IocExplorer() {
  const { t } = useI18n();
  const inputId = useId();
  const fileId = useId();
  const [input, setInput] = useState('');
  const [origin, setOrigin] = useState<string | null>(null);
  const [result, setResult] = useState<ExtractionResult | null>(null);
  const [type, setType] = useState<'all' | IocType>('all');
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const analyse = (text: string) => {
    setResult(extractIocs(text));
    setType('all');
    setPage(1);
  };

  const onFile = async (file: File | undefined) => {
    setError(null);
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError(t('intel.ioc.fileTooLarge', { max: '5' }));
      return;
    }
    try {
      const text = await file.text();
      // The file name is only displayed, as text; it is never used as a path.
      setOrigin(file.name.slice(0, 120));
      setInput(text.slice(0, MAX_IOC_INPUT_CHARS));
      analyse(text);
    } catch {
      setError(t('intel.ioc.fileUnreadable'));
    }
  };

  const counts = useMemo(() => {
    const map = new Map<IocType, number>();
    for (const ioc of result?.iocs ?? []) map.set(ioc.type, (map.get(ioc.type) ?? 0) + 1);
    return map;
  }, [result]);
  const visible = useMemo(() => (result?.iocs ?? []).filter((ioc) => type === 'all' || ioc.type === type), [result, type]);
  const { slice, pageCount, page: current } = paginate(visible, page, 50);
  const sourceLabel = origin ?? t('intel.ioc.pasted');

  const exportCsv = () =>
    downloadText(
      `blackwatch-iocs-${fileStamp()}.csv`,
      toCsv(['type', 'value', 'defanged', 'address_class', 'occurrences', 'source'], visible.map((ioc) => [ioc.type, ioc.value, defang(ioc), ioc.addressClass ?? '', ioc.count, sourceLabel])),
      'text/csv;charset=utf-8',
    );
  const exportJson = () =>
    downloadText(
      `blackwatch-iocs-${fileStamp()}.json`,
      JSON.stringify({ generatedAt: new Date().toISOString(), source: sourceLabel, truncated: result?.truncated ?? false, indicators: visible }, null, 2),
      'application/json',
    );

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <label htmlFor={inputId} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
          {t('intel.ioc.input')}
        </label>
        <textarea
          id={inputId}
          value={input}
          onChange={(event) => { setInput(event.target.value); setOrigin(null); }}
          maxLength={MAX_IOC_INPUT_CHARS}
          rows={8}
          spellCheck={false}
          placeholder={t('intel.ioc.placeholder')}
          className="w-full rounded-sm border border-line-strong bg-bg p-2.5 font-mono text-xs text-fg placeholder:text-subtle"
        />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button variant="danger" onClick={() => analyse(input)} disabled={input.trim() === ''}>
            {t('intel.ioc.extract')}
          </Button>
          <label htmlFor={fileId} className="inline-flex min-h-9 cursor-pointer items-center rounded-sm border border-line-strong bg-raised px-3 text-sm font-medium text-fg hover:border-subtle has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-gold">
            {t('intel.ioc.importFile')}
            <input id={fileId} type="file" accept=".txt,.log,.csv,.json,.eml,.md,text/*" className="sr-only" onChange={(event) => { void onFile(event.target.files?.[0]); event.target.value = ''; }} />
          </label>
          <Button variant="ghost" onClick={() => { setInput(''); setResult(null); setOrigin(null); setError(null); }} disabled={input === '' && !result}>
            {t('common.clear')}
          </Button>
        </div>
        {error ? <p role="alert" className="mt-2 text-sm text-accent">{error}</p> : null}

        {result ? (
          <div className="mt-5">
            <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
              <p role="status" className="text-sm text-muted">
                {t('intel.ioc.found', { n: result.iocs.length })} · {t('intel.ioc.source', { source: sourceLabel })}
              </p>
              <div className="flex gap-2">
                <Button onClick={exportCsv} disabled={visible.length === 0}>{t('common.exportCsv')}</Button>
                <Button onClick={exportJson} disabled={visible.length === 0}>{t('common.exportJson')}</Button>
              </div>
            </div>
            {result.truncated ? <p className="mb-3 text-sm text-gold">{t('intel.ioc.truncated')}</p> : null}
            <SelectField
              className="mb-3 max-w-xs"
              label={t('intel.ioc.type')}
              value={type}
              onChange={(value) => { setType(value); setPage(1); }}
              options={[
                { value: 'all', label: `${t('common.all')} (${result.iocs.length})` },
                ...IOC_TYPES.filter((item) => counts.has(item)).map((item) => ({ value: item, label: `${t(`ioc.type.${item}`)} (${counts.get(item)})` })),
              ]}
            />
            {visible.length === 0 ? (
              <EmptyState>{t('intel.ioc.none')}</EmptyState>
            ) : (
              <TableScroll label={t('common.resultsTable')} className="rounded-sm border border-line">
                <table className="w-full text-left text-sm">
                  <thead className="bg-surface text-xs uppercase tracking-wider text-subtle">
                    <tr>
                      <th scope="col" className="px-3 py-2 font-medium">{t('intel.ioc.type')}</th>
                      <th scope="col" className="px-3 py-2 font-medium">{t('intel.ioc.value')}</th>
                      <th scope="col" className="hidden px-3 py-2 font-medium sm:table-cell">{t('intel.ioc.class')}</th>
                      <th scope="col" className="px-3 py-2 text-right font-medium">{t('intel.ioc.count')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {slice.map((ioc) => (
                      <tr key={`${ioc.type}|${ioc.value}`} className="align-top">
                        <td className="whitespace-nowrap px-3 py-1.5 text-muted">{t(`ioc.type.${ioc.type}`)}</td>
                        <td className="break-all px-3 py-1.5 font-mono text-xs text-fg">{defang(ioc)}</td>
                        <td className="hidden whitespace-nowrap px-3 py-1.5 text-muted sm:table-cell">
                          {ioc.addressClass ? t(`ioc.class.${ioc.addressClass}` as MessageKey) : '—'}
                        </td>
                        <td className="px-3 py-1.5 text-right font-mono text-muted">{ioc.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
            )}
            <Pagination page={current} pageCount={pageCount} onChange={setPage} />
            <p className="mt-3 text-xs text-subtle">{t('intel.ioc.defangNote')}</p>
          </div>
        ) : null}
      </div>

      <Panel title={t('intel.ioc.limits.title')} className="self-start">
        <ul className="list-disc space-y-2 pl-4 text-sm text-muted">
          <li>{t('intel.ioc.limits.local')}</li>
          <li>{t('intel.ioc.limits.pattern')}</li>
          <li>{t('intel.ioc.limits.domains', { snapshot: TLD_SNAPSHOT })}</li>
          <li>{t('intel.ioc.limits.reputation')}</li>
          <li>{t('intel.ioc.limits.size', { chars: '2,000,000', mb: '5' })}</li>
        </ul>
      </Panel>
    </div>
  );
}

