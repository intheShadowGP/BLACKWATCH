import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useI18n } from '../../app/preferences-context';
import { Tag } from '../../components/data';
import { Button, Panel } from '../../components/ui';
import { MAX_RULE_CHARS, parseSigma, parseYara, type SigmaParseResult, type YaraParseResult } from '../lib/rules';
import { Message, Output, TextArea } from '../ui';

function ParseError({ message, line, source }: { message: string; line: number | null; source: string }) {
  const { t } = useI18n();
  return (
    <div className="space-y-3">
      <Message tone="error">{line === null ? t('tb.rules.errorNoLine', { message }) : t('tb.rules.error', { line, message })}</Message>
      <Output label={t('tb.rules.raw')} text={source} />
    </div>
  );
}

export function YaraTool() {
  const { t } = useI18n();
  const [source, setSource] = useState('');
  const [result, setResult] = useState<YaraParseResult | null>(null);
  return (
    <div className="space-y-4">
      <TextArea label={t('tb.rules.input')} value={source} onChange={setSource} maxLength={MAX_RULE_CHARS} rows={12} />
      <Button variant="danger" onClick={() => setResult(parseYara(source))} disabled={source.trim() === ''}>
        {t('tb.rules.parse')}
      </Button>
      {result === null ? null : !result.ok ? (
        <ParseError message={result.message} line={result.line} source={source} />
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-muted">{t('tb.rules.count', { n: result.rules.length })}{result.imports.length > 0 ? ` · ${t('tb.yara.imports')}: ${result.imports.join(', ')}` : ''}</p>
          {result.rules.map((rule) => (
            <Panel key={`${rule.name}-${rule.line}`} title={rule.name}>
              <div className="space-y-3 text-sm">
                <p className="flex flex-wrap items-center gap-2 text-xs text-subtle">
                  {t('tb.yara.line', { n: rule.line })}
                  {rule.modifiers.map((modifier) => <Tag key={modifier}>{modifier}</Tag>)}
                  {rule.tags.map((tag) => <Tag key={tag} tone="gold">{tag}</Tag>)}
                </p>
                {rule.meta.length > 0 ? (
                  <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1">
                    {rule.meta.map((entry, index) => (
                      <div key={`${entry.key}-${index}`} className="contents">
                        <dt className="font-mono text-xs text-muted">{entry.key}</dt>
                        <dd className="break-all text-xs text-fg">{entry.value}</dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
                {rule.strings.length > 0 ? (
                  <div>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.yara.strings')}</h3>
                    <ul className="space-y-1 font-mono text-xs">
                      {rule.strings.map((entry) => (
                        <li key={entry.identifier} className="break-all">
                          <span className="text-accent">{entry.identifier}</span> <span className="text-subtle">[{entry.kind}]</span> <span className="text-fg">{entry.value}</span>{' '}
                          <span className="text-gold">{entry.modifiers.join(' ')}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                <div>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.yara.condition')}</h3>
                  <p className="break-all font-mono text-xs text-fg">{rule.condition}</p>
                </div>
              </div>
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}

export function SigmaTool() {
  const { t } = useI18n();
  const [source, setSource] = useState('');
  const [result, setResult] = useState<SigmaParseResult | null>(null);
  return (
    <div className="space-y-4">
      <TextArea label={t('tb.rules.input')} value={source} onChange={setSource} maxLength={MAX_RULE_CHARS} rows={12} />
      <Button variant="danger" onClick={() => void parseSigma(source).then(setResult)} disabled={source.trim() === ''}>
        {t('tb.rules.parse')}
      </Button>
      {result === null ? null : !result.ok ? (
        <ParseError message={result.message} line={result.line} source={source} />
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-muted">{t('tb.rules.count', { n: result.rules.length })}</p>
          {result.rules.map((rule, index) => (
            <Panel key={`${rule.id ?? rule.title}-${index}`} title={rule.title}>
              <div className="space-y-3 text-sm">
                <p className="flex flex-wrap gap-2">
                  {rule.status ? <Tag>{rule.status}</Tag> : null}
                  {rule.level ? <Tag tone={rule.level === 'critical' || rule.level === 'high' ? 'alert' : 'neutral'}>{rule.level}</Tag> : null}
                  {rule.id ? <span className="font-mono text-xs text-subtle">{rule.id}</span> : null}
                </p>
                {rule.description ? <p className="text-muted">{rule.description}</p> : null}
                {rule.author || rule.date ? <p className="text-xs text-subtle">{[rule.author, rule.date].filter(Boolean).join(' · ')}</p> : null}
                <div>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.sigma.logsource')}</h3>
                  <p className="font-mono text-xs text-fg">{Object.entries(rule.logsource).map(([key, value]) => `${key}: ${value}`).join(' · ') || '—'}</p>
                </div>
                <div>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.sigma.detection')}</h3>
                  <div className="space-y-2">
                    {rule.detection.map((block) => (
                      <div key={block.name}>
                        <p className="font-mono text-xs text-accent">{block.name}</p>
                        <pre tabIndex={0} className="overflow-auto whitespace-pre-wrap break-all rounded-sm border border-line bg-bg p-2 font-mono text-xs text-fg">{block.body}</pre>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.sigma.condition')}</h3>
                  <p className="font-mono text-xs text-fg">{rule.condition.join(' | ') || '—'}</p>
                </div>
                {rule.techniques.length > 0 ? (
                  <div>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.sigma.techniques')}</h3>
                    <p className="flex flex-wrap gap-2">
                      {rule.techniques.map((technique) => (
                        <Link key={technique} to={`/attack/${technique}`} className="font-mono text-xs text-accent hover:underline">{technique}</Link>
                      ))}
                    </p>
                  </div>
                ) : null}
                {rule.tags.length > 0 ? <p className="flex flex-wrap gap-1.5">{rule.tags.map((tag) => <Tag key={tag}>{tag}</Tag>)}</p> : null}
                {rule.falsepositives.length > 0 ? (
                  <div>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.sigma.falsepositives')}</h3>
                    <ul className="list-disc pl-5 text-muted">{rule.falsepositives.map((item) => <li key={item}>{item}</li>)}</ul>
                  </div>
                ) : null}
                {rule.references.length > 0 ? (
                  <div>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-subtle">{t('tb.sigma.references')}</h3>
                    {/* References come from pasted, untrusted rules: shown as text, never as live links. */}
                    <ul className="space-y-1 break-all font-mono text-xs text-muted">
                      {rule.references.map((reference) => (
                        <li key={reference}>{reference}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}
