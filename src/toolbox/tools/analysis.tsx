import { useMemo, useState } from 'react';
import { useI18n } from '../../app/preferences-context';
import { ExternalLink, Tag } from '../../components/data';
import { IocExplorer } from '../../components/IocExplorer';
import { Button } from '../../components/ui';
import type { MessageKey } from '../../i18n';
import { analyzeJson, decodeJwt, formatJson, MAX_JSON_CHARS, MAX_JSON_ISSUES } from '../lib/analysis';
import { MAX_REGEX_PATTERN, MAX_REGEX_TEXT, REGEX_FLAGS, runRegex, type RegexResult } from '../lib/regex';
import { analyzeHeaders, analyzePassword, MAX_HEADER_CHARS, MAX_URL_CHARS, parseHeaders, parseUrl } from '../lib/web';
import { KeyValues, Message, Output, TextArea, TextLine } from '../ui';

export function JwtTool() {
  const { t, language } = useI18n();
  const [token, setToken] = useState('');
  const result = token.trim() ? decodeJwt(token) : null;
  return (
    <div className="space-y-4">
      <TextArea label="JWT" value={token} onChange={setToken} maxLength={100_000} rows={4} />
      {result === null ? null : !result.ok ? (
        <Message tone="error">{t('tb.invalidInput', { reason: t(`tb.jwt.reason.${result.reason}` as MessageKey, { n: result.segment ?? 0 }) })}</Message>
      ) : (
        <>
          <p className="flex flex-wrap items-center gap-2">
            <Tag tone="alert">{t('tb.jwt.notVerified')}</Tag>
            <Tag>{result.kind}</Tag>
          </p>
          {result.warnings.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-gold">
              {result.warnings.map((warning) => (
                <li key={warning}>{t(`tb.jwt.warn.${warning}` as MessageKey)}</li>
              ))}
            </ul>
          ) : null}
          <Output label={t('tb.jwt.header')} text={JSON.stringify(result.header, null, 2)} />
          {result.payload ? <Output label={t('tb.jwt.payload')} text={JSON.stringify(result.payload, null, 2)} /> : null}
          {result.times.length > 0 ? (
            <KeyValues
              rows={result.times.map((time) => ({
                label: time.claim,
                value: `${time.value} → ${time.iso ? new Intl.DateTimeFormat(language === 'fr' ? 'fr-FR' : 'en-GB', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(time.iso)) + ' UTC' : '—'}`,
              }))}
            />
          ) : null}
        </>
      )}
    </div>
  );
}

export function JsonTool() {
  const { t } = useI18n();
  const [text, setText] = useState('');
  const [indent, setIndent] = useState<number | null>(2);
  const result = useMemo(() => (text.trim() ? analyzeJson(text) : null), [text]);
  return (
    <div className="space-y-4">
      <TextArea label="JSON" value={text} onChange={setText} maxLength={MAX_JSON_CHARS} rows={10} />
      {result === null ? null : !result.ok ? (
        <Message tone="error">{t('tb.json.invalid', { line: result.line, column: result.column, message: result.message })}</Message>
      ) : (
        <>
          <Message>{t('tb.json.valid', { depth: result.depth })}</Message>
          {result.issues.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-gold">
              {result.issues.map((issue, index) => (
                <li key={`${issue.kind}-${index}`}>{t(`tb.json.issue.${issue.kind}` as MessageKey, { line: issue.line, detail: issue.detail })}</li>
              ))}
            </ul>
          ) : null}
          {result.issues.length >= MAX_JSON_ISSUES ? <Message tone="warning">{t('tb.json.issuesCapped', { n: MAX_JSON_ISSUES })}</Message> : null}
          <div className="flex gap-2">
            <Button onClick={() => setIndent(2)} aria-pressed={indent === 2}>
              {t('tb.json.format')}
            </Button>
            <Button onClick={() => setIndent(null)} aria-pressed={indent === null}>
              {t('tb.json.minify')}
            </Button>
          </div>
          <Output label={t('toolbox.output')} text={formatJson(result.value, indent)} />
        </>
      )}
    </div>
  );
}

export function UrlTool() {
  const { t } = useI18n();
  const [input, setInput] = useState('');
  const parsed = input.trim() ? parseUrl(input) : null;
  return (
    <div className="space-y-4">
      <TextArea label="URL" value={input} onChange={setInput} maxLength={MAX_URL_CHARS} rows={3} />
      {input.trim() === '' ? null : parsed === null ? (
        <Message tone="error">{t('tb.url.invalid')}</Message>
      ) : (
        <>
          {parsed.findings.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-gold">
              {parsed.findings.map((finding) => (
                <li key={finding}>{t(`tb.url.finding.${finding}` as MessageKey)}</li>
              ))}
            </ul>
          ) : null}
          <KeyValues
            rows={[
              { label: 'protocol', value: parsed.protocol },
              { label: 'username', value: parsed.username || '—' },
              { label: 'password', value: parsed.passwordPresent ? t('tb.url.passwordPresent') : '—' },
              { label: 'hostname', value: parsed.hostname || '—', copy: parsed.hostname },
              { label: 'port', value: parsed.port || '—' },
              { label: 'pathname', value: parsed.pathname, copy: parsed.pathname },
              { label: 'search', value: parsed.search || '—' },
              { label: 'hash', value: parsed.hash || '—' },
            ]}
          />
          {parsed.params.length > 0 ? (
            <div className="overflow-x-auto rounded-sm border border-line">
              <table className="w-full text-left text-sm">
                <caption className="px-3 py-2 text-left text-xs font-medium uppercase tracking-wider text-subtle">{t('tb.url.params')}</caption>
                <tbody className="divide-y divide-line">
                  {parsed.params.map((param, index) => (
                    <tr key={`${param.key}-${index}`}>
                      <th scope="row" className="break-all px-3 py-1.5 text-left font-mono text-xs font-normal text-muted">{param.key}</th>
                      <td className="break-all px-3 py-1.5 font-mono text-xs text-fg">{param.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

export function IocTool() {
  return <IocExplorer />;
}

export function RegexTool() {
  const { t } = useI18n();
  const [pattern, setPattern] = useState('');
  const [flags, setFlags] = useState<string[]>(['g']);
  const [text, setText] = useState('');
  const [result, setResult] = useState<RegexResult | null>(null);
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true);
    setResult(await runRegex({ pattern, flags: flags.join(''), text }));
    setRunning(false);
  };

  return (
    <div className="space-y-4">
      <TextLine label={t('tb.regex.pattern')} value={pattern} onChange={setPattern} maxLength={MAX_REGEX_PATTERN} placeholder="(?<user>[\w.]+)@example\.com" />
      <fieldset className="flex flex-wrap items-center gap-3 text-sm">
        <legend className="mb-1 text-xs font-medium uppercase tracking-wider text-subtle">{t('tb.regex.flags')}</legend>
        {REGEX_FLAGS.map((flag) => (
          <label key={flag} className="flex items-center gap-1.5 font-mono text-muted">
            <input type="checkbox" checked={flags.includes(flag)} onChange={(event) => setFlags(event.target.checked ? [...flags, flag] : flags.filter((value) => value !== flag))} />
            {flag}
          </label>
        ))}
      </fieldset>
      <TextArea label={t('tb.text')} value={text} onChange={setText} maxLength={MAX_REGEX_TEXT} rows={8} />
      <Button variant="danger" onClick={() => void run()} disabled={pattern === '' || running}>
        {running ? t('toolbox.processing') : t('tb.regex.run')}
      </Button>
      {result === null ? null : result.status === 'timeout' ? (
        <Message tone="error">{t('tb.regex.timeout')}</Message>
      ) : result.status === 'invalid' ? (
        <Message tone="error">{t('tb.regex.invalid', { message: result.message })}</Message>
      ) : result.status === 'unavailable' ? (
        <Message tone="error">{t('tb.regex.unavailable')}</Message>
      ) : (
        <>
          <Message>{t('tb.regex.matches', { n: result.matches.length, ms: result.elapsedMs.toFixed(1) })}</Message>
          {result.truncated ? <Message tone="warning">{t('tb.regex.truncated')}</Message> : null}
          {result.matches.length > 0 ? (
            <div className="max-h-96 overflow-auto rounded-sm border border-line">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-surface text-xs uppercase tracking-wider text-subtle">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">{t('tb.regex.index')}</th>
                    <th scope="col" className="px-3 py-2 font-medium">{t('tb.regex.match')}</th>
                    <th scope="col" className="px-3 py-2 font-medium">{t('tb.regex.groups')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line font-mono text-xs">
                  {result.matches.map((match, index) => (
                    <tr key={`${match.index}-${index}`} className="align-top">
                      <td className="px-3 py-1.5 text-muted">{match.index}</td>
                      <td className="break-all px-3 py-1.5 text-fg">{match.value}</td>
                      <td className="break-all px-3 py-1.5 text-muted">
                        {[...match.groups.map((group, groupIndex) => `$${groupIndex + 1}=${group ?? '∅'}`), ...Object.entries(match.named).map(([name, value]) => `${name}=${value ?? '∅'}`)].join('  ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

const STATE_TONES = { present: 'gold', absent: 'alert', weak: 'alert', info: 'neutral' } as const;

export function HeadersTool() {
  const { t } = useI18n();
  const [raw, setRaw] = useState('');
  const parsed = useMemo(() => parseHeaders(raw), [raw]);
  const checks = useMemo(() => analyzeHeaders(parsed.headers), [parsed]);
  return (
    <div className="space-y-4">
      <TextArea label={t('tb.headers.input')} value={raw} onChange={setRaw} maxLength={MAX_HEADER_CHARS} rows={10} placeholder={'HTTP/1.1 200 OK\nContent-Type: text/html\nStrict-Transport-Security: max-age=31536000'} />
      {raw.trim() === '' ? null : parsed.headers.length === 0 ? (
        <Message tone="warning">{t('tb.headers.none')}</Message>
      ) : (
        <>
          {parsed.status ? <p className="font-mono text-xs text-muted">{t('tb.headers.status')}: {parsed.status}</p> : null}
          <ul className="divide-y divide-line rounded-sm border border-line bg-surface">
            {checks.map((check) => (
              <li key={check.id} className="px-3 py-2.5 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-fg">{t(`tb.headers.name.${check.id}` as MessageKey)}</span>
                  <Tag tone={STATE_TONES[check.state]}>{t(`tb.headers.state.${check.state}` as MessageKey)}</Tag>
                  <ExternalLink href={check.reference.url} className="text-xs">{check.reference.label}</ExternalLink>
                </div>
                {check.values.map((value, index) => (
                  <p key={index} className="mt-1 break-all font-mono text-xs text-muted">{value}</p>
                ))}
                {check.notes.length > 0 ? (
                  <ul className="mt-1 list-disc pl-5 text-xs text-gold">
                    {check.notes.map((note) => {
                      const [key, name] = note.split(':');
                      return <li key={note}>{t(`tb.headers.note.${key}` as MessageKey, { name: name ?? '' })}</li>;
                    })}
                  </ul>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export function PasswordTool() {
  const { t } = useI18n();
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const analysis = password ? analyzePassword(password) : null;
  return (
    <div className="space-y-4">
      <TextLine label={t('tb.password.input')} value={password} onChange={setPassword} maxLength={256} type={visible ? 'text' : 'password'} />
      <label className="flex items-center gap-2 text-sm text-muted">
        <input type="checkbox" checked={visible} onChange={(event) => setVisible(event.target.checked)} />
        {t('tb.password.show')}
      </label>
      {analysis ? (
        <div className="space-y-3">
          <p>
            <Tag tone={analysis.verdict === 'weak' ? 'alert' : 'gold'}>{t(`tb.password.verdict.${analysis.verdict}` as MessageKey)}</Tag>
          </p>
          {analysis.findings.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-gold">
              {analysis.findings.map((finding) => (
                <li key={finding}>{t(`tb.password.finding.${finding}` as MessageKey)}</li>
              ))}
            </ul>
          ) : null}
          <p className="text-sm text-muted">{t('tb.password.length', { n: analysis.length })}</p>
          <p className="text-sm text-muted">{t('tb.password.bits', { bits: Math.round(analysis.upperBoundBits) })}</p>
          <p className="text-xs text-subtle">{t('tb.password.advice')}</p>
        </div>
      ) : null}
    </div>
  );
}
