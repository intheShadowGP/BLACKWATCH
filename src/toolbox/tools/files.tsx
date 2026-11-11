import { useRef, useState } from 'react';
import { useI18n } from '../../app/preferences-context';
import { ExternalLink, Tag } from '../../components/data';
import { formatDateTime } from '../../lib/format';
import { shannonEntropy } from '../lib/analysis';
import { utf8Encode } from '../lib/bytes';
import { analyzeFile, type FileAnalysisResult } from '../lib/file';
import { HASH_ALGORITHMS } from '../lib/hash';
import { FILE_SIGNATURES } from '../lib/reference';
import { FilePicker, formatBytes, KeyValues, Message, Output, TextArea } from '../ui';

interface Selected {
  name: string;
  type: string;
  lastModified: number;
}

function useFileAnalysis() {
  const [selected, setSelected] = useState<Selected | null>(null);
  const [result, setResult] = useState<FileAnalysisResult | 'pending' | null>(null);
  // Each pick gets a sequence number; a result that arrives after a newer pick is discarded,
  // so the hashes of one file can never be shown under the name of another.
  const sequence = useRef(0);
  const pick = (file: File) => {
    sequence.current += 1;
    const current = sequence.current;
    // Only metadata is kept in state; the file name is displayed as text.
    setSelected({ name: file.name.slice(0, 255), type: file.type, lastModified: file.lastModified });
    setResult('pending');
    void analyzeFile(file).then((analysis) => {
      if (current === sequence.current) setResult(analysis);
    });
  };
  return { selected, result, pick };
}

function AnalysisState({ result }: { result: FileAnalysisResult | 'pending' | null }) {
  const { t } = useI18n();
  if (result === 'pending') return <Message>{t('toolbox.processing')}</Message>;
  if (result?.status === 'tooLarge') return <Message tone="error">{t('toolbox.fileTooLarge', { max: '512 MB' })}</Message>;
  if (result?.status === 'error') return <Message tone="error">{t('toolbox.fileError')}</Message>;
  return null;
}

export function HashFileTool() {
  const { t, language } = useI18n();
  const { selected, result, pick } = useFileAnalysis();
  return (
    <div className="space-y-4">
      <FilePicker onFile={pick} />
      <AnalysisState result={result} />
      {selected && result !== null && result !== 'pending' && result.status === 'ok' ? (
        <>
          <p className="break-all text-sm text-muted">
            {selected.name} · {formatBytes(result.report.size, language)}
          </p>
          <KeyValues rows={HASH_ALGORITHMS.map((algorithm) => ({ label: algorithm, value: result.report.hashes[algorithm], copy: result.report.hashes[algorithm] }))} />
          <p className="text-xs text-subtle">{t('toolbox.local')}</p>
        </>
      ) : null}
    </div>
  );
}

function Profile({ profile }: { profile: number[] }) {
  const { t } = useI18n();
  if (profile.length < 2) return null;
  return (
    <div>
      <p className="mb-1 text-xs font-medium uppercase tracking-wider text-subtle">{t('tb.profile')}</p>
      <svg viewBox={`0 0 ${profile.length} 8`} preserveAspectRatio="none" className="block h-16 w-full rounded-sm border border-line bg-surface" role="img" aria-label={t('tb.profile')}>
        {profile.map((value, index) => (
          <rect key={index} x={index} y={8 - value} width={1} height={value} className={value > 7.2 ? 'fill-accent-fill' : 'fill-gold'} />
        ))}
      </svg>
    </div>
  );
}

export function EntropyTool() {
  const { t, language } = useI18n();
  const [text, setText] = useState('');
  const { selected, result, pick } = useFileAnalysis();
  const textEntropy = text ? shannonEntropy(utf8Encode(text)) : null;
  return (
    <div className="space-y-4">
      <TextArea label={t('tb.text')} value={text} onChange={setText} maxLength={5_000_000} />
      {textEntropy ? (
        <KeyValues
          rows={[
            { label: t('tb.file.entropy'), value: t('tb.entropyValue', { value: textEntropy.bitsPerByte.toFixed(4) }) },
            { label: t('tb.length'), value: t('tb.bytes', { n: textEntropy.length }) },
            { label: t('tb.distinctLabel'), value: String(textEntropy.distinctBytes) },
          ]}
        />
      ) : null}
      <div className="border-t border-line pt-4">
        <FilePicker onFile={pick} />
      </div>
      <AnalysisState result={result} />
      {selected && result !== null && result !== 'pending' && result.status === 'ok' ? (
        <>
          <KeyValues
            rows={[
              { label: t('tb.file.name'), value: selected.name },
              { label: t('tb.file.size'), value: formatBytes(result.report.size, language) },
              { label: t('tb.file.entropy'), value: t('tb.entropyValue', { value: result.report.entropy.toFixed(4) }) },
              { label: t('tb.distinctLabel'), value: String(result.report.distinctBytes) },
            ]}
          />
          <Profile profile={result.report.profile} />
        </>
      ) : null}
    </div>
  );
}

export function FileMetaTool() {
  const { t, language } = useI18n();
  const { selected, result, pick } = useFileAnalysis();
  const report = result !== null && result !== 'pending' && result.status === 'ok' ? result.report : null;
  const signatures = report ? FILE_SIGNATURES.filter((signature) => report.signatures.includes(signature.id)) : [];
  // Every dot-separated suffix counts, so versioned names such as libssl.so.3 match "so".
  const suffixes = selected ? selected.name.toLowerCase().split('.').slice(1) : [];
  const extensions = suffixes.length === 0 ? [''] : suffixes;
  const mismatch = signatures.length > 0 && !signatures.some((signature) => signature.extensions.some((known) => extensions.includes(known)));

  return (
    <div className="space-y-4">
      <FilePicker onFile={pick} />
      <AnalysisState result={result} />
      {selected && report ? (
        <>
          <KeyValues
            rows={[
              { label: t('tb.file.name'), value: selected.name },
              { label: t('tb.file.size'), value: `${formatBytes(report.size, language)} (${report.size})` },
              { label: t('tb.file.declaredType'), value: selected.type || t('tb.unknown') },
              {
                label: t('tb.file.detectedType'),
                value: signatures.length > 0 ? signatures.map((signature) => signature.label).join(' / ') : t('tb.file.unknownType'),
              },
              { label: t('tb.file.modified'), value: formatDateTime(new Date(selected.lastModified).toISOString(), language) },
              { label: t('tb.file.entropy'), value: t('tb.entropyValue', { value: report.entropy.toFixed(4) }) },
            ]}
          />
          {mismatch ? (
            <p>
              <Tag tone="alert">{t('tb.file.mismatch')}</Tag>
            </p>
          ) : null}
          {signatures.map((signature) => (
            <p key={signature.id} className="text-xs text-subtle">
              {signature.label}: <ExternalLink href={signature.reference.url}>{signature.reference.label}</ExternalLink>
              {signature.ambiguousWith ? ` · ${t('tb.file.ambiguous', { other: signature.ambiguousWith })}` : ''}
            </p>
          ))}
          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wider text-subtle">{t('tb.file.hashes')}</p>
            <KeyValues rows={HASH_ALGORITHMS.map((algorithm) => ({ label: algorithm, value: report.hashes[algorithm], copy: report.hashes[algorithm] }))} />
          </div>
          <Profile profile={report.profile} />
          <Output label={t('tb.file.head')} text={report.headDump} />
        </>
      ) : null}
    </div>
  );
}
