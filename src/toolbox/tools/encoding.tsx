import { useEffect, useState } from 'react';
import { useI18n } from '../../app/preferences-context';
import { Segmented } from '../../components/ui';
import type { MessageKey } from '../../i18n';
import { base64Decode, base64Encode, fromHex, hexDump, printableText, toHex, utf8Encode } from '../lib/bytes';
import { HASH_ALGORITHMS, hashBytes, type HashAlgorithm } from '../lib/hash';
import { KeyValues, Message, Output, TextArea } from '../ui';

const MAX_TEXT = 5_000_000;

export function HashTextTool() {
  const { t } = useI18n();
  const [text, setText] = useState('');
  const [hashes, setHashes] = useState<Record<HashAlgorithm, string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    void hashBytes(utf8Encode(text)).then((result) => {
      if (!cancelled) setHashes(result);
    });
    return () => {
      cancelled = true;
    };
  }, [text]);

  return (
    <div className="space-y-4">
      <TextArea label={t('tb.text')} value={text} onChange={setText} maxLength={MAX_TEXT} />
      <p className="text-xs text-subtle">{t('tb.bytes', { n: utf8Encode(text).length })}</p>
      {hashes ? <KeyValues rows={HASH_ALGORITHMS.map((algorithm) => ({ label: algorithm, value: hashes[algorithm], copy: hashes[algorithm] }))} /> : null}
    </div>
  );
}

/** Shows decoded bytes as text when they are printable UTF-8, as a hex dump otherwise. */
function DecodedBytes({ bytes }: { bytes: Uint8Array }) {
  const { t } = useI18n();
  const text = printableText(bytes);
  return (
    <div className="space-y-2">
      <p className="text-xs text-subtle">{t('tb.bytes', { n: bytes.length })}</p>
      {text !== null ? (
        <Output label={t('tb.decodedText')} text={text} />
      ) : (
        <>
          <Message tone="warning">{t('tb.decodedBinary')}</Message>
          <Output label={t('toolbox.output')} text={hexDump(bytes)} />
        </>
      )}
    </div>
  );
}

function invalidMessage(t: (key: MessageKey, params?: Record<string, string | number>) => string, reason: string, position?: number) {
  const text = t('tb.invalidInput', { reason: t(`tb.reason.${reason}` as MessageKey) });
  return position === undefined ? text : `${text} ${t('tb.atPosition', { n: position + 1 })}`;
}

export function Base64Tool() {
  const { t } = useI18n();
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [urlSafe, setUrlSafe] = useState(false);
  const [input, setInput] = useState('');
  const decoded = mode === 'decode' && input.trim() !== '' ? base64Decode(input) : null;

  return (
    <div className="space-y-4">
      <Segmented legend={t('tb.format')} name="base64-mode" value={mode} onChange={setMode} options={[{ value: 'encode', label: t('tb.encode') }, { value: 'decode', label: t('tb.decode') }]} />
      {mode === 'encode' ? (
        <label className="flex items-center gap-2 text-sm text-muted">
          <input type="checkbox" checked={urlSafe} onChange={(event) => setUrlSafe(event.target.checked)} />
          {t('tb.urlSafe')}
        </label>
      ) : null}
      <TextArea label={t('toolbox.input')} value={input} onChange={setInput} maxLength={MAX_TEXT} />
      {mode === 'encode' ? (
        <Output label={t('toolbox.output')} text={base64Encode(utf8Encode(input), urlSafe)} />
      ) : decoded === null ? null : decoded.ok ? (
        <DecodedBytes bytes={decoded.bytes} />
      ) : (
        <Message tone="error">{invalidMessage(t, decoded.reason, decoded.position)}</Message>
      )}
    </div>
  );
}

export function HexTool() {
  const { t } = useI18n();
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [format, setFormat] = useState<'plain' | 'spaced' | 'escaped'>('spaced');
  const [input, setInput] = useState('');
  const bytes = utf8Encode(input);
  const encoded = format === 'plain' ? toHex(bytes) : format === 'spaced' ? toHex(bytes, ' ') : toHex(bytes).replace(/(..)/g, '\\x$1');
  const decoded = mode === 'decode' && input.trim() !== '' ? fromHex(input) : null;

  return (
    <div className="space-y-4">
      <Segmented legend={t('tb.format')} name="hex-mode" value={mode} onChange={setMode} options={[{ value: 'encode', label: t('tb.encode') }, { value: 'decode', label: t('tb.decode') }]} />
      {mode === 'encode' ? (
        <Segmented legend={t('toolbox.output')} name="hex-format" value={format} onChange={setFormat} options={[{ value: 'plain', label: t('tb.hexPlain') }, { value: 'spaced', label: t('tb.hexSpaced') }, { value: 'escaped', label: t('tb.hexEscaped') }]} />
      ) : null}
      <TextArea label={t('toolbox.input')} value={input} onChange={setInput} maxLength={MAX_TEXT} />
      {mode === 'encode' ? (
        <>
          <Output label={t('toolbox.output')} text={encoded} />
          {bytes.length > 0 ? <Output label="Hex dump" text={hexDump(bytes)} /> : null}
        </>
      ) : decoded === null ? null : decoded.ok ? (
        <DecodedBytes bytes={decoded.bytes} />
      ) : (
        <Message tone="error">{invalidMessage(t, decoded.reason, decoded.position)}</Message>
      )}
    </div>
  );
}
