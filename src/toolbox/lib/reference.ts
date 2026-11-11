// Authored reference data. Every row cites the document that defines it.

export interface Citation {
  label: string;
  url: string;
}

const rfc = (number: number, section?: string): Citation => ({
  label: section ? `RFC ${number} §${section}` : `RFC ${number}`,
  url: `https://www.rfc-editor.org/rfc/rfc${number}${section ? `#section-${section}` : ''}`,
});

// ── TLS ─────────────────────────────────────────────────────────────────────

export type TlsStatus = 'prohibited' | 'deprecated' | 'required' | 'recommended';

export interface TlsVersionRow {
  version: string;
  specification: Citation;
  status: TlsStatus;
  /** Documents establishing the status. */
  basis: Citation[];
}

/** Protocol versions and their status under BCP 195 (RFC 9325, November 2022). */
export const TLS_VERSIONS: readonly TlsVersionRow[] = [
  { version: 'SSL 2.0', specification: { label: 'Netscape, 1995 (see RFC 6176)', url: 'https://www.rfc-editor.org/rfc/rfc6176' }, status: 'prohibited', basis: [rfc(6176), rfc(9325, '3.1.1')] },
  { version: 'SSL 3.0', specification: rfc(6101), status: 'prohibited', basis: [rfc(7568), rfc(9325, '3.1.1')] },
  { version: 'TLS 1.0', specification: rfc(2246), status: 'deprecated', basis: [rfc(8996), rfc(9325, '3.1.1')] },
  { version: 'TLS 1.1', specification: rfc(4346), status: 'deprecated', basis: [rfc(8996), rfc(9325, '3.1.1')] },
  { version: 'TLS 1.2', specification: rfc(5246), status: 'required', basis: [rfc(9325, '3.1.1')] },
  { version: 'TLS 1.3', specification: rfc(8446), status: 'recommended', basis: [rfc(9325, '3.1.1')] },
];

export interface TlsSuiteRow {
  name: string;
  version: 'TLS 1.2' | 'TLS 1.3';
  basis: Citation;
}

export const TLS_SUITES: readonly TlsSuiteRow[] = [
  { name: 'TLS_AES_128_GCM_SHA256', version: 'TLS 1.3', basis: rfc(8446, '9.1') },
  { name: 'TLS_AES_256_GCM_SHA384', version: 'TLS 1.3', basis: rfc(8446, '9.1') },
  { name: 'TLS_CHACHA20_POLY1305_SHA256', version: 'TLS 1.3', basis: rfc(8446, '9.1') },
  { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', version: 'TLS 1.2', basis: rfc(9325, '4.2') },
  { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', version: 'TLS 1.2', basis: rfc(9325, '4.2') },
  { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', version: 'TLS 1.2', basis: rfc(9325, '4.2') },
  { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', version: 'TLS 1.2', basis: rfc(9325, '4.2') },
];

/** Requirements from BCP 195, keyed for translation. */
export const TLS_RULES: readonly { id: string; basis: Citation[] }[] = [
  { id: 'noNull', basis: [rfc(9325, '4.1')] },
  { id: 'noRc4', basis: [rfc(7465), rfc(9325, '4.1')] },
  { id: 'min112', basis: [rfc(9325, '4.1')] },
  { id: 'prefer128', basis: [rfc(9325, '4.1')] },
  { id: 'ems', basis: [rfc(7627), rfc(9325, '3.5')] },
  { id: 'renegotiation', basis: [rfc(5746), rfc(9325, '3.5')] },
  { id: 'sni', basis: [rfc(6066, '3'), rfc(9325, '3.7')] },
  { id: 'alpn', basis: [rfc(7301), rfc(9325, '3.8')] },
  { id: 'tickets', basis: [rfc(9325, '3.4')] },
  { id: 'hsts', basis: [rfc(6797)] },
];

// ── File signatures ─────────────────────────────────────────────────────────

export interface FileSignature {
  id: string;
  label: string;
  /** Bytes expected at `offset`; null entries match any byte. */
  bytes: readonly (number | null)[];
  offset: number;
  extensions: readonly string[];
  reference: Citation;
  /** Other formats sharing this signature. */
  ambiguousWith?: string;
}

const ascii = (text: string) => [...text].map((char) => char.charCodeAt(0));

export const FILE_SIGNATURES: readonly FileSignature[] = [
  { id: 'pe', label: 'Windows PE / MS-DOS executable', bytes: ascii('MZ'), offset: 0, extensions: ['exe', 'dll', 'sys', 'scr'], reference: { label: 'Microsoft PE format', url: 'https://learn.microsoft.com/windows/win32/debug/pe-format' } },
  { id: 'elf', label: 'ELF executable or object', bytes: [0x7f, ...ascii('ELF')], offset: 0, extensions: ['', 'so', 'o'], reference: { label: 'System V ABI (ELF)', url: 'https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html' } },
  { id: 'macho32', label: 'Mach-O 32-bit', bytes: [0xfe, 0xed, 0xfa, 0xce], offset: 0, extensions: [''], reference: { label: 'Apple mach-o/loader.h', url: 'https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h' } },
  { id: 'macho64', label: 'Mach-O 64-bit', bytes: [0xfe, 0xed, 0xfa, 0xcf], offset: 0, extensions: [''], reference: { label: 'Apple mach-o/loader.h', url: 'https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h' } },
  { id: 'macho32le', label: 'Mach-O 32-bit (little-endian)', bytes: [0xce, 0xfa, 0xed, 0xfe], offset: 0, extensions: [''], reference: { label: 'Apple mach-o/loader.h', url: 'https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h' } },
  { id: 'macho64le', label: 'Mach-O 64-bit (little-endian)', bytes: [0xcf, 0xfa, 0xed, 0xfe], offset: 0, extensions: [''], reference: { label: 'Apple mach-o/loader.h', url: 'https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h' } },
  { id: 'cafebabe', label: 'Java class file or Mach-O universal binary', bytes: [0xca, 0xfe, 0xba, 0xbe], offset: 0, extensions: ['class', ''], reference: { label: 'JVM Specification §4.1', url: 'https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html#jvms-4.1' }, ambiguousWith: 'Mach-O fat binary' },
  { id: 'wasm', label: 'WebAssembly binary', bytes: [0x00, ...ascii('asm')], offset: 0, extensions: ['wasm'], reference: { label: 'WebAssembly Core §5.5.16', url: 'https://webassembly.github.io/spec/core/binary/modules.html#binary-module' } },
  { id: 'pdf', label: 'PDF document', bytes: ascii('%PDF-'), offset: 0, extensions: ['pdf'], reference: { label: 'ISO 32000-2 §7.5.2', url: 'https://pdfa.org/resource/iso-32000-2/' } },
  { id: 'zip', label: 'ZIP archive (also DOCX, XLSX, PPTX, JAR, APK, ODT)', bytes: [0x50, 0x4b, 0x03, 0x04], offset: 0, extensions: ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt'], reference: { label: 'PKWARE APPNOTE §4.3.7', url: 'https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT' } },
  { id: 'zipEmpty', label: 'ZIP archive (empty)', bytes: [0x50, 0x4b, 0x05, 0x06], offset: 0, extensions: ['zip'], reference: { label: 'PKWARE APPNOTE §4.3.16', url: 'https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT' } },
  { id: 'gzip', label: 'gzip compressed data', bytes: [0x1f, 0x8b], offset: 0, extensions: ['gz', 'tgz'], reference: rfc(1952, '2.3.1') },
  { id: 'bzip2', label: 'bzip2 compressed data', bytes: ascii('BZh'), offset: 0, extensions: ['bz2'], reference: { label: 'bzip2 format', url: 'https://sourceware.org/bzip2/' } },
  { id: 'xz', label: 'XZ compressed data', bytes: [0xfd, ...ascii('7zXZ'), 0x00], offset: 0, extensions: ['xz'], reference: { label: 'XZ file format §2.1.1.1', url: 'https://tukaani.org/xz/xz-file-format.txt' } },
  { id: '7z', label: '7-Zip archive', bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], offset: 0, extensions: ['7z'], reference: { label: '7-Zip 7z format', url: 'https://www.7-zip.org/7z.html' } },
  { id: 'rar', label: 'RAR archive', bytes: [...ascii('Rar!'), 0x1a, 0x07], offset: 0, extensions: ['rar'], reference: { label: 'RAR 5.0 archive format', url: 'https://www.rarlab.com/technote.htm' } },
  { id: 'tar', label: 'POSIX tar archive', bytes: ascii('ustar'), offset: 257, extensions: ['tar'], reference: { label: 'POSIX pax / ustar format', url: 'https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html' } },
  { id: 'cfb', label: 'OLE compound file (DOC, XLS, PPT, MSI)', bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], offset: 0, extensions: ['doc', 'xls', 'ppt', 'msi', 'msg'], reference: { label: '[MS-CFB] Compound File Binary Format', url: 'https://learn.microsoft.com/openspecs/windows_protocols/ms-cfb/' } },
  { id: 'lnk', label: 'Windows shortcut (LNK)', bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], offset: 0, extensions: ['lnk'], reference: { label: '[MS-SHLLINK] Shell Link Binary Format', url: 'https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/' } },
  { id: 'evtx', label: 'Windows event log (EVTX)', bytes: [...ascii('ElfFile'), 0x00], offset: 0, extensions: ['evtx'], reference: { label: 'libyal libevtx documentation', url: 'https://github.com/libyal/libevtx' } },
  { id: 'pcap', label: 'pcap capture (microsecond, little-endian)', bytes: [0xd4, 0xc3, 0xb2, 0xa1], offset: 0, extensions: ['pcap'], reference: { label: 'IETF draft-ietf-opsawg-pcap', url: 'https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/' } },
  { id: 'pcapBe', label: 'pcap capture (microsecond, big-endian)', bytes: [0xa1, 0xb2, 0xc3, 0xd4], offset: 0, extensions: ['pcap'], reference: { label: 'IETF draft-ietf-opsawg-pcap', url: 'https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/' } },
  { id: 'pcapng', label: 'pcapng capture', bytes: [0x0a, 0x0d, 0x0d, 0x0a], offset: 0, extensions: ['pcapng'], reference: { label: 'IETF draft-ietf-opsawg-pcapng', url: 'https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/' } },
  { id: 'sqlite', label: 'SQLite 3 database', bytes: [...ascii('SQLite format 3'), 0x00], offset: 0, extensions: ['sqlite', 'db'], reference: { label: 'SQLite file format §1.3', url: 'https://www.sqlite.org/fileformat.html' } },
  { id: 'png', label: 'PNG image', bytes: [0x89, ...ascii('PNG'), 0x0d, 0x0a, 0x1a, 0x0a], offset: 0, extensions: ['png'], reference: { label: 'W3C PNG §5.2', url: 'https://www.w3.org/TR/png/#5PNG-file-signature' } },
  { id: 'jpeg', label: 'JPEG image', bytes: [0xff, 0xd8, 0xff], offset: 0, extensions: ['jpg', 'jpeg'], reference: { label: 'ITU-T T.81 (SOI marker)', url: 'https://www.w3.org/Graphics/JPEG/itu-t81.pdf' } },
  { id: 'gif', label: 'GIF image', bytes: ascii('GIF8'), offset: 0, extensions: ['gif'], reference: { label: 'GIF89a specification', url: 'https://www.w3.org/Graphics/GIF/spec-gif89a.txt' } },
  { id: 'riffWebp', label: 'WebP image', bytes: [...ascii('RIFF'), null, null, null, null, ...ascii('WEBP')], offset: 0, extensions: ['webp'], reference: rfc(9649) },
  { id: 'riffWav', label: 'WAVE audio', bytes: [...ascii('RIFF'), null, null, null, null, ...ascii('WAVE')], offset: 0, extensions: ['wav'], reference: { label: 'Microsoft RIFF / WAVE', url: 'https://learn.microsoft.com/windows/win32/xaudio2/resource-interchange-file-format--riff-' } },
  { id: 'iso', label: 'ISO 9660 disc image', bytes: ascii('CD001'), offset: 0x8001, extensions: ['iso'], reference: { label: 'ECMA-119 §8.4', url: 'https://ecma-international.org/publications-and-standards/standards/ecma-119/' } },
];

/** Returns every signature matching the first bytes of a file, longest first. */
export function detectSignatures(head: Uint8Array): FileSignature[] {
  return FILE_SIGNATURES.filter(
    (signature) =>
      head.length >= signature.offset + signature.bytes.length &&
      signature.bytes.every((byte, index) => byte === null || head[signature.offset + index] === byte),
  ).sort((a, b) => b.bytes.length - a.bytes.length);
}

/** Bytes to read from the start of a file to evaluate every signature. */
export const SIGNATURE_HEAD_BYTES = Math.max(...FILE_SIGNATURES.map((signature) => signature.offset + signature.bytes.length));
