// Local file analysis: hashes, entropy and signature detection. Files are read
// in the browser; nothing is uploaded.

import { shannonEntropy, entropyProfile } from './analysis';
import { hexDump } from './bytes';
import { hashBytes, MAX_HASH_FILE_BYTES, type HashAlgorithm } from './hash';
import { detectSignatures, SIGNATURE_HEAD_BYTES } from './reference';

export interface FileReport {
  size: number;
  hashes: Record<HashAlgorithm, string>;
  entropy: number;
  distinctBytes: number;
  profile: number[];
  signatures: string[];
  headDump: string;
}

export type FileAnalysisResult = { status: 'ok'; report: FileReport } | { status: 'tooLarge' } | { status: 'error' };

export async function analyzeBytes(bytes: Uint8Array): Promise<FileReport> {
  const entropy = shannonEntropy(bytes);
  return {
    size: bytes.length,
    hashes: await hashBytes(bytes),
    entropy: entropy.bitsPerByte,
    distinctBytes: entropy.distinctBytes,
    profile: entropyProfile(bytes),
    signatures: detectSignatures(bytes.subarray(0, SIGNATURE_HEAD_BYTES)).map((signature) => signature.id),
    headDump: hexDump(bytes.subarray(0, 256)),
  };
}

export async function analyzeBlob(blob: Blob): Promise<FileAnalysisResult> {
  if (blob.size > MAX_HASH_FILE_BYTES) return { status: 'tooLarge' };
  try {
    return { status: 'ok', report: await analyzeBytes(new Uint8Array(await blob.arrayBuffer())) };
  } catch {
    return { status: 'error' };
  }
}

/** Analyses a file in a worker so hashing large files does not block the interface. */
export function analyzeFile(file: Blob): Promise<FileAnalysisResult> {
  if (file.size > MAX_HASH_FILE_BYTES) return Promise.resolve({ status: 'tooLarge' });
  if (typeof Worker === 'undefined') return analyzeBlob(file);
  return new Promise((resolve) => {
    const worker = new Worker(new URL('../workers/file.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (event: MessageEvent<FileAnalysisResult>) => {
      worker.terminate();
      resolve(event.data);
    };
    worker.onerror = () => {
      worker.terminate();
      resolve({ status: 'error' });
    };
    worker.postMessage(file);
  });
}
