/** Hands generated content to the browser as a local file download. Nothing leaves the device. */
export function downloadText(fileName: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * Escapes one CSV cell (RFC 4180) and neutralises spreadsheet formula
 * injection: a cell starting with = + - @ tab or carriage return is prefixed
 * with an apostrophe so that it is read as text.
 */
export function csvCell(value: unknown): string {
  let cell = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(cell)) cell = `'${cell}`;
  return /[",\r\n]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell;
}

export function toCsv(header: readonly string[], rows: readonly (readonly unknown[])[]): string {
  return [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

/** File name stamp such as 2026-03-04T05-06-07Z, safe on every file system. */
export function fileStamp(date: Date = new Date()): string {
  return date.toISOString().replace(/\.\d+Z$/, 'Z').replace(/:/g, '-');
}
