// Builders for synthetic evidence. Output formats match what the SOC
// Workbench parses, so learners can import the evidence there too.

export const pad = (value: number) => String(value).padStart(2, '0');

/** ISO timestamp on a fixed synthetic day, offset by seconds. */
export const iso = (day: string, seconds: number) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${day}T${pad(h)}:${pad(m)}:${pad(s)}Z`;
};

const escapeXml = (value: string) => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&apos;');

export function windowsEvent(id: number, time: string, computer: string, data: Record<string, string>, provider = 'Microsoft-Windows-Security-Auditing', channel = 'Security'): string {
  const fields = Object.entries(data)
    .map(([name, value]) => `<Data Name='${name}'>${escapeXml(value)}</Data>`)
    .join('');
  return `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='${provider}'/><EventID>${id}</EventID><TimeCreated SystemTime='${time}'/><Channel>${channel}</Channel><Computer>${computer}</Computer></System><EventData>${fields}</EventData></Event>`;
}

export const windowsExport = (events: string[]) => `<Events>\n${events.join('\n')}\n</Events>\n`;

export const jsonLines = (records: Record<string, unknown>[]) => `${records.map((record) => JSON.stringify(record)).join('\n')}\n`;

/** Base64 of UTF-16LE text, the encoding PowerShell expects for -EncodedCommand. */
export function utf16Base64(text: string): string {
  const bytes: number[] = [];
  for (const char of text) {
    const code = char.charCodeAt(0);
    bytes.push(code & 0xff, code >> 8);
  }
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
