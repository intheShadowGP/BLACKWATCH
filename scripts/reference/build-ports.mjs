// Builds public/reference/iana-ports.json from the IANA Service Name and
// Transport Protocol Port Number Registry (CC0 1.0, see
// https://www.iana.org/help/licensing-terms). Run occasionally; the output is
// committed together with its retrieval date.
//
// Usage: node scripts/reference/build-ports.mjs

import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const SOURCE = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv';
const OUTPUT = fileURLToPath(new URL('../../public/reference/iana-ports.json', import.meta.url));

/** RFC 4180 CSV parser (quoted fields, doubled quotes, CRLF). */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else quoted = false;
      } else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (char !== '\r') field += char;
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** Keeps single TCP/UDP ports with a service name; merges identical TCP and UDP rows. */
export function buildPorts(csv) {
  const [header, ...rows] = parseCsv(csv);
  const column = (name) => header.indexOf(name);
  const [name, port, proto, description] = ['Service Name', 'Port Number', 'Transport Protocol', 'Description'].map(column);
  if ([name, port, proto, description].some((index) => index < 0)) throw new Error('Unexpected registry columns');
  const merged = new Map();
  for (const row of rows) {
    const number = row[port];
    const transport = row[proto];
    if (!row[name] || !/^\d+$/.test(number ?? '') || !/^(tcp|udp)$/.test(transport ?? '')) continue;
    const text = (row[description] ?? '').replace(/\s+/g, ' ').trim().slice(0, 120);
    const key = `${number}|${row[name]}|${text}`;
    const existing = merged.get(key);
    if (existing) existing[1] = [...new Set([...existing[1].split('/'), transport])].sort().join('/');
    else merged.set(key, [Number(number), transport, row[name], text]);
  }
  return [...merged.values()].sort((a, b) => a[0] - b[0] || a[2].localeCompare(b[2]));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const response = await fetch(SOURCE, { headers: { 'user-agent': 'blackwatch-reference-builder' } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const entries = buildPorts(await response.text());
  if (entries.length < 5000) throw new Error(`Only ${entries.length} entries: refusing to write`);
  await mkdir(new URL('.', `file:///${OUTPUT.replace(/\\/g, '/')}`), { recursive: true });
  await writeFile(
    OUTPUT,
    JSON.stringify({
      source: SOURCE,
      registry: 'IANA Service Name and Transport Protocol Port Number Registry',
      licence: 'CC0 1.0 (IANA and IETF joint statement on the Protocol Registries)',
      licenceUrl: 'https://www.iana.org/help/licensing-terms',
      retrievedAt: new Date().toISOString(),
      entries,
    }),
  );
  console.log(`${entries.length} port entries written`);
}
