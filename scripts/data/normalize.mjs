// Pure normalisation functions: raw publisher payloads in, dataset objects out.
// No network or file access here, so every function can be unit tested.
// Values are copied from the sources; the pipeline selects and trims fields but
// never rewrites scores, statuses or identifiers.

const DESCRIPTION_LIMIT = 900;

const asArray = (value) => (Array.isArray(value) ? value : []);
/** Array elements that are plain objects; anything else in a payload is ignored. */
const asObjects = (value) => asArray(value).filter((item) => item !== null && typeof item === 'object' && !Array.isArray(item));
const asString = (value) => (typeof value === 'string' ? value : '');
const unique = (values) => [...new Set(values)];

/** Accepts "2026-11-10" or NVD timestamps without a zone ("2026-11-10T18:17:23.490") as UTC. */
export function toIso(value) {
  const raw = asString(value).trim();
  if (!raw) return null;
  const candidate = /^\d{4}-\d{2}-\d{2}T[\d:.]+$/.test(raw) ? `${raw}Z` : raw;
  const time = Date.parse(candidate);
  return Number.isNaN(time) ? null : new Date(time).toISOString();
}

function isHttpUrl(value) {
  return /^https?:\/\/[^\s<>"']+$/i.test(asString(value)) && asString(value).length <= 2048;
}

function extractCwes(values) {
  return unique(
    asArray(values)
      .map((value) => asString(value).trim())
      .filter((value) => /^CWE-\d+$/.test(value)),
  ).slice(0, 30);
}

// ── CISA KEV ────────────────────────────────────────────────────────────────

export function normalizeKev(raw) {
  const items = asObjects(raw?.vulnerabilities)
    .map((entry) => ({
      cve: asString(entry.cveID).trim(),
      vendor: asString(entry.vendorProject).trim(),
      product: asString(entry.product).trim(),
      name: asString(entry.vulnerabilityName).trim(),
      dateAdded: toIso(entry.dateAdded),
      description: asString(entry.shortDescription).trim(),
      requiredAction: asString(entry.requiredAction).trim(),
      dueDate: toIso(entry.dueDate),
      ransomware: entry.knownRansomwareCampaignUse === 'Known' ? 'Known' : 'Unknown',
      cwes: extractCwes(entry.cwes),
    }))
    .filter((item) => /^CVE-\d{4}-\d{4,}$/.test(item.cve) && item.dateAdded);

  const seen = new Set();
  const deduplicated = items.filter((item) => !seen.has(item.cve) && seen.add(item.cve));
  deduplicated.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || a.cve.localeCompare(b.cve));

  return {
    catalogVersion: asString(raw?.catalogVersion),
    dateReleased: toIso(raw?.dateReleased),
    items: deduplicated,
  };
}

// ── NVD ─────────────────────────────────────────────────────────────────────

const SEVERITIES = new Set(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

function pickCvss(metrics, version) {
  const candidates = asArray(metrics);
  // The NVD marks its own assessment "Primary"; fall back to the first other source.
  const chosen = candidates.find((metric) => metric?.type === 'Primary') ?? candidates[0];
  const data = chosen?.cvssData;
  if (!data || typeof data.baseScore !== 'number') return null;
  const severity = asString(data.baseSeverity).toUpperCase();
  if (!SEVERITIES.has(severity)) return null;
  return {
    version,
    score: data.baseScore,
    severity,
    vector: asString(data.vectorString).slice(0, 400),
    source: asString(chosen.source).slice(0, 200),
  };
}

function extractProducts(cve) {
  const products = [];
  for (const configuration of asArray(cve.configurations)) {
    for (const node of asArray(configuration?.nodes)) {
      for (const match of asArray(node?.cpeMatch)) {
        if (match?.vulnerable === false) continue;
        const parts = asString(match?.criteria).split(':');
        if (parts.length > 5 && parts[3] && parts[4] && parts[3] !== '*') {
          products.push(`${parts[3]}:${parts[4]}`);
        }
      }
    }
  }
  for (const source of asArray(cve.affected)) {
    for (const entry of asArray(source?.affectedData)) {
      const vendor = asString(entry?.vendor).trim();
      const product = asString(entry?.product).trim();
      if (vendor && product) products.push(`${vendor}:${product}`.slice(0, 300));
    }
  }
  return unique(products.map((value) => value.toLowerCase())).slice(0, 25);
}

const MAX_REFERENCES = 12;
const REMEDIATION_TAGS = new Set(['Patch', 'Vendor Advisory', 'Mitigation']);

/** Keeps at most MAX_REFERENCES references, remediation-tagged ones first, original order otherwise. */
function selectReferences(raw) {
  const valid = asObjects(raw)
    .filter((reference) => isHttpUrl(reference.url))
    .map((reference) => ({
      url: reference.url,
      tags: asArray(reference.tags).map((tag) => asString(tag).slice(0, 60)).slice(0, 10),
    }));
  const rank = (reference) => (reference.tags.some((tag) => REMEDIATION_TAGS.has(tag)) ? 0 : 1);
  const ordered = valid.map((reference, index) => ({ reference, index }))
    .sort((a, b) => rank(a.reference) - rank(b.reference) || a.index - b.index)
    .map((entry) => entry.reference);
  return { references: ordered.slice(0, MAX_REFERENCES), referenceCount: valid.length };
}

export function normalizeCve(wrapper) {
  const cve = wrapper?.cve;
  const id = asString(cve?.id);
  const published = toIso(cve?.published);
  const lastModified = toIso(cve?.lastModified);
  if (!/^CVE-\d{4}-\d{4,}$/.test(id) || !published || !lastModified) return null;

  const description =
    asArray(cve.descriptions).find((entry) => entry?.lang === 'en')?.value ?? '';
  const metrics = cve.metrics ?? {};
  const weaknesses = asArray(cve.weaknesses).flatMap((weakness) =>
    asArray(weakness?.description).map((entry) => entry?.value),
  );

  return {
    id,
    published,
    lastModified,
    status: asString(cve.vulnStatus).slice(0, 60),
    description: asString(description).trim().slice(0, 8000),
    cvss3: pickCvss(metrics.cvssMetricV31, '3.1') ?? pickCvss(metrics.cvssMetricV30, '3.0'),
    cvss4: pickCvss(metrics.cvssMetricV40, '4.0'),
    cwes: extractCwes(weaknesses),
    products: extractProducts(cve),
    ...selectReferences(cve.references),
  };
}

export function normalizeCveList(wrappers, meta) {
  const byId = new Map();
  for (const wrapper of asArray(wrappers)) {
    const item = normalizeCve(wrapper);
    // Rejected CVE ids are withdrawn by their CNA: they describe no vulnerability.
    if (!item || item.status === 'Rejected') continue;
    const existing = byId.get(item.id);
    if (!existing || existing.lastModified < item.lastModified) byId.set(item.id, item);
  }
  const items = [...byId.values()].sort(
    (a, b) => b.published.localeCompare(a.published) || a.id.localeCompare(b.id),
  );
  return { scope: meta.scope, publishedFrom: meta.publishedFrom, publishedTo: meta.publishedTo, items };
}

// ── MITRE ATT&CK ────────────────────────────────────────────────────────────

/** Removes citation markers and Markdown links, then shortens to a sentence boundary when possible. */
export function cleanDescription(value, limit = DESCRIPTION_LIMIT) {
  const cleaned = asString(value)
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\((?:[^)]+)\)/g, '$1')
    .replace(/<\/?code>/g, '`')
    .replace(/[ \t]+/g, ' ')
    .replace(/ +([.,;])/g, '$1')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  if (cleaned.length <= limit) return cleaned;
  const slice = cleaned.slice(0, limit);
  const stop = slice.lastIndexOf('. ');
  return `${stop > limit * 0.5 ? slice.slice(0, stop + 1) : slice.trimEnd()} […]`;
}

function attackExternalId(object) {
  const reference = asArray(object?.external_references).find(
    (entry) => entry?.source_name === 'mitre-attack' && typeof entry.external_id === 'string',
  );
  return reference?.external_id ?? null;
}

const isActive = (object) => object && object.revoked !== true && object.x_mitre_deprecated !== true;

export function normalizeAttack(bundle) {
  const objects = asObjects(bundle?.objects);
  const collection = objects.find((object) => object.type === 'x-mitre-collection');
  const matrix = objects.find((object) => object.type === 'x-mitre-matrix');
  const stixToId = new Map();
  const byType = (type) => objects.filter((object) => object.type === type && isActive(object));
  const register = (object, pattern) => {
    const id = attackExternalId(object);
    if (!id || !pattern.test(id)) return null;
    stixToId.set(object.id, id);
    return id;
  };
  const sortById = (list) => list.sort((a, b) => a.id.localeCompare(b.id, 'en', { numeric: true }));

  const tacticOrder = asArray(matrix?.tactic_refs);
  const tactics = byType('x-mitre-tactic')
    .map((object) => ({ object, id: register(object, /^TA\d{4}$/) }))
    .filter((entry) => entry.id)
    .sort((a, b) => tacticOrder.indexOf(a.object.id) - tacticOrder.indexOf(b.object.id))
    .map(({ object, id }) => ({
      id,
      shortname: asString(object.x_mitre_shortname),
      name: asString(object.name),
      description: cleanDescription(object.description),
    }));

  const techniques = sortById(
    byType('attack-pattern')
      .map((object) => {
        const id = register(object, /^T\d{4}(\.\d{3})?$/);
        if (!id) return null;
        return {
          id,
          name: asString(object.name),
          description: cleanDescription(object.description),
          tactics: asArray(object.kill_chain_phases)
            .filter((phase) => phase?.kill_chain_name === 'mitre-attack')
            .map((phase) => asString(phase.phase_name)),
          platforms: asArray(object.x_mitre_platforms).map(asString),
          parent: id.includes('.') ? id.split('.')[0] : null,
        };
      })
      .filter(Boolean),
  );

  const groups = sortById(
    byType('intrusion-set')
      .map((object) => {
        const id = register(object, /^G\d{4}$/);
        if (!id) return null;
        const name = asString(object.name);
        return {
          id,
          name,
          aliases: unique(asArray(object.aliases).map(asString)).filter((alias) => alias && alias !== name),
          description: cleanDescription(object.description),
        };
      })
      .filter(Boolean),
  );

  const software = sortById(
    [...byType('malware'), ...byType('tool')]
      .map((object) => {
        const id = register(object, /^S\d{4}$/);
        if (!id) return null;
        return {
          id,
          name: asString(object.name),
          kind: object.type === 'tool' ? 'tool' : 'malware',
          platforms: asArray(object.x_mitre_platforms).map(asString),
          description: cleanDescription(object.description),
        };
      })
      .filter(Boolean),
  );

  const campaigns = sortById(
    byType('campaign')
      .map((object) => {
        const id = register(object, /^C\d{4}$/);
        if (!id) return null;
        return {
          id,
          name: asString(object.name),
          description: cleanDescription(object.description),
          firstSeen: toIso(object.first_seen),
          lastSeen: toIso(object.last_seen),
        };
      })
      .filter(Boolean),
  );

  const mitigations = sortById(
    byType('course-of-action')
      .map((object) => {
        const id = register(object, /^M\d{4}$/);
        return id
          ? { id, name: asString(object.name), description: cleanDescription(object.description) }
          : null;
      })
      .filter(Boolean),
  );

  const detections = sortById(
    byType('x-mitre-detection-strategy')
      .map((object) => {
        const id = register(object, /^DET\d{4}$/);
        return id ? { id, name: asString(object.name).slice(0, 400) } : null;
      })
      .filter(Boolean),
  );

  const relations = {
    groupTechnique: [],
    groupSoftware: [],
    softwareTechnique: [],
    campaignTechnique: [],
    campaignSoftware: [],
    campaignGroup: [],
    mitigationTechnique: [],
    detectionTechnique: [],
  };
  const kindOf = (id) =>
    id.startsWith('TA') ? 'tactic'
    : id.startsWith('DET') ? 'detection'
    : id.startsWith('T') ? 'technique'
    : id.startsWith('G') ? 'group'
    : id.startsWith('S') ? 'software'
    : id.startsWith('C') ? 'campaign'
    : id.startsWith('M') ? 'mitigation'
    : 'other';
  const ROUTES = {
    'uses:group>technique': 'groupTechnique',
    'uses:group>software': 'groupSoftware',
    'uses:software>technique': 'softwareTechnique',
    'uses:campaign>technique': 'campaignTechnique',
    'uses:campaign>software': 'campaignSoftware',
    'attributed-to:campaign>group': 'campaignGroup',
    'mitigates:mitigation>technique': 'mitigationTechnique',
    'detects:detection>technique': 'detectionTechnique',
  };
  const seenPairs = new Set();
  for (const relationship of byType('relationship')) {
    const source = stixToId.get(relationship.source_ref);
    const target = stixToId.get(relationship.target_ref);
    if (!source || !target) continue;
    const route = ROUTES[`${relationship.relationship_type}:${kindOf(source)}>${kindOf(target)}`];
    if (!route) continue;
    const key = `${route}|${source}|${target}`;
    if (seenPairs.has(key)) continue;
    seenPairs.add(key);
    relations[route].push([source, target]);
  }
  for (const list of Object.values(relations)) {
    list.sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
  }

  return {
    domain: 'enterprise-attack',
    version: asString(collection?.x_mitre_version),
    modified: toIso(collection?.modified),
    descriptionsTruncatedAt: DESCRIPTION_LIMIT,
    tactics,
    techniques,
    groups,
    software,
    campaigns,
    mitigations,
    detections,
    relations,
  };
}

// ── CERT-FR RSS ─────────────────────────────────────────────────────────────

const XML_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

export function decodeXml(value) {
  return asString(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, entity) => {
      if (entity[0] === '#') {
        const code = entity[1].toLowerCase() === 'x' ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
        return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
      }
      return XML_ENTITIES[entity.toLowerCase()] ?? match;
    });
}

/** Strips any markup that a feed may embed in a text field: the result is plain text. */
function plainText(value) {
  return decodeXml(value)
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tagContent(block, tag) {
  const match = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, 'i').exec(block);
  return match ? match[1] : '';
}

const CERTFR_HOSTS = new Set(['www.cert.cyber.gouv.fr', 'cert.cyber.gouv.fr', 'www.cert.ssi.gouv.fr', 'cert.ssi.gouv.fr']);

export function normalizeCertfr(feeds) {
  const byId = new Map();
  for (const xml of asArray(feeds)) {
    for (const match of asString(xml).matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)) {
      const block = match[1];
      const url = decodeXml(tagContent(block, 'link')).trim();
      const id = /CERTFR-\d{4}-([A-Z]{3})-\d+/.exec(url);
      const published = toIso(decodeXml(tagContent(block, 'pubDate')));
      let host;
      try {
        host = new URL(url).hostname;
      } catch {
        continue;
      }
      if (!id || !published || !CERTFR_HOSTS.has(host) || !url.startsWith('https://')) continue;
      const kind = id[1] === 'AVI' ? 'avis' : id[1] === 'ALE' ? 'alerte' : null;
      if (!kind) continue;
      byId.set(id[0], {
        id: id[0],
        kind,
        title: plainText(tagContent(block, 'title')).slice(0, 600),
        summary: plainText(tagContent(block, 'description')).slice(0, 4000),
        url,
        published,
      });
    }
  }
  const items = [...byId.values()].sort(
    (a, b) => b.published.localeCompare(a.published) || b.id.localeCompare(a.id),
  );
  return { items };
}
