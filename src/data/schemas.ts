// Schemas of the published static datasets.
//
// This file is the contract between the data pipeline (scripts/data), which
// validates every dataset against it before publication, and the application,
// which validates again on load. It must stay free of non-erasable TypeScript
// syntax and of imports other than zod: the pipeline imports it directly.

import { z } from 'zod';

export const DATA_SCHEMA_VERSION = 1;

const httpUrl = z
  .string()
  .max(2048)
  .refine((value) => /^https?:\/\/[^\s<>"']+$/i.test(value), 'must be an http(s) URL');
const isoDate = z.string().refine((value) => !Number.isNaN(Date.parse(value)), 'must be a date');
const cveId = z.string().regex(/^CVE-\d{4}-\d{4,}$/);
const text = (max: number) => z.string().max(max);
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const count = z.number().int().nonnegative();

// ── Manifest ────────────────────────────────────────────────────────────────

export const DATASET_IDS = ['kev', 'nvd-recent', 'nvd-kev', 'attack', 'certfr'] as const;
export const datasetIdSchema = z.enum(DATASET_IDS);
export type DatasetId = z.infer<typeof datasetIdSchema>;

export const manifestEntrySchema = z.object({
  id: datasetIdSchema,
  file: z.string().regex(/^[a-z0-9-]+\.json$/),
  /** fresh: retrieved by the last pipeline run. stale: last valid copy kept after a failed update. */
  status: z.enum(['fresh', 'stale', 'missing']),
  retrievedAt: isoDate.nullable(),
  publisher: text(200),
  sourceUrl: httpUrl,
  licence: text(200),
  licenceUrl: httpUrl,
  /** Attribution or notice required by the publisher, reproduced verbatim. */
  notice: text(1000),
  version: text(100).nullable(),
  count: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
});
export type ManifestEntry = z.infer<typeof manifestEntrySchema>;

export const manifestSchema = z.object({
  schemaVersion: z.literal(DATA_SCHEMA_VERSION),
  generatedAt: isoDate,
  datasets: z.array(manifestEntrySchema).max(20),
  /** Derived Overview summary (see overviewSummarySchema). Absent from manifests published before 1.0. */
  overview: z.object({ file: z.literal('overview.json'), sha256 }).optional(),
});
export type Manifest = z.infer<typeof manifestSchema>;

// ── CISA Known Exploited Vulnerabilities ────────────────────────────────────

export const kevItemSchema = z.object({
  cve: cveId,
  vendor: text(300),
  product: text(300),
  name: text(600),
  dateAdded: isoDate,
  description: text(6000),
  requiredAction: text(6000),
  dueDate: isoDate.nullable(),
  /** Value published by CISA: "Known" or "Unknown". */
  ransomware: z.enum(['Known', 'Unknown']),
  cwes: z.array(z.string().regex(/^CWE-\d+$/)).max(30),
});
export type KevItem = z.infer<typeof kevItemSchema>;

export const kevDatasetSchema = z.object({
  catalogVersion: text(50),
  dateReleased: isoDate,
  items: z.array(kevItemSchema).max(20000),
});
export type KevDataset = z.infer<typeof kevDatasetSchema>;

// ── NVD CVE records ─────────────────────────────────────────────────────────

export const cvssSchema = z.object({
  version: z.enum(['3.0', '3.1', '4.0']),
  score: z.number().min(0).max(10),
  severity: z.enum(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  vector: text(400),
  /** Identifier of the organisation that assigned the score, as published by the NVD. */
  source: text(200),
});
export type Cvss = z.infer<typeof cvssSchema>;

export const cveItemSchema = z.object({
  id: cveId,
  published: isoDate,
  lastModified: isoDate,
  /** NVD analysis status, e.g. "Analyzed", "Awaiting Analysis", "Deferred". */
  status: text(60),
  description: text(8000),
  cvss3: cvssSchema.nullable(),
  cvss4: cvssSchema.nullable(),
  cwes: z.array(z.string().regex(/^CWE-\d+$/)).max(30),
  /** "vendor:product" pairs taken from CPE match criteria and affected-product data. */
  products: z.array(text(300)).max(25),
  /** At most 12 references, those tagged Patch, Vendor Advisory or Mitigation first. */
  references: z.array(z.object({ url: httpUrl, tags: z.array(text(60)).max(10) })).max(12),
  /** Number of valid references in the NVD record, before the selection above. */
  referenceCount: z.number().int().nonnegative(),
});
export type CveItem = z.infer<typeof cveItemSchema>;

export const cveDatasetSchema = z.object({
  /** Human-readable definition of what the file contains. */
  scope: text(300),
  publishedFrom: isoDate.nullable(),
  publishedTo: isoDate.nullable(),
  items: z.array(cveItemSchema).max(50000),
});
export type CveDataset = z.infer<typeof cveDatasetSchema>;

// ── MITRE ATT&CK (Enterprise) ───────────────────────────────────────────────

const attackId = (pattern: RegExp) => z.string().regex(pattern);
const tacticShortname = z.string().regex(/^[a-z-]+$/);
const pair = z.tuple([text(20), text(20)]);

export const attackDatasetSchema = z.object({
  domain: z.literal('enterprise-attack'),
  version: text(20),
  modified: isoDate,
  /** True when long descriptions were shortened by the pipeline. */
  descriptionsTruncatedAt: z.number().int().positive(),
  tactics: z
    .array(
      z.object({
        id: attackId(/^TA\d{4}$/),
        shortname: tacticShortname,
        name: text(200),
        description: text(4000),
      }),
    )
    .max(50),
  techniques: z
    .array(
      z.object({
        id: attackId(/^T\d{4}(\.\d{3})?$/),
        name: text(300),
        description: text(4000),
        tactics: z.array(tacticShortname).max(20),
        platforms: z.array(text(60)).max(30),
        parent: attackId(/^T\d{4}$/).nullable(),
      }),
    )
    .max(5000),
  groups: z
    .array(
      z.object({
        id: attackId(/^G\d{4}$/),
        name: text(300),
        aliases: z.array(text(200)).max(60),
        description: text(4000),
      }),
    )
    .max(2000),
  software: z
    .array(
      z.object({
        id: attackId(/^S\d{4}$/),
        name: text(300),
        kind: z.enum(['malware', 'tool']),
        platforms: z.array(text(60)).max(30),
        description: text(4000),
      }),
    )
    .max(5000),
  campaigns: z
    .array(
      z.object({
        id: attackId(/^C\d{4}$/),
        name: text(300),
        description: text(4000),
        firstSeen: isoDate.nullable(),
        lastSeen: isoDate.nullable(),
      }),
    )
    .max(2000),
  mitigations: z
    .array(z.object({ id: attackId(/^M\d{4}$/), name: text(300), description: text(4000) }))
    .max(2000),
  detections: z.array(z.object({ id: attackId(/^DET\d{4}$/), name: text(400) })).max(5000),
  /** Relationship pairs [source id, target id], taken from STIX relationship objects. */
  relations: z.object({
    groupTechnique: z.array(pair).max(50000),
    groupSoftware: z.array(pair).max(50000),
    softwareTechnique: z.array(pair).max(50000),
    campaignTechnique: z.array(pair).max(50000),
    campaignSoftware: z.array(pair).max(50000),
    campaignGroup: z.array(pair).max(50000),
    mitigationTechnique: z.array(pair).max(50000),
    detectionTechnique: z.array(pair).max(50000),
  }),
});
export type AttackDataset = z.infer<typeof attackDatasetSchema>;

// ── CERT-FR advisories and alerts ───────────────────────────────────────────

export const certfrItemSchema = z.object({
  id: z.string().regex(/^CERTFR-\d{4}-[A-Z]{3}-\d+$/),
  kind: z.enum(['avis', 'alerte']),
  title: text(600),
  summary: text(4000),
  url: httpUrl,
  published: isoDate,
});
export type CertfrItem = z.infer<typeof certfrItemSchema>;

export const certfrDatasetSchema = z.object({
  items: z.array(certfrItemSchema).max(2000),
});
export type CertfrDataset = z.infer<typeof certfrDatasetSchema>;

// ── Registry ────────────────────────────────────────────────────────────────

export const DATASET_SCHEMAS = {
  kev: kevDatasetSchema,
  'nvd-recent': cveDatasetSchema,
  'nvd-kev': cveDatasetSchema,
  attack: attackDatasetSchema,
  certfr: certfrDatasetSchema,
} as const;

export interface DatasetTypes {
  kev: KevDataset;
  'nvd-recent': CveDataset;
  'nvd-kev': CveDataset;
  attack: AttackDataset;
  certfr: CertfrDataset;
}

// ── Overview summary (derived) ─────────────────────────────────────────────
//
// Computed by the pipeline from the published kev and nvd-recent files, so the
// Overview does not download and parse several megabytes. `sources` holds the
// sha256 of the files it was computed from: the application uses the summary
// only when they match the manifest, and otherwise computes the same figures
// from the full datasets (src/data/overview.ts holds the single implementation).

export const kevSummarySchema = z.object({
  total: count,
  added30: count,
  ransomware: count,
  months: z.array(z.object({ label: z.string().regex(/^\d{4}-\d{2}$/), value: count })).length(12),
  latest: z.array(kevItemSchema.pick({ cve: true, dateAdded: true, name: true })).max(6),
});
export type KevSummary = z.infer<typeof kevSummarySchema>;

export const recentSummarySchema = z.object({
  total: count,
  inKev: count,
  buckets: z.object({ CRITICAL: count, HIGH: count, MEDIUM: count, LOW: count, NONE: count, UNSCORED: count }),
  critical: z.array(z.object({ id: cveId, published: isoDate, description: text(6000), cvss: cvssSchema })).max(6),
});
export type RecentSummary = z.infer<typeof recentSummarySchema>;

export const overviewSummarySchema = z.object({
  schemaVersion: z.literal(DATA_SCHEMA_VERSION),
  generatedAt: isoDate,
  sources: z.object({ kev: sha256.nullable(), 'nvd-recent': sha256.nullable() }),
  kev: kevSummarySchema.nullable(),
  recent: recentSummarySchema.nullable(),
});
export type OverviewSummary = z.infer<typeof overviewSummarySchema>;
