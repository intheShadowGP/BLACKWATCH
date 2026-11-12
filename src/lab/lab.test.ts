import { existsSync, readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BlackwatchDb } from '../lib/db';
import { extractIocs } from '../lib/ioc';
import { runDetections } from '../soc/lib/detections';
import { parseText } from '../soc/lib/parsers';
import { CATALOG, loadScenario, SCENARIO_IDS } from './catalog';
import { bestAnswer, buildLabReport, scenarioMax, scoreAttempt, scoreStep, type Answers } from './engine';
import type { Scenario, Step } from './model';
import { clearProgress, emptyProgress, loadProgress, saveProgress } from './progress';

/** The topics required by the specification, mapped to the scenario covering each. */
export const SPECIFICATION_SCENARIOS: Readonly<Record<string, string>> = {
  'SSH brute-force attack': 'ssh-bruteforce',
  'Phishing incident': 'phishing',
  'Ransomware simulation': 'ransomware',
  'Lateral movement': 'lateral-movement',
  'Suspicious PowerShell activity': 'powershell',
  'Web application compromise': 'web-compromise',
  'Account compromise': 'account-compromise',
  'Simulated data exfiltration': 'exfiltration',
  'Active Directory misconfiguration': 'ad-misconfiguration',
  'Network intrusion': 'network-intrusion',
};

async function all(): Promise<Scenario[]> {
  return Promise.all(SCENARIO_IDS.map(async (id) => (await loadScenario(id)) as Scenario));
}

const labels = {
  kind: (kind: Step['kind']) => kind,
  yourAnswer: 'Your answer',
  bestAnswer: 'Best answer',
  score: 'Score',
  context: 'Context',
  debrief: 'Debrief',
  lessons: 'Lessons',
  references: 'References',
  syntheticNote: 'Synthetic exercise.',
};

describe('catalogue and specification coverage', () => {
  it('maps every required topic to a scenario', () => {
    expect(Object.keys(SPECIFICATION_SCENARIOS)).toHaveLength(10);
    for (const [topic, id] of Object.entries(SPECIFICATION_SCENARIOS)) expect(SCENARIO_IDS, topic).toContain(id);
  });

  it('matches each scenario body to its catalogue summary', async () => {
    for (const scenario of await all()) {
      const summary = CATALOG.find((entry) => entry.id === scenario.id);
      expect(summary, scenario.id).toEqual({ id: scenario.id, version: scenario.version, title: scenario.title, difficulty: scenario.difficulty, minutes: scenario.minutes, techniques: scenario.techniques });
    }
    expect(CATALOG.map((entry) => entry.id).sort()).toEqual([...SCENARIO_IDS].sort());
  });
});

describe('scenario content', () => {
  it('has the nine required parts, consistent ids and both languages', async () => {
    for (const scenario of await all()) {
      const name = scenario.id;
      for (const text of [scenario.title, scenario.context, scenario.incident, scenario.debrief, ...scenario.lessons]) {
        expect(text.en.trim(), name).not.toBe('');
        expect(text.fr.trim(), name).not.toBe('');
      }
      expect(scenario.evidence.length, name).toBeGreaterThan(0);
      for (const kind of ['investigation', 'decision', 'containment', 'remediation'] as const) {
        expect(scenario.steps.some((step) => step.kind === kind), `${name} ${kind}`).toBe(true);
      }
      expect(scenario.lessons.length, name).toBeGreaterThan(0);
      const evidenceIds = new Set(scenario.evidence.map((item) => item.id));
      expect(evidenceIds.size, name).toBe(scenario.evidence.length);
      expect(new Set(scenario.steps.map((step) => step.id)).size, name).toBe(scenario.steps.length);
      for (const step of scenario.steps) {
        const where = `${name}/${step.id}`;
        expect(step.references.length, where).toBeGreaterThan(0);
        for (const reference of step.references) expect(reference.url, where).toMatch(/^https:\/\//);
        for (const id of step.evidence) expect(evidenceIds.has(id), `${where} → ${id}`).toBe(true);
        expect(new Set(step.options.map((option) => option.id)).size, where).toBe(step.options.length);
        for (const option of step.options) {
          expect(option.text.en && option.text.fr && option.feedback.en && option.feedback.fr, `${where}/${option.id}`).toBeTruthy();
        }
        if (step.mode === 'single') {
          expect(step.options.every((option) => option.correct === undefined && typeof option.points === 'number'), where).toBe(true);
          expect(Math.max(...step.options.map((option) => option.points ?? 0)), where).toBe(step.points);
        } else {
          expect(step.options.every((option) => option.points === undefined && typeof option.correct === 'boolean'), where).toBe(true);
          expect(step.options.some((option) => option.correct), where).toBe(true);
          expect(step.options.some((option) => !option.correct), where).toBe(true);
        }
      }
    }
  });

  it('uses only documentation or private addresses and reserved example domains', async () => {
    for (const scenario of await all()) {
      const text = JSON.stringify(scenario);
      for (const ioc of extractIocs(text).iocs) {
        if (ioc.type === 'ipv4' || ioc.type === 'ipv6') {
          expect(['documentation', 'private', 'loopback', 'uniqueLocal', 'linkLocal'], `${scenario.id}: ${ioc.value}`).toContain(ioc.addressClass);
        }
        if (ioc.type === 'domain' || ioc.type === 'email' || ioc.type === 'url') {
          const host = ioc.type === 'url' ? new URL(ioc.value).hostname : ioc.value.split('@').pop() as string;
          const external = scenario.steps.flatMap((step) => step.references.map((reference) => new URL(reference.url).hostname));
          // schemas.microsoft.com appears only as the XML namespace of Windows event exports.
          const allowed = host === 'schemas.microsoft.com' || /(^|\.)(example|test|invalid|localhost)$/.test(host) || /(^|\.)example\.(com|net|org)$/.test(host) || external.includes(host);
          expect(allowed, `${scenario.id}: ${ioc.value}`).toBe(true);
        }
      }
    }
  });

  it('produces evidence logs the SOC Workbench parses without loss and detects', async () => {
    for (const scenario of await all()) {
      for (const item of scenario.evidence.filter((entry) => entry.logFormat)) {
        const parsed = parseText(item.content, item.logFormat as never, { endYear: 2026, offsetMinutes: 0 });
        expect(parsed.stats.unparsed, `${scenario.id}/${item.id}`).toBe(0);
        expect(parsed.stats.parsed, `${scenario.id}/${item.id}`).toBeGreaterThan(0);
      }
    }
    const ssh = (await loadScenario('ssh-bruteforce')) as Scenario;
    const events = parseText(ssh.evidence[0]?.content as string, 'syslog', { endYear: 2026, offsetMinutes: 0 }).events.map((event, index) => ({ ...event, id: index, file: 0 }));
    const findings = runDetections(events).findings;
    expect(findings.some((finding) => finding.rule === 'successAfterFailures' && finding.entity.value === '203.0.113.50')).toBe(true);
    expect(findings.some((finding) => finding.rule === 'accountChanges' && finding.entity.value === 'sysupdate')).toBe(true);

    const detect = async (id: string, evidenceId: string) => {
      const scenario = (await loadScenario(id)) as Scenario;
      const item = scenario.evidence.find((entry) => entry.id === evidenceId);
      const parsed = parseText(item?.content as string, item?.logFormat as never, { endYear: 2026, offsetMinutes: 0 });
      return runDetections(parsed.events.map((event, index) => ({ ...event, id: index, file: 0 }))).findings;
    };
    expect((await detect('powershell', 'process')).some((finding) => finding.rule === 'encodedPowerShell' && finding.entity.value === 'WKS-042')).toBe(true);
    expect((await detect('web-compromise', 'access')).some((finding) => finding.rule === 'suspiciousWebRequest' && finding.entity.value === '203.0.113.88')).toBe(true);
  });

  it('ships only inert encoded commands', async () => {
    const scenario = (await loadScenario('powershell')) as Scenario;
    const encoded = /-EncodedCommand ([A-Za-z0-9+/=]+)/.exec(scenario.evidence[0]?.content as string)?.[1] as string;
    const decoded = Buffer.from(encoded, 'base64').toString('utf16le');
    expect(decoded).toBe("Write-Output 'BLACKWATCH training sample: no action performed'");
  });

  it('cites ATT&CK techniques present in the published dataset', async () => {
    const file = 'public/data/attack.json';
    if (!existsSync(file)) return;
    const ids = new Set((JSON.parse(readFileSync(file, 'utf8')) as { techniques: { id: string }[]; mitigations: { id: string }[] }).techniques.map((technique) => technique.id));
    const mitigations = new Set((JSON.parse(readFileSync(file, 'utf8')) as { mitigations: { id: string }[] }).mitigations.map((item) => item.id));
    for (const scenario of await all()) {
      for (const technique of scenario.techniques) expect(ids.has(technique), `${scenario.id} ${technique}`).toBe(true);
      for (const step of scenario.steps) {
        for (const reference of step.references) {
          const id = /attack\.mitre\.org\/mitigations\/(M\d{4})\//.exec(reference.url)?.[1];
          if (id) expect(mitigations.has(id), `${scenario.id} ${id}`).toBe(true);
        }
      }
    }
  });
});

describe('scoring', () => {
  it('gives the declared maximum for the best answers and never goes negative', async () => {
    for (const scenario of await all()) {
      const best: Answers = Object.fromEntries(scenario.steps.map((step) => [step.id, bestAnswer(step)]));
      expect(scoreAttempt(scenario, best).total, scenario.id).toBe(scenarioMax(scenario));
      const worst: Answers = Object.fromEntries(
        scenario.steps.map((step) => [step.id, step.mode === 'multiple' ? step.options.filter((option) => !option.correct).map((option) => option.id) : [step.options.reduce((low, option) => ((option.points ?? 0) < (low.points ?? 0) ? option : low)).id]]),
      );
      expect(scoreAttempt(scenario, worst).total, scenario.id).toBeGreaterThanOrEqual(0);
    }
  });

  it('never gives full marks for selecting everything or nothing', async () => {
    for (const scenario of await all()) {
      for (const step of scenario.steps.filter((candidate) => candidate.mode === 'multiple')) {
        expect(scoreStep(step, step.options.map((option) => option.id)), `${scenario.id}/${step.id}`).toBeLessThan(step.points);
        expect(scoreStep(step, []), `${scenario.id}/${step.id}`).toBe(0);
      }
    }
  });

  it('ignores unknown option ids and multiple picks on single-choice steps', async () => {
    const scenario = (await loadScenario('ssh-bruteforce')) as Scenario;
    const single = scenario.steps.find((step) => step.mode === 'single') as Step;
    expect(scoreStep(single, ['not-an-option'])).toBe(0);
    expect(scoreStep(single, single.options.map((option) => option.id))).toBe(0);
  });

  it('is reproducible and reports escaped text', async () => {
    const scenario = (await loadScenario('ssh-bruteforce')) as Scenario;
    const answers: Answers = Object.fromEntries(scenario.steps.map((step) => [step.id, [step.options[0]?.id as string]]));
    const first = buildLabReport(scenario, answers, 'en', labels, '2026-01-01T00:00:00Z');
    const second = buildLabReport(scenario, answers, 'en', labels, '2026-01-01T00:00:00Z');
    expect(first).toBe(second);
    expect(first).toContain(`Score: ${scoreAttempt(scenario, answers).total} / ${scenarioMax(scenario)}`);
    expect(first).not.toMatch(/<(?!https:)/);
  });
});

describe('progress storage', () => {
  let database: BlackwatchDb;
  let sequence = 0;
  beforeEach(() => {
    sequence += 1;
    database = new BlackwatchDb(`blackwatch-lab-${sequence}`);
  });
  afterEach(async () => {
    await database.delete();
  });

  it('saves, reloads and clears an attempt with its scenario version', async () => {
    const progress = { ...emptyProgress(3), answers: { a: ['x'] } };
    expect(await saveProgress('s', progress, database)).toBe(true);
    expect(await loadProgress('s', database)).toEqual(progress);
    await clearProgress('s', database);
    expect(await loadProgress('s', database)).toBeNull();
  });

  it('refuses invalid progress and ignores corrupted records', async () => {
    expect(await saveProgress('s', { ...emptyProgress(1), scenarioVersion: 0 }, database)).toBe(false);
    await database.labProgress.put({ scenarioId: 'bad', data: { answers: 'nope' }, updatedAt: 'x' });
    expect(await loadProgress('bad', database)).toBeNull();
  });
});
