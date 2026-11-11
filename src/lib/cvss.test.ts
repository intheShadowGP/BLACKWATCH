import { describe, expect, it } from 'vitest';
import { computeCvss3BaseScore, decodeVector, severityFromScore } from './cvss';

describe('computeCvss3BaseScore', () => {
  // Reference values from the FIRST CVSS 3.1 calculator.
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s -> %s', (vector, expected) => {
    expect(computeCvss3BaseScore(vector)).toBe(expected);
  });

  it('ignores temporal metrics appended to the vector', () => {
    expect(computeCvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C')).toBe(9.8);
  });

  it.each([
    '',
    'not a vector',
    'CVSS:3.1/AV:N/AC:L',
    'CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P',
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    `CVSS:3.1/${'AV:N/'.repeat(200)}`,
  ])('returns null for %j', (vector) => {
    expect(computeCvss3BaseScore(vector)).toBeNull();
  });
});

describe('decodeVector', () => {
  it('names the base metrics of a 3.1 vector', () => {
    const decoded = decodeVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
    expect(decoded?.version).toBe('3.1');
    expect(decoded?.base).toHaveLength(8);
    expect(decoded?.base[0]).toEqual({ metric: 'AV', value: 'N', metricName: 'Attack Vector', valueName: 'Network' });
  });

  it('decodes a 4.0 vector and counts defined supplemental metrics', () => {
    const decoded = decodeVector('CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:X/V:D/U:Amber');
    expect(decoded?.version).toBe('4.0');
    expect(decoded?.base).toHaveLength(11);
    expect(decoded?.extraMetrics).toBe(3);
  });

  it('rejects a 4.0 vector with a missing base metric', () => {
    expect(decodeVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N')).toBeNull();
  });

  it('rejects non-string input', () => {
    expect(decodeVector(undefined as unknown as string)).toBeNull();
  });
});

describe('severityFromScore', () => {
  it.each([[0, 'NONE'], [0.1, 'LOW'], [3.9, 'LOW'], [4, 'MEDIUM'], [6.9, 'MEDIUM'], [7, 'HIGH'], [8.9, 'HIGH'], [9, 'CRITICAL'], [10, 'CRITICAL']])(
    '%s -> %s',
    (score, severity) => {
      expect(severityFromScore(score)).toBe(severity);
    },
  );
});
