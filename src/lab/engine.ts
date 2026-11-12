// Deterministic scoring and reporting for Cyber Lab attempts. No randomness,
// no time-based points: the same answers always give the same score.

import { fence, inline } from '../soc/lib/report';
import type { Localized, Scenario, Step } from './model';

export type Answers = Record<string, string[]>;

export interface StepScore {
  stepId: string;
  points: number;
  max: number;
}

export function stepMax(step: Step): number {
  return step.points;
}

/**
 * Single choice: the points of the chosen option.
 * Multiple selection: (correct chosen − incorrect chosen) / correct options × points,
 * floored at zero and rounded, so selecting everything or nothing never earns full marks.
 */
export function scoreStep(step: Step, selected: readonly string[]): number {
  const chosen = new Set(selected.filter((id) => step.options.some((option) => option.id === id)));
  if (step.mode === 'single') {
    if (chosen.size !== 1) return 0;
    const option = step.options.find((candidate) => chosen.has(candidate.id));
    return Math.max(0, Math.min(step.points, option?.points ?? 0));
  }
  const correct = step.options.filter((option) => option.correct).length;
  if (correct === 0) return 0;
  let right = 0;
  let wrong = 0;
  for (const option of step.options) {
    if (!chosen.has(option.id)) continue;
    if (option.correct) right += 1;
    else wrong += 1;
  }
  return Math.max(0, Math.round(((right - wrong) / correct) * step.points));
}

export function scenarioMax(scenario: Scenario): number {
  return scenario.steps.reduce((total, step) => total + stepMax(step), 0);
}

export function scoreAttempt(scenario: Scenario, answers: Answers): { total: number; max: number; steps: StepScore[] } {
  const steps = scenario.steps.map((step) => ({ stepId: step.id, points: answers[step.id] ? scoreStep(step, answers[step.id] as string[]) : 0, max: stepMax(step) }));
  return { total: steps.reduce((sum, step) => sum + step.points, 0), max: scenarioMax(scenario), steps };
}

/** The answer that earns the most points: the best single option, or every correct option. */
export function bestAnswer(step: Step): string[] {
  if (step.mode === 'multiple') return step.options.filter((option) => option.correct).map((option) => option.id);
  const best = step.options.reduce((top, option) => ((option.points ?? 0) > (top.points ?? 0) ? option : top));
  return [best.id];
}

export type Language = keyof Localized;

export interface ReportLabels {
  kind: (kind: Step['kind']) => string;
  yourAnswer: string;
  bestAnswer: string;
  score: string;
  context: string;
  debrief: string;
  lessons: string;
  references: string;
  syntheticNote: string;
}

/** Markdown report of an attempt. Text is escaped and quoted options fenced, as in SOC reports. */
export function buildLabReport(scenario: Scenario, answers: Answers, language: Language, labels: ReportLabels, completedAt: string): string {
  const { total, max, steps } = scoreAttempt(scenario, answers);
  const text = (value: Localized) => value[language];
  const out: string[] = [];
  out.push(`# ${inline(text(scenario.title))}`, '');
  out.push(`${labels.score}: ${total} / ${max} · ${completedAt} · v${scenario.version}`, '');
  out.push(`## ${labels.context}`, '', fence(`${text(scenario.context)}\n\n${text(scenario.incident)}`), '');
  scenario.steps.forEach((step, index) => {
    const chosen = answers[step.id] ?? [];
    const label = (ids: readonly string[]) => ids.map((id) => step.options.find((option) => option.id === id)).filter((option) => option !== undefined).map((option) => `- ${text(option.text)}`).join('\n') || '-';
    out.push(`## ${index + 1}. ${inline(labels.kind(step.kind))} (${steps[index]?.points ?? 0} / ${step.points})`, '');
    out.push(fence(text(step.prompt)), '');
    out.push(`${labels.yourAnswer}:`, '', fence(label(chosen)), '');
    out.push(`${labels.bestAnswer}:`, '', fence(label(bestAnswer(step))), '');
    const feedback = step.options.filter((option) => chosen.includes(option.id)).map((option) => text(option.feedback)).join('\n');
    if (feedback) out.push(fence(feedback), '');
    if (step.references.length > 0) out.push(`${labels.references}: ${step.references.map((reference) => `${inline(reference.label)} <${reference.url}>`).join(' · ')}`, '');
  });
  out.push(`## ${labels.debrief}`, '', fence(text(scenario.debrief)), '');
  out.push(`## ${labels.lessons}`, '', ...scenario.lessons.map((lesson) => `- ${inline(text(lesson))}`), '');
  out.push('---', labels.syntheticNote, '');
  return out.join('\n');
}
