// Cyber Lab scenario model. Scenarios are synthetic, educational exercises:
// no step executes anything, and all evidence is invented.

/** Text in both interface languages. */
export interface Localized {
  en: string;
  fr: string;
}

export type StepKind = 'investigation' | 'decision' | 'containment' | 'remediation';

export interface Reference {
  label: string;
  url: string;
}

export interface Option {
  id: string;
  text: Localized;
  /**
   * Single-choice steps: points awarded when this option is chosen (0 to the step's points).
   * Partial credit expresses options that practitioners consider acceptable but not best.
   */
  points?: number;
  /** Multi-select steps: whether the option belongs in the answer. */
  correct?: boolean;
  feedback: Localized;
}

export interface Step {
  id: string;
  kind: StepKind;
  prompt: Localized;
  /** Single choice (one option) or multiple selection. */
  mode: 'single' | 'multiple';
  points: number;
  options: Option[];
  /** Evidence items the learner should look at. */
  evidence: string[];
  /** Public guidance supporting the answer key. */
  references: Reference[];
}

export type EvidenceKind = 'log' | 'email' | 'alert' | 'process' | 'network' | 'file' | 'note' | 'config';

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  title: Localized;
  /** Synthetic artefact, shown as text. */
  content: string;
  /** Format the SOC parsers should read this artefact as, when it is a log. */
  logFormat?: 'syslog' | 'webAccess' | 'windowsXml' | 'json';
}

export type Difficulty = 'introductory' | 'intermediate' | 'advanced';

export interface ScenarioSummary {
  id: string;
  /** Increased whenever questions or scoring change; stored with each attempt. */
  version: number;
  title: Localized;
  difficulty: Difficulty;
  minutes: number;
  /** MITRE ATT&CK techniques illustrated by the scenario. */
  techniques: string[];
}

export interface Scenario extends ScenarioSummary {
  context: Localized;
  incident: Localized;
  evidence: Evidence[];
  steps: Step[];
  /** What happened, revealed in the final report. */
  debrief: Localized;
  lessons: Localized[];
}
