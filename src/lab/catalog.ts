// Scenario catalogue. The list page only needs these summaries; each scenario
// body is a separate chunk loaded when the scenario is opened.

import type { Scenario, ScenarioSummary } from './model';

export const CATALOG: readonly ScenarioSummary[] = [
  { id: 'ssh-bruteforce', version: 1, title: { en: 'SSH brute force on a database server', fr: 'Force brute SSH sur un serveur de base de données' }, difficulty: 'introductory', minutes: 15, techniques: ['T1110.001', 'T1078', 'T1136.001'] },
];

const LOADERS: Record<string, () => Promise<Scenario>> = {
  'ssh-bruteforce': async () => (await import('./scenarios/ssh-bruteforce')).sshBruteforce,
};

export async function loadScenario(id: string): Promise<Scenario | null> {
  const loader = LOADERS[id];
  return loader ? loader() : null;
}

export const SCENARIO_IDS = Object.keys(LOADERS);
