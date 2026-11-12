// Scenario catalogue. The list page only needs these summaries; each scenario
// body is a separate chunk loaded when the scenario is opened. A test checks
// that every summary matches its scenario.

import type { Scenario, ScenarioSummary } from './model';

export const CATALOG: readonly ScenarioSummary[] = [
  { id: 'ssh-bruteforce', version: 1, title: { en: 'SSH brute force on a database server', fr: 'Force brute SSH sur un serveur de base de données' }, difficulty: 'introductory', minutes: 15, techniques: ['T1110.001', 'T1078', 'T1136.001'] },
  { id: 'phishing', version: 1, title: { en: 'Credential phishing in a law firm', fr: 'Hameçonnage d’identifiants dans un cabinet d’avocats' }, difficulty: 'introductory', minutes: 15, techniques: ['T1566.002', 'T1078', 'T1114'] },
  { id: 'ransomware', version: 1, title: { en: 'Ransomware on file servers', fr: 'Rançongiciel sur des serveurs de fichiers' }, difficulty: 'intermediate', minutes: 20, techniques: ['T1486', 'T1490', 'T1078'] },
  { id: 'lateral-movement', version: 1, title: { en: 'Lateral movement with a shared local administrator', fr: 'Mouvement latéral avec un administrateur local partagé' }, difficulty: 'intermediate', minutes: 20, techniques: ['T1078', 'T1550.002', 'T1021.002'] },
  { id: 'powershell', version: 1, title: { en: 'Suspicious PowerShell launched by a document', fr: 'PowerShell suspect lancé par un document' }, difficulty: 'intermediate', minutes: 15, techniques: ['T1566.001', 'T1204.002', 'T1059.001', 'T1027', 'T1105', 'T1071.001'] },
  { id: 'web-compromise', version: 1, title: { en: 'Web shell through an avatar upload', fr: 'Web shell via le téléversement d’un avatar' }, difficulty: 'intermediate', minutes: 20, techniques: ['T1190', 'T1505.003'] },
  { id: 'account-compromise', version: 1, title: { en: 'Account takeover by push fatigue', fr: 'Prise de contrôle de compte par fatigue des notifications' }, difficulty: 'intermediate', minutes: 15, techniques: ['T1078.004', 'T1621', 'T1114', 'T1530'] },
  { id: 'exfiltration', version: 1, title: { en: 'Night-time data exfiltration from an engineering server', fr: 'Exfiltration nocturne depuis un serveur d’ingénierie' }, difficulty: 'advanced', minutes: 20, techniques: ['T1567.002', 'T1213'] },
  { id: 'ad-misconfiguration', version: 1, title: { en: 'Kerberoasting and an over-privileged service account', fr: 'Kerberoasting et compte de service surprivilégié' }, difficulty: 'advanced', minutes: 20, techniques: ['T1558.003', 'T1078'] },
  { id: 'network-intrusion', version: 1, title: { en: 'Intrusion through an unpatched VPN appliance', fr: 'Intrusion via une appliance VPN non corrigée' }, difficulty: 'advanced', minutes: 20, techniques: ['T1190', 'T1133', 'T1136.001', 'T1046', 'T1021.001'] },
];

const LOADERS: Record<string, () => Promise<Scenario>> = {
  'ssh-bruteforce': async () => (await import('./scenarios/ssh-bruteforce')).sshBruteforce,
  phishing: async () => (await import('./scenarios/phishing')).phishing,
  ransomware: async () => (await import('./scenarios/ransomware')).ransomware,
  'lateral-movement': async () => (await import('./scenarios/lateral-movement')).lateralMovement,
  powershell: async () => (await import('./scenarios/powershell')).powershell,
  'web-compromise': async () => (await import('./scenarios/web-compromise')).webCompromise,
  'account-compromise': async () => (await import('./scenarios/account-compromise')).accountCompromise,
  exfiltration: async () => (await import('./scenarios/exfiltration')).exfiltration,
  'ad-misconfiguration': async () => (await import('./scenarios/ad-misconfiguration')).adMisconfiguration,
  'network-intrusion': async () => (await import('./scenarios/network-intrusion')).networkIntrusion,
};

export async function loadScenario(id: string): Promise<Scenario | null> {
  const loader = LOADERS[id];
  return loader ? loader() : null;
}

export const SCENARIO_IDS = Object.keys(LOADERS);
