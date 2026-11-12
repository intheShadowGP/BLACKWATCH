import type { Scenario } from '../model';
import { DE_AE_03, mitigation, PR_PS_02, RS_AN_03, RS_AN_07, RS_MI_01, RS_MI_02 } from '../references';
import { iso, jsonLines } from './helpers';

const DAY = '2026-08-19';

const ids = jsonLines([
  { timestamp: iso(DAY, 3 * 3600 + 12 * 60), host: 'vpn-gw', src_ip: '203.0.113.17', severity: 'high', message: 'IDS: exploitation attempt against VPN appliance web portal (vendor advisory VA-2026-014, unpatched)' },
  { timestamp: iso(DAY, 3 * 3600 + 12 * 60 + 30), host: 'vpn-gw', src_ip: '203.0.113.17', severity: 'high', message: 'VPN appliance: new local administrator "support2" created via web portal' },
  { timestamp: iso(DAY, 3 * 3600 + 15 * 60), host: 'vpn-gw', src_ip: '203.0.113.17', user: 'support2', severity: 'medium', message: 'VPN session established, assigned address 172.16.200.9' },
  { timestamp: iso(DAY, 3 * 3600 + 17 * 60), host: 'core-fw', src_ip: '172.16.200.9', severity: 'medium', message: 'IDS: TCP SYN scan of 10.80.0.0/16, 4,096 hosts, ports 22,445,3389,5985 in 90 s' },
  { timestamp: iso(DAY, 3 * 3600 + 25 * 60), host: 'core-fw', src_ip: '172.16.200.9', severity: 'medium', message: 'allow tcp 172.16.200.9 -> 10.80.3.12:3389 (SRV-ERP01)' },
]);

const inventory = `Asset notes (fictitious)
- vpn-gw: VPN appliance, firmware 9.1.2. Vendor advisory VA-2026-014 (published 2026-08-05) fixes a remote code execution in the web portal in 9.1.4; update scheduled for "next maintenance window".
- VPN users get addresses in 172.16.200.0/24 and can reach every internal network.
- SRV-ERP01: ERP server, RDP enabled for administrators.`;

export const networkIntrusion: Scenario = {
  id: 'network-intrusion',
  version: 1,
  title: { en: 'Intrusion through an unpatched VPN appliance', fr: 'Intrusion via une appliance VPN non corrigée' },
  difficulty: 'advanced',
  minutes: 20,
  techniques: ['T1190', 'T1133', 'T1136.001', 'T1046', 'T1021.001'],
  context: {
    en: 'A logistics company (fictitious) gives remote staff a VPN appliance. An intrusion detection system watches the Internet edge and the core firewall.',
    fr: 'Une entreprise de logistique (fictive) fournit une appliance VPN au personnel distant. Un système de détection d’intrusion surveille la bordure Internet et le pare-feu central.',
  },
  incident: {
    en: 'Overnight, the IDS logs an exploitation attempt on the VPN portal, then an internal scan from a VPN address. The on-call engineer asks you to assess.',
    fr: 'Pendant la nuit, l’IDS journalise une tentative d’exploitation du portail VPN, puis un balayage interne depuis une adresse VPN. L’astreinte vous demande d’évaluer la situation.',
  },
  evidence: [
    { id: 'ids', kind: 'alert', title: { en: 'IDS and firewall events (JSON Lines)', fr: 'Événements IDS et pare-feu (JSON Lines)' }, content: ids, logFormat: 'json' },
    { id: 'inventory', kind: 'note', title: { en: 'Asset notes', fr: 'Notes sur les équipements' }, content: inventory },
  ],
  steps: [
    {
      id: 'sequence',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['ids', 'inventory'],
      references: [DE_AE_03, RS_AN_03],
      prompt: { en: 'Which steps are supported by the evidence?', fr: 'Quelles étapes les éléments étayent-ils ?' },
      options: [
        { id: 'exploit', correct: true, text: { en: 'Exploitation of a known, unpatched flaw in the VPN portal.', fr: 'Exploitation d’une faille connue et non corrigée du portail VPN.' }, feedback: { en: 'The firmware is below the fixed version of the advisory.', fr: 'Le micrologiciel est antérieur à la version corrigée de l’avis.' } },
        { id: 'account', correct: true, text: { en: 'Creation of a local administrator on the appliance, then a VPN session with it.', fr: 'Création d’un administrateur local sur l’appliance, puis une session VPN avec celui-ci.' }, feedback: { en: 'The attacker turned the exploit into a valid access.', fr: 'L’attaquant a transformé l’exploitation en accès valide.' } },
        { id: 'scan', correct: true, text: { en: 'An internal scan and an RDP connection to the ERP server.', fr: 'Un balayage interne et une connexion RDP au serveur ERP.' }, feedback: { en: 'Discovery, then movement toward a business-critical server.', fr: 'Reconnaissance, puis déplacement vers un serveur critique.' } },
        { id: 'blocked', correct: false, text: { en: 'The IDS blocked the attack, so nothing got in.', fr: 'L’IDS a bloqué l’attaque, donc rien n’est entré.' }, feedback: { en: 'The IDS detects; the following events show the attacker inside.', fr: 'L’IDS détecte ; les événements suivants montrent l’attaquant à l’intérieur.' } },
      ],
    },
    {
      id: 'decide',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['ids'],
      references: [RS_MI_01],
      prompt: { en: 'Remote staff depend on the VPN. What do you decide?', fr: 'Le personnel distant dépend du VPN. Que décidez-vous ?' },
      options: [
        { id: 'cut', points: 10, text: { en: 'Take the VPN offline (or block its portal from the Internet) until it is patched and rebuilt, and arrange a temporary access method for staff.', fr: 'Mettre le VPN hors ligne (ou bloquer son portail depuis Internet) jusqu’à sa correction et sa reconstruction, et prévoir un accès temporaire pour le personnel.' }, feedback: { en: 'The appliance is compromised; leaving it up leaves the door open.', fr: 'L’appliance est compromise ; la laisser en service laisse la porte ouverte.' } },
        { id: 'delete-user', points: 4, text: { en: 'Delete "support2" and keep the VPN running until the maintenance window.', fr: 'Supprimer « support2 » et garder le VPN en service jusqu’à la fenêtre de maintenance.' }, feedback: { en: 'The flaw can be exploited again in minutes.', fr: 'La faille peut être réexploitée en quelques minutes.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['ids', 'inventory'],
      references: [RS_MI_01, RS_AN_07],
      prompt: { en: 'Which containment actions do you take inside the network?', fr: 'Quelles actions de confinement prenez-vous dans le réseau ?' },
      options: [
        { id: 'erp', correct: true, text: { en: 'Isolate SRV-ERP01 for analysis and check RDP logons on it.', fr: 'Isoler SRV-ERP01 pour analyse et vérifier les connexions RDP.' }, feedback: { en: 'The attacker reached it.', fr: 'L’attaquant l’a atteint.' } },
        { id: 'preserve', correct: true, text: { en: 'Preserve the appliance configuration and logs before patching or rebuilding it.', fr: 'Conserver la configuration et les journaux de l’appliance avant de la corriger ou de la reconstruire.' }, feedback: { en: 'Patching may erase traces of the exploit.', fr: 'La correction peut effacer les traces de l’exploitation.' } },
        { id: 'creds', correct: true, text: { en: 'Reset credentials stored on or used through the appliance.', fr: 'Réinitialiser les identifiants stockés sur l’appliance ou utilisés à travers elle.' }, feedback: { en: 'Assume what the appliance saw is known to the attacker.', fr: 'Considérez comme connu de l’attaquant ce que l’appliance a vu.' } },
        { id: 'block-only', correct: false, text: { en: 'Only block 203.0.113.17 and close the case.', fr: 'Bloquer seulement 203.0.113.17 et clore le dossier.' }, feedback: { en: 'The attacker can use another address and is already inside.', fr: 'L’attaquant peut utiliser une autre adresse et est déjà à l’intérieur.' } },
      ],
    },
    {
      id: 'scope',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['ids'],
      references: [RS_AN_03],
      prompt: { en: 'What else do you check?', fr: 'Que vérifiez-vous d’autre ?' },
      options: [
        { id: 'all-vpn', points: 10, text: { en: 'All activity from 172.16.200.9 and from "support2", and any other new accounts on the appliance since the advisory was published.', fr: 'Toute l’activité de 172.16.200.9 et de « support2 », et tout autre compte créé sur l’appliance depuis la publication de l’avis.' }, feedback: { en: 'The flaw was public for two weeks: earlier intrusions are possible.', fr: 'La faille était publique depuis deux semaines : des intrusions antérieures sont possibles.' } },
        { id: 'only-tonight', points: 3, text: { en: 'Only tonight’s alerts.', fr: 'Uniquement les alertes de cette nuit.' }, feedback: { en: 'Too narrow for a two-week exposure.', fr: 'Trop restreint pour une exposition de deux semaines.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['inventory'],
      references: [RS_MI_02, PR_PS_02, mitigation('M1051', 'Update Software'), mitigation('M1030', 'Network Segmentation'), mitigation('M1032', 'Multi-factor Authentication')],
      prompt: { en: 'Which measures prevent a repeat?', fr: 'Quelles mesures empêchent une récidive ?' },
      options: [
        { id: 'patch-fast', correct: true, text: { en: 'Patch Internet-facing devices on a short deadline after a critical advisory, not at the next window.', fr: 'Corriger les équipements exposés à Internet dans un délai court après un avis critique, pas à la prochaine fenêtre.' }, feedback: { en: 'Exposed devices with public flaws are exploited within days.', fr: 'Les équipements exposés avec une faille publique sont exploités en quelques jours.' } },
        { id: 'segment', correct: true, text: { en: 'Limit what VPN users can reach to the services they need.', fr: 'Limiter ce que les utilisateurs VPN peuvent atteindre aux services nécessaires.' }, feedback: { en: 'A full /16 was reachable from the VPN pool.', fr: 'Tout un /16 était joignable depuis la plage VPN.' } },
        { id: 'mfa', correct: true, text: { en: 'Require multi-factor authentication for VPN and administrator access.', fr: 'Exiger une authentification multifacteur pour le VPN et les accès administrateur.' }, feedback: { en: 'Raises the bar for using created or stolen accounts.', fr: 'Complique l’usage de comptes créés ou volés.' } },
        { id: 'ids-only', correct: false, text: { en: 'Rely on the IDS to block future attempts.', fr: 'Compter sur l’IDS pour bloquer les tentatives futures.' }, feedback: { en: 'It detected but did not prevent this intrusion.', fr: 'Il a détecté mais n’a pas empêché cette intrusion.' } },
      ],
    },
  ],
  debrief: {
    en: 'An attacker exploited a published flaw in the unpatched VPN portal, created an administrator on the appliance, connected through the VPN and scanned the internal network before opening RDP on the ERP server. Taking the VPN offline, preserving evidence and isolating the ERP server contained it; fast patching of exposed devices and VPN segmentation prevent a repeat.',
    fr: 'Un attaquant a exploité une faille publiée du portail VPN non corrigé, créé un administrateur sur l’appliance, s’est connecté via le VPN et a balayé le réseau interne avant d’ouvrir une session RDP sur le serveur ERP. Mettre le VPN hors ligne, préserver les preuves et isoler le serveur ERP ont contenu l’attaque ; la correction rapide des équipements exposés et la segmentation du VPN empêchent une récidive.',
  },
  lessons: [
    { en: 'Internet-facing devices with public critical flaws cannot wait for the next maintenance window.', fr: 'Les équipements exposés à Internet présentant une faille critique publique ne peuvent pas attendre la prochaine fenêtre de maintenance.' },
    { en: 'An IDS alert is the start of an investigation, not proof of prevention.', fr: 'Une alerte IDS est le début d’une investigation, pas la preuve d’un blocage.' },
  ],
};
