import type { Scenario } from '../model';
import { DE_AE_03, mitigation, PR_AA_05, RS_AN_03, RS_MI_01, RS_MI_02 } from '../references';
import { iso, windowsEvent, windowsExport } from './helpers';

const DAY = '2026-06-11';
const logon = (seconds: number, target: string) =>
  windowsEvent(4624, iso(DAY, seconds), target, { SubjectUserName: '-', TargetUserName: 'localadmin', TargetDomainName: target, LogonType: '3', AuthenticationPackageName: 'NTLM', WorkstationName: 'WKS-117', IpAddress: '10.30.8.117', IpPort: '0' });

const events = windowsExport([
  windowsEvent(4624, iso(DAY, 14 * 3600 + 2 * 60), 'WKS-117', { TargetUserName: 'j.durand', TargetDomainName: 'CORP', LogonType: '2', AuthenticationPackageName: 'Kerberos', IpAddress: '-', IpPort: '-' }),
  logon(14 * 3600 + 31 * 60, 'SRV-HR01'),
  logon(14 * 3600 + 31 * 60 + 40, 'SRV-FIN02'),
  logon(14 * 3600 + 32 * 60 + 15, 'SRV-APP03'),
  logon(14 * 3600 + 32 * 60 + 50, 'SRV-HR02'),
  windowsEvent(4688, iso(DAY, 14 * 3600 + 33 * 60), 'SRV-FIN02', { SubjectUserName: 'localadmin', NewProcessName: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'cmd.exe /c dir \\\\SRV-FIN02\\Finance$ /s > C:\\Windows\\Temp\\list.txt', ParentProcessName: 'C:\\Windows\\System32\\services.exe' }),
]);

const inventory = `Workstation build notes (fictitious)
- All workstations and servers are deployed from the same image.
- The local account "localadmin" has the same password on every machine (set in the image in 2023).
- WKS-117: assigned to j.durand (accounting); a support ticket mentions a "free PDF converter" installed on 2026-06-10.`;

export const lateralMovement: Scenario = {
  id: 'lateral-movement',
  version: 1,
  title: { en: 'Lateral movement with a shared local administrator', fr: 'Mouvement latéral avec un administrateur local partagé' },
  difficulty: 'intermediate',
  minutes: 20,
  techniques: ['T1078', 'T1550.002', 'T1021.002'],
  context: {
    en: 'A mid-sized company (fictitious) deploys every Windows machine from one image. Security events of servers are collected centrally.',
    fr: 'Une entreprise de taille moyenne (fictive) déploie toutes ses machines Windows à partir d’une même image. Les événements de sécurité des serveurs sont centralisés.',
  },
  incident: {
    en: 'A correlation rule flags network logons with the local account "localadmin" on four servers in two minutes, all from the workstation WKS-117.',
    fr: 'Une règle de corrélation signale des connexions réseau avec le compte local « localadmin » sur quatre serveurs en deux minutes, toutes depuis le poste WKS-117.',
  },
  evidence: [
    { id: 'events', kind: 'log', title: { en: 'Windows Security events (XML export)', fr: 'Événements de sécurité Windows (export XML)' }, content: events, logFormat: 'windowsXml' },
    { id: 'inventory', kind: 'note', title: { en: 'Build and inventory notes', fr: 'Notes de déploiement et d’inventaire' }, content: inventory },
  ],
  steps: [
    {
      id: 'pattern',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['events'],
      references: [DE_AE_03, RS_AN_03],
      prompt: { en: 'What does the sequence show?', fr: 'Que montre la séquence ?' },
      options: [
        { id: 'fanout', correct: true, text: { en: 'One source (10.30.8.117) logging on to many servers with the same local account in a short time.', fr: 'Une source (10.30.8.117) qui se connecte à de nombreux serveurs avec le même compte local en peu de temps.' }, feedback: { en: 'Administrators rarely use a local account across servers; this is a lateral movement pattern.', fr: 'Les administrateurs utilisent rarement un compte local sur plusieurs serveurs ; c’est un schéma de mouvement latéral.' } },
        { id: 'ntlm', correct: true, text: { en: 'NTLM network logons, consistent with reuse of a password or its hash.', fr: 'Des connexions réseau NTLM, compatibles avec la réutilisation d’un mot de passe ou de son empreinte.' }, feedback: { en: 'A shared local password lets one stolen hash open every machine.', fr: 'Un mot de passe local partagé permet à une seule empreinte volée d’ouvrir toutes les machines.' } },
        { id: 'finance', correct: true, text: { en: 'On SRV-FIN02 the session listed the Finance share.', fr: 'Sur SRV-FIN02, la session a listé le partage Finance.' }, feedback: { en: 'Discovery of data of interest.', fr: 'Recherche de données intéressantes.' } },
        { id: 'jdupont', correct: false, text: { en: 'j.durand logged on to the servers.', fr: 'j.durand s’est connecté aux serveurs.' }, feedback: { en: 'j.durand only has an interactive logon on WKS-117; the server logons use localadmin.', fr: 'j.durand n’a qu’une ouverture de session interactive sur WKS-117 ; les connexions aux serveurs utilisent localadmin.' } },
      ],
    },
    {
      id: 'patient-zero',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['inventory'],
      references: [RS_AN_03],
      prompt: { en: 'What is the most likely origin?', fr: 'Quelle est l’origine la plus probable ?' },
      options: [
        { id: 'pdf', points: 10, text: { en: 'The "free PDF converter" installed on WKS-117 the day before.', fr: 'Le « convertisseur PDF gratuit » installé sur WKS-117 la veille.' }, feedback: { en: 'An unvetted program run by the user is a plausible foothold; examine the workstation.', fr: 'Un programme non vérifié lancé par l’utilisateur est un point d’entrée plausible ; examinez le poste.' } },
        { id: 'servers', points: 0, text: { en: 'One of the servers attacked WKS-117.', fr: 'Un des serveurs a attaqué WKS-117.' }, feedback: { en: 'The connections go from WKS-117 to the servers.', fr: 'Les connexions vont de WKS-117 vers les serveurs.' } },
      ],
    },
    {
      id: 'decide',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['events'],
      references: [RS_MI_01],
      prompt: { en: 'What do you decide?', fr: 'Que décidez-vous ?' },
      options: [
        { id: 'incident', points: 10, text: { en: 'Open an incident and treat every machine sharing the password as potentially exposed.', fr: 'Ouvrir un incident et considérer chaque machine partageant le mot de passe comme potentiellement exposée.' }, feedback: { en: 'The shared password makes the scope the whole estate.', fr: 'Le mot de passe partagé étend le périmètre à tout le parc.' } },
        { id: 'admin', points: 2, text: { en: 'Ask around whether an administrator did this before acting.', fr: 'Demander si un administrateur est à l’origine avant d’agir.' }, feedback: { en: 'Worth checking, but in parallel with containment: the pattern and the share listing are strong signals.', fr: 'À vérifier, mais en parallèle du confinement : le schéma et le listage du partage sont des signaux forts.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['events', 'inventory'],
      references: [RS_MI_01],
      prompt: { en: 'Which containment actions do you take?', fr: 'Quelles actions de confinement prenez-vous ?' },
      options: [
        { id: 'isolate', correct: true, text: { en: 'Isolate WKS-117 from the network, keeping it on for analysis.', fr: 'Isoler WKS-117 du réseau en le laissant allumé pour l’analyse.' }, feedback: { en: 'Cuts the source of the movement.', fr: 'Coupe la source du mouvement.' } },
        { id: 'disable', correct: true, text: { en: 'Disable or change the localadmin password on every machine.', fr: 'Désactiver ou changer le mot de passe de localadmin sur toutes les machines.' }, feedback: { en: 'Otherwise the stolen credential keeps working everywhere.', fr: 'Sinon, l’identifiant volé reste valable partout.' } },
        { id: 'block-445', correct: true, text: { en: 'Temporarily block workstation-to-server administration ports (SMB, RPC) except from administration hosts.', fr: 'Bloquer temporairement les ports d’administration (SMB, RPC) des postes vers les serveurs, sauf depuis les postes d’administration.' }, feedback: { en: 'Limits further movement while the rest is fixed.', fr: 'Limite d’autres mouvements le temps de corriger le reste.' } },
        { id: 'delete-logs', correct: false, text: { en: 'Clear the server security logs to start fresh.', fr: 'Effacer les journaux de sécurité des serveurs pour repartir de zéro.' }, feedback: { en: 'Destroys the evidence of what was accessed.', fr: 'Détruit la preuve de ce qui a été consulté.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['inventory'],
      references: [RS_MI_02, PR_AA_05, mitigation('M1027', 'Password Policies'), mitigation('M1026', 'Privileged Account Management'), mitigation('M1030', 'Network Segmentation')],
      prompt: { en: 'Which remediation measures address the root cause?', fr: 'Quelles mesures de remédiation traitent la cause profonde ?' },
      options: [
        { id: 'unique', correct: true, text: { en: 'Give each machine a unique, automatically rotated local administrator password.', fr: 'Donner à chaque machine un mot de passe administrateur local unique et renouvelé automatiquement.' }, feedback: { en: 'Removes the single key that opened every machine.', fr: 'Supprime la clé unique qui ouvrait toutes les machines.' } },
        { id: 'deny-network', correct: true, text: { en: 'Deny network logon to local accounts on servers.', fr: 'Interdire les connexions réseau aux comptes locaux sur les serveurs.' }, feedback: { en: 'Local accounts should not be usable remotely.', fr: 'Les comptes locaux ne doivent pas être utilisables à distance.' } },
        { id: 'software', correct: true, text: { en: 'Restrict software installation on workstations to an approved catalogue.', fr: 'Limiter l’installation de logiciels sur les postes à un catalogue approuvé.' }, feedback: { en: 'Addresses the probable entry point.', fr: 'Traite le point d’entrée probable.' } },
        { id: 'longer', correct: false, text: { en: 'Make the shared password longer and keep it shared.', fr: 'Allonger le mot de passe partagé en le gardant commun.' }, feedback: { en: 'A hash can be reused regardless of length; sharing is the problem.', fr: 'Une empreinte se réutilise quelle que soit la longueur ; c’est le partage qui pose problème.' } },
      ],
    },
  ],
  debrief: {
    en: 'A trojanised utility gave an attacker control of WKS-117. The local administrator password, identical on every machine, let the attacker log on to four servers over NTLM within two minutes and list the Finance share. Unique local passwords and a ban on remote use of local accounts close this path.',
    fr: 'Un utilitaire piégé a donné à un attaquant le contrôle de WKS-117. Le mot de passe administrateur local, identique sur toutes les machines, lui a permis de se connecter à quatre serveurs en NTLM en deux minutes et de lister le partage Finance. Des mots de passe locaux uniques et l’interdiction d’utiliser les comptes locaux à distance ferment ce chemin.',
  },
  lessons: [
    { en: 'One shared local password turns one compromised workstation into many compromised servers.', fr: 'Un mot de passe local partagé transforme un poste compromis en de nombreux serveurs compromis.' },
    { en: 'Correlate logons by source and account across machines, not machine by machine.', fr: 'Corrélez les connexions par source et par compte sur l’ensemble des machines, pas machine par machine.' },
  ],
};
