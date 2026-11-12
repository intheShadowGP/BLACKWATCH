import type { Scenario } from '../model';
import { DE_AE_02, mitigation, PR_AA_05, RS_AN_03, RS_MI_01, RS_MI_02 } from '../references';
import { iso, windowsEvent, windowsExport } from './helpers';

const DAY = '2026-03-23';
const tgs = (seconds: number, service: string) =>
  windowsEvent(4769, iso(DAY, seconds), 'DC01.corp.example', { TargetUserName: 'w.perrin@CORP.EXAMPLE', ServiceName: service, TicketEncryptionType: '0x17', IpAddress: '::ffff:10.70.4.66', Status: '0x0' });

const events = windowsExport([
  tgs(15 * 3600, 'svc-sql'),
  tgs(15 * 3600 + 1, 'svc-backup'),
  tgs(15 * 3600 + 1, 'svc-report'),
  tgs(15 * 3600 + 2, 'svc-intranet'),
  tgs(15 * 3600 + 2, 'svc-print'),
  tgs(15 * 3600 + 3, 'svc-crm'),
]);

const config = `Directory review extract (fictitious)
Account        Has SPN  Member of                 Password last set   Kerberos encryption
svc-sql        yes      Domain Admins             2019-02-11          RC4 allowed
svc-backup     yes      Backup Operators          2021-07-30          RC4 allowed
svc-report     yes      Domain Users              2024-01-12          AES only
svc-intranet   yes      Domain Users              2025-11-02          AES only
w.perrin       no       Domain Users (Marketing)  2026-01-04          -

Note: svc-sql password is 9 characters and was set by the original installer.`;

export const adMisconfiguration: Scenario = {
  id: 'ad-misconfiguration',
  version: 1,
  title: { en: 'Kerberoasting and an over-privileged service account', fr: 'Kerberoasting et compte de service surprivilégié' },
  difficulty: 'advanced',
  minutes: 20,
  techniques: ['T1558.003', 'T1078'],
  context: {
    en: 'A company (fictitious) runs an Active Directory domain, corp.example. Several service accounts have service principal names (SPNs). Domain controller security events are collected.',
    fr: 'Une entreprise (fictive) exploite un domaine Active Directory, corp.example. Plusieurs comptes de service ont des noms principaux de service (SPN). Les événements de sécurité des contrôleurs de domaine sont collectés.',
  },
  incident: {
    en: 'A detection fires: one user requested Kerberos service tickets for six different services within three seconds, with RC4 encryption.',
    fr: 'Une détection se déclenche : un utilisateur a demandé des tickets de service Kerberos pour six services différents en trois secondes, avec un chiffrement RC4.',
  },
  evidence: [
    { id: 'tgs', kind: 'log', title: { en: 'Domain controller events 4769 (XML export)', fr: 'Événements 4769 du contrôleur de domaine (export XML)' }, content: events, logFormat: 'windowsXml' },
    { id: 'config', kind: 'config', title: { en: 'Service account review', fr: 'Revue des comptes de service' }, content: config },
  ],
  steps: [
    {
      id: 'recognise',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['tgs'],
      references: [DE_AE_02],
      prompt: { en: 'What does the burst of 4769 events indicate?', fr: 'Qu’indique la rafale d’événements 4769 ?' },
      options: [
        { id: 'kerberoast', points: 10, text: { en: 'Ticket harvesting to crack service account passwords offline (Kerberoasting).', fr: 'Une collecte de tickets pour casser hors ligne les mots de passe des comptes de service (Kerberoasting).' }, feedback: { en: 'Any user can request these tickets; RC4 ones are fastest to crack.', fr: 'Tout utilisateur peut demander ces tickets ; ceux en RC4 se cassent le plus vite.' } },
        { id: 'normal', points: 2, text: { en: 'Normal activity of a marketing user.', fr: 'L’activité normale d’un utilisateur du marketing.' }, feedback: { en: 'A marketing user does not need six services in three seconds.', fr: 'Un utilisateur du marketing n’a pas besoin de six services en trois secondes.' } },
      ],
    },
    {
      id: 'risk',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['config'],
      references: [RS_AN_03, PR_AA_05],
      prompt: { en: 'Which findings of the review make the situation critical?', fr: 'Quels constats de la revue rendent la situation critique ?' },
      options: [
        { id: 'da', correct: true, text: { en: 'svc-sql is a Domain Admin.', fr: 'svc-sql est administrateur du domaine.' }, feedback: { en: 'Cracking its password gives control of the whole domain.', fr: 'Casser son mot de passe donne le contrôle de tout le domaine.' } },
        { id: 'weak', correct: true, text: { en: 'Its password is short, old, and RC4 is allowed.', fr: 'Son mot de passe est court, ancien, et RC4 est autorisé.' }, feedback: { en: 'A 9-character password with RC4 can be cracked quickly.', fr: 'Un mot de passe de 9 caractères avec RC4 se casse rapidement.' } },
        { id: 'aes', correct: false, text: { en: 'svc-report uses AES only.', fr: 'svc-report n’utilise qu’AES.' }, feedback: { en: 'That is good practice, not a risk.', fr: 'C’est une bonne pratique, pas un risque.' } },
      ],
    },
    {
      id: 'decide',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['tgs', 'config'],
      references: [RS_MI_01],
      prompt: { en: 'What is your priority?', fr: 'Quelle est votre priorité ?' },
      options: [
        { id: 'svc-sql-first', points: 10, text: { en: 'Assume svc-sql may be cracked: change its password to a long random one now and investigate w.perrin’s workstation.', fr: 'Considérer que svc-sql peut être cassé : changer son mot de passe pour une longue valeur aléatoire maintenant et examiner le poste de w.perrin.' }, feedback: { en: 'Cracking happens offline and leaves no trace on the domain.', fr: 'Le cassage se fait hors ligne et ne laisse aucune trace sur le domaine.' } },
        { id: 'ask-user', points: 4, text: { en: 'Ask w.perrin first whether they ran something unusual.', fr: 'Demander d’abord à w.perrin s’il a lancé quelque chose d’inhabituel.' }, feedback: { en: 'Useful, but the account or workstation may be controlled by an attacker; do not delay the password change.', fr: 'Utile, mais le compte ou le poste peut être contrôlé par un attaquant ; ne retardez pas le changement de mot de passe.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['tgs'],
      references: [RS_MI_01],
      prompt: { en: 'Which containment actions do you take?', fr: 'Quelles actions de confinement prenez-vous ?' },
      options: [
        { id: 'isolate', correct: true, text: { en: 'Isolate the workstation at 10.70.4.66 for analysis.', fr: 'Isoler le poste 10.70.4.66 pour analyse.' }, feedback: { en: 'The requests came from there.', fr: 'Les demandes en venaient.' } },
        { id: 'reset-user', correct: true, text: { en: 'Reset w.perrin’s password and revoke the user’s sessions.', fr: 'Réinitialiser le mot de passe de w.perrin et révoquer ses sessions.' }, feedback: { en: 'The account was used for the requests.', fr: 'Le compte a servi aux demandes.' } },
        { id: 'rotate-svc', correct: true, text: { en: 'Rotate passwords of every service account whose ticket was requested, starting with svc-sql.', fr: 'Changer les mots de passe de tous les comptes de service dont le ticket a été demandé, en commençant par svc-sql.' }, feedback: { en: 'All six tickets may be cracked offline.', fr: 'Les six tickets peuvent être cassés hors ligne.' } },
        { id: 'disable-kerberos', correct: false, text: { en: 'Disable Kerberos on the domain.', fr: 'Désactiver Kerberos sur le domaine.' }, feedback: { en: 'Kerberos is the domain’s authentication; the fix is account hygiene.', fr: 'Kerberos est l’authentification du domaine ; la solution est l’hygiène des comptes.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['config'],
      references: [RS_MI_02, mitigation('M1026', 'Privileged Account Management'), mitigation('M1027', 'Password Policies'), mitigation('M1041', 'Encrypt Sensitive Information'), mitigation('M1015', 'Active Directory Configuration')],
      prompt: { en: 'Which measures fix the misconfiguration?', fr: 'Quelles mesures corrigent la mauvaise configuration ?' },
      options: [
        { id: 'least', correct: true, text: { en: 'Remove svc-sql from Domain Admins and grant only the rights the service needs.', fr: 'Retirer svc-sql des administrateurs du domaine et n’accorder que les droits nécessaires au service.' }, feedback: { en: 'Least privilege limits the damage of any future crack.', fr: 'Le moindre privilège limite les dégâts d’un futur cassage.' } },
        { id: 'managed', correct: true, text: { en: 'Use managed service accounts or long random passwords that are rotated automatically.', fr: 'Utiliser des comptes de service gérés ou des mots de passe longs et aléatoires renouvelés automatiquement.' }, feedback: { en: 'Makes offline cracking impractical.', fr: 'Rend le cassage hors ligne irréaliste.' } },
        { id: 'aes-only', correct: true, text: { en: 'Disable RC4 for service accounts and require AES.', fr: 'Désactiver RC4 pour les comptes de service et exiger AES.' }, feedback: { en: 'Removes the weakest ticket encryption.', fr: 'Supprime le chiffrement de ticket le plus faible.' } },
        { id: 'hide-spn', correct: false, text: { en: 'Rename the service accounts so attackers cannot guess them.', fr: 'Renommer les comptes de service pour que les attaquants ne les devinent pas.' }, feedback: { en: 'SPNs are listed in the directory for every user.', fr: 'Les SPN sont visibles de tous les utilisateurs dans l’annuaire.' } },
      ],
    },
  ],
  debrief: {
    en: 'From w.perrin’s workstation, an attacker requested RC4 tickets for six service accounts in three seconds. svc-sql, a Domain Admin with a short, old password, was the prize. Rotating service passwords at once, removing excessive privileges and enforcing AES with managed accounts close this path.',
    fr: 'Depuis le poste de w.perrin, un attaquant a demandé des tickets RC4 pour six comptes de service en trois secondes. svc-sql, administrateur du domaine avec un mot de passe court et ancien, était la cible. Changer immédiatement les mots de passe de service, retirer les privilèges excessifs et imposer AES avec des comptes gérés ferment ce chemin.',
  },
  lessons: [
    { en: 'A service account in Domain Admins with a weak password is a domain compromise waiting to happen.', fr: 'Un compte de service administrateur du domaine avec un mot de passe faible est une compromission du domaine en attente.' },
    { en: 'Offline attacks leave no failed logons: act on the ticket requests themselves.', fr: 'Les attaques hors ligne ne laissent aucun échec de connexion : agissez sur les demandes de tickets elles-mêmes.' },
  ],
};
