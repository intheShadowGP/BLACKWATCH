import type { Scenario } from '../model';
import { ANSSI_RANSOMWARE, CISA_RANSOMWARE, mitigation, PR_DS_11, RC_RP_03, RC_RP_05, RS_AN_08, RS_CO_02, RS_MI_01 } from '../references';
import { iso, jsonLines } from './helpers';

const DAY = '2026-05-02';

const edr = jsonLines([
  { timestamp: iso(DAY, 1 * 3600 + 4 * 60), host: 'FS01', severity: 'high', message: 'Suspicious service installed: "UpdSvcHelper" running C:\\ProgramData\\updsvc.exe', user: 'svc-backup', src_ip: '10.10.5.40' },
  { timestamp: iso(DAY, 1 * 3600 + 6 * 60), host: 'FS01', severity: 'critical', message: 'Volume shadow copies deleted by updsvc.exe (command line withheld in this training artefact)', user: 'svc-backup' },
  { timestamp: iso(DAY, 1 * 3600 + 7 * 60), host: 'FS01', severity: 'critical', message: 'Mass file modification: 18,412 files renamed to *.lkd in 4 minutes under D:\\Shares', user: 'svc-backup' },
  { timestamp: iso(DAY, 1 * 3600 + 9 * 60), host: 'FS02', severity: 'critical', message: 'Mass file modification: 2,107 files renamed to *.lkd in 1 minute under E:\\Projects', user: 'svc-backup', src_ip: '10.10.5.40' },
]);

const note = `README-RESTORE.txt (found in every shared folder)

Your files are encrypted. Contact the address below with your ID to get the price.
ID: TRAINING-ONLY-0000
Contact: recover@restore-desk.example`;

const backup = `Backup console summary (fictitious product)
- Nightly backup of FS01 and FS02: last success 2026-05-01 23:00
- Backup repository: NAS02, joined to the domain, share \\\\NAS02\\backups writable by svc-backup
- Weekly offline copy to removable media: last success 2026-04-26
- Restore test: never performed`;

export const ransomware: Scenario = {
  id: 'ransomware',
  version: 1,
  title: { en: 'Ransomware on file servers', fr: 'Rançongiciel sur des serveurs de fichiers' },
  difficulty: 'intermediate',
  minutes: 20,
  techniques: ['T1486', 'T1490', 'T1078'],
  context: {
    en: 'A design office (fictitious) runs two Windows file servers, FS01 and FS02, backed up nightly to a NAS. A service account, svc-backup, has administrator rights on both servers.',
    fr: 'Un bureau d’études (fictif) exploite deux serveurs de fichiers Windows, FS01 et FS02, sauvegardés chaque nuit sur un NAS. Un compte de service, svc-backup, est administrateur des deux serveurs.',
  },
  incident: {
    en: 'At 01:10 on a Saturday the endpoint protection console raises critical alerts on both servers. Users who work remotely report that their files cannot be opened. A ransom note appears in the shares.',
    fr: 'Un samedi à 01 h 10, la console de protection des postes lève des alertes critiques sur les deux serveurs. Des utilisateurs en télétravail signalent qu’ils ne peuvent plus ouvrir leurs fichiers. Une demande de rançon apparaît dans les partages.',
  },
  evidence: [
    { id: 'edr', kind: 'alert', title: { en: 'Endpoint protection alerts (JSON Lines)', fr: 'Alertes de protection des postes (JSON Lines)' }, content: edr, logFormat: 'json' },
    { id: 'note', kind: 'file', title: { en: 'Ransom note (inert copy)', fr: 'Demande de rançon (copie inerte)' }, content: note },
    { id: 'backup', kind: 'config', title: { en: 'Backup status', fr: 'État des sauvegardes' }, content: backup },
  ],
  steps: [
    {
      id: 'first-move',
      kind: 'containment',
      mode: 'single',
      points: 10,
      evidence: ['edr'],
      references: [RS_MI_01, CISA_RANSOMWARE, ANSSI_RANSOMWARE],
      prompt: { en: 'Encryption is still running. What is your first action?', fr: 'Le chiffrement est toujours en cours. Quelle est votre première action ?' },
      options: [
        { id: 'isolate', points: 10, text: { en: 'Disconnect FS01, FS02 and 10.10.5.40 from the network while keeping them powered on.', fr: 'Déconnecter FS01, FS02 et 10.10.5.40 du réseau en les laissant allumés.' }, feedback: { en: 'Stops the spread and keeps memory for analysis. Public guides recommend isolation first.', fr: 'Arrête la propagation et préserve la mémoire pour l’analyse. Les guides publics recommandent d’abord l’isolement.' } },
        { id: 'poweroff', points: 6, text: { en: 'Power the servers off immediately.', fr: 'Éteindre immédiatement les serveurs.' }, feedback: { en: 'Acceptable when isolation is impossible, but memory evidence (and sometimes keys) is lost. Guides prefer isolation when it can be done quickly.', fr: 'Acceptable si l’isolement est impossible, mais les traces en mémoire (et parfois des clés) sont perdues. Les guides préfèrent l’isolement s’il est rapide.' } },
        { id: 'wait', points: 0, text: { en: 'Wait for Monday to involve the whole team.', fr: 'Attendre lundi pour mobiliser toute l’équipe.' }, feedback: { en: 'Encryption continues and may reach the backups.', fr: 'Le chiffrement continue et peut atteindre les sauvegardes.' } },
      ],
    },
    {
      id: 'origin',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['edr'],
      references: [RS_AN_08],
      prompt: { en: 'What do the alerts tell you?', fr: 'Que vous apprennent les alertes ?' },
      options: [
        { id: 'account', correct: true, text: { en: 'The actions run under svc-backup, so this account is compromised.', fr: 'Les actions s’exécutent sous svc-backup, ce compte est donc compromis.' }, feedback: { en: 'Every alert names it.', fr: 'Chaque alerte le mentionne.' } },
        { id: 'source', correct: true, text: { en: '10.10.5.40 is a likely staging point: it installed the service and reached FS02.', fr: '10.10.5.40 est un point de départ probable : il a installé le service et atteint FS02.' }, feedback: { en: 'It needs investigation before any reconnection.', fr: 'Il doit être analysé avant toute reconnexion.' } },
        { id: 'recovery', correct: true, text: { en: 'Shadow copies were deleted to prevent local recovery.', fr: 'Les clichés instantanés ont été supprimés pour empêcher une restauration locale.' }, feedback: { en: 'Typical of ransomware (inhibit system recovery).', fr: 'Typique des rançongiciels (empêcher la restauration).' } },
        { id: 'one', correct: false, text: { en: 'Only FS01 is affected.', fr: 'Seul FS01 est touché.' }, feedback: { en: 'FS02 also shows mass renaming.', fr: 'FS02 montre aussi un renommage massif.' } },
      ],
    },
    {
      id: 'backups',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['backup'],
      references: [RC_RP_03, PR_DS_11, mitigation('M1053', 'Data Backup')],
      prompt: { en: 'What do you do about the backups?', fr: 'Que faites-vous des sauvegardes ?' },
      options: [
        { id: 'protect', points: 10, text: { en: 'Disconnect NAS02 now, keep the offline copy safe, and verify backup integrity before any restore.', fr: 'Déconnecter NAS02 maintenant, mettre la copie hors ligne en sécurité et vérifier l’intégrité des sauvegardes avant toute restauration.' }, feedback: { en: 'The NAS is writable by the compromised account; the offline copy is the safest restore point.', fr: 'Le NAS est accessible en écriture au compte compromis ; la copie hors ligne est le point de restauration le plus sûr.' } },
        { id: 'restore-now', points: 3, text: { en: 'Restore last night’s backup to the servers immediately.', fr: 'Restaurer immédiatement la sauvegarde de la nuit sur les serveurs.' }, feedback: { en: 'The attacker still holds the account and the entry point: files would be encrypted again, and the backup itself may be affected.', fr: 'L’attaquant détient encore le compte et le point d’entrée : les fichiers seraient rechiffrés, et la sauvegarde elle-même peut être touchée.' } },
        { id: 'pay', points: 0, text: { en: 'Pay to get the decryption key; it is faster.', fr: 'Payer pour obtenir la clé de déchiffrement ; c’est plus rapide.' }, feedback: { en: 'Public authorities advise against paying: no guarantee of recovery, and it funds further attacks.', fr: 'Les autorités publiques déconseillent de payer : aucune garantie de récupération, et cela finance d’autres attaques.' } },
      ],
    },
    {
      id: 'notify',
      kind: 'decision',
      mode: 'multiple',
      points: 10,
      evidence: ['note'],
      references: [RS_CO_02, ANSSI_RANSOMWARE],
      prompt: { en: 'Whom do you inform?', fr: 'Qui informez-vous ?' },
      options: [
        { id: 'management', correct: true, text: { en: 'Management, who decide on business continuity and communication.', fr: 'La direction, qui décide de la continuité d’activité et de la communication.' }, feedback: { en: 'The incident affects the whole business.', fr: 'L’incident touche toute l’activité.' } },
        { id: 'authorities', correct: true, text: { en: 'The relevant authorities (police complaint, national CERT) and, if personal data may be affected, the data protection authority within the legal deadline.', fr: 'Les autorités compétentes (plainte, CERT national) et, si des données personnelles peuvent être touchées, l’autorité de protection des données dans le délai légal.' }, feedback: { en: 'Notification duties depend on the country and on the data involved.', fr: 'Les obligations de notification dépendent du pays et des données concernées.' } },
        { id: 'insurer', correct: true, text: { en: 'The cyber insurer, if the firm has one.', fr: 'L’assureur cyber, si le bureau en a un.' }, feedback: { en: 'Policies often require early notification.', fr: 'Les contrats exigent souvent une déclaration rapide.' } },
        { id: 'attacker', correct: false, text: { en: 'The attacker, to negotiate before anything else.', fr: 'L’attaquant, pour négocier avant toute chose.' }, feedback: { en: 'Contact with the attacker is a management decision taken with specialists, not a first step.', fr: 'Tout contact avec l’attaquant est une décision de la direction prise avec des spécialistes, pas une première étape.' } },
      ],
    },
    {
      id: 'recover',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['backup'],
      references: [RC_RP_05, mitigation('M1053', 'Data Backup'), mitigation('M1026', 'Privileged Account Management'), mitigation('M1030', 'Network Segmentation')],
      prompt: { en: 'Which measures belong to recovery and hardening?', fr: 'Quelles mesures relèvent de la reprise et du durcissement ?' },
      options: [
        { id: 'rebuild', correct: true, text: { en: 'Rebuild the servers from clean media, then restore verified data.', fr: 'Reconstruire les serveurs à partir de supports sains, puis restaurer des données vérifiées.' }, feedback: { en: 'Cleaning an infected system in place leaves doubts.', fr: 'Nettoyer un système infecté sur place laisse des doutes.' } },
        { id: 'offline', correct: true, text: { en: 'Keep an offline or immutable backup copy and test restores regularly.', fr: 'Conserver une copie de sauvegarde hors ligne ou immuable et tester régulièrement les restaurations.' }, feedback: { en: 'The restore test had never been done.', fr: 'Le test de restauration n’avait jamais été fait.' } },
        { id: 'svc', correct: true, text: { en: 'Replace svc-backup with an account limited to backup operations, without interactive logon.', fr: 'Remplacer svc-backup par un compte limité aux opérations de sauvegarde, sans ouverture de session interactive.' }, feedback: { en: 'An administrator service account on every server is a single point of failure.', fr: 'Un compte de service administrateur de tous les serveurs est un point unique de défaillance.' } },
        { id: 'av-only', correct: false, text: { en: 'Buy a second antivirus and consider the matter closed.', fr: 'Acheter un second antivirus et considérer l’affaire close.' }, feedback: { en: 'The attack used a valid account; the root causes remain.', fr: 'L’attaque a utilisé un compte valide ; les causes profondes demeurent.' } },
      ],
    },
  ],
  debrief: {
    en: 'An attacker controlling svc-backup used 10.10.5.40 to install a service on FS01, delete shadow copies and encrypt the shares, then reached FS02. The NAS backups were writable by the same account. Isolation, protection of the offline copy and a rebuild with verified data allowed recovery without paying.',
    fr: 'Un attaquant maîtrisant svc-backup a utilisé 10.10.5.40 pour installer un service sur FS01, supprimer les clichés instantanés et chiffrer les partages, puis a atteint FS02. Les sauvegardes du NAS étaient accessibles en écriture au même compte. L’isolement, la protection de la copie hors ligne et une reconstruction avec des données vérifiées ont permis la reprise sans payer.',
  },
  lessons: [
    { en: 'Isolate first; keep systems powered on when you can.', fr: 'Isolez d’abord ; laissez les systèmes allumés quand c’est possible.' },
    { en: 'A backup reachable by a compromised account is not a backup: keep one offline and test it.', fr: 'Une sauvegarde accessible à un compte compromis n’en est pas une : gardez-en une hors ligne et testez-la.' },
  ],
};
