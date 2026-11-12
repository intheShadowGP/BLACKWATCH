import type { Scenario } from '../model';
import { DE_AE_02, mitigation, PR_PS_04, RS_AN_03, RS_AN_07, RS_MI_01, RS_MI_02 } from '../references';
import { iso, jsonLines, utf16Base64, windowsEvent, windowsExport } from './helpers';

const DAY = '2026-09-03';
// Decodes to an inert training string: nothing in this scenario is executable.
const ENCODED = utf16Base64("Write-Output 'BLACKWATCH training sample: no action performed'");

const processes = windowsExport([
  windowsEvent(4688, iso(DAY, 10 * 3600 + 5 * 60), 'WKS-042', { SubjectUserName: 'm.bernard', NewProcessName: 'C:\\Program Files\\Office\\WINWORD.EXE', CommandLine: '"WINWORD.EXE" /n "C:\\Users\\m.bernard\\Downloads\\Order_2209.docm"', ParentProcessName: 'C:\\Windows\\explorer.exe' }),
  windowsEvent(4688, iso(DAY, 10 * 3600 + 5 * 60 + 12), 'WKS-042', { SubjectUserName: 'm.bernard', NewProcessName: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${ENCODED}`, ParentProcessName: 'C:\\Program Files\\Office\\WINWORD.EXE' }),
]);

const proxy = jsonLines([
  { timestamp: iso(DAY, 10 * 3600 + 5 * 60 + 14), src_ip: '10.50.2.42', user: 'm.bernard', message: 'GET https://cdn-updates.invoice-share.example.org/a/stage2.bin 200 (application/octet-stream, 412 KB)' },
  { timestamp: iso(DAY, 10 * 3600 + 6 * 60), src_ip: '10.50.2.42', user: 'm.bernard', message: 'POST https://telemetry.invoice-share.example.org/beacon 200 (every 60 s since 10:06)' },
]);

export const powershell: Scenario = {
  id: 'powershell',
  version: 1,
  title: { en: 'Suspicious PowerShell launched by a document', fr: 'PowerShell suspect lancé par un document' },
  difficulty: 'intermediate',
  minutes: 15,
  techniques: ['T1566.001', 'T1204.002', 'T1059.001', 'T1027', 'T1105', 'T1071.001'],
  context: {
    en: 'An industrial supplier (fictitious) collects process creation events (4688 with command line) and web proxy logs. Office macros are allowed for files from the Internet.',
    fr: 'Un fournisseur industriel (fictif) collecte les événements de création de processus (4688 avec ligne de commande) et les journaux du proxy web. Les macros Office sont autorisées pour les fichiers venant d’Internet.',
  },
  incident: {
    en: 'The SOC Workbench rule "Encoded PowerShell command" fires on WKS-042 at 10:05. The user, m.bernard, works in purchasing.',
    fr: 'La règle « Commande PowerShell encodée » de l’atelier SOC réagit sur WKS-042 à 10 h 05. L’utilisateur, m.bernard, travaille aux achats.',
  },
  evidence: [
    { id: 'process', kind: 'process', title: { en: 'Process creation events (XML export)', fr: 'Événements de création de processus (export XML)' }, content: processes, logFormat: 'windowsXml' },
    { id: 'proxy', kind: 'network', title: { en: 'Web proxy log (JSON Lines)', fr: 'Journal du proxy web (JSON Lines)' }, content: proxy, logFormat: 'json' },
  ],
  steps: [
    {
      id: 'chain',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['process'],
      references: [DE_AE_02, RS_AN_03],
      prompt: { en: 'What is suspicious in the process chain?', fr: 'Qu’y a-t-il de suspect dans la chaîne de processus ?' },
      options: [
        { id: 'parent', correct: true, text: { en: 'Word starts PowerShell.', fr: 'Word lance PowerShell.' }, feedback: { en: 'Office applications rarely need to start a shell; this is typical of a malicious macro.', fr: 'Les applications Office ont rarement besoin de lancer un shell ; c’est typique d’une macro malveillante.' } },
        { id: 'hidden', correct: true, text: { en: 'Hidden window and an encoded command to hide what runs.', fr: 'Fenêtre masquée et commande encodée pour cacher ce qui s’exécute.' }, feedback: { en: 'Obfuscation, not proof of malice on its own, but strong in this context.', fr: 'De l’obscurcissement, pas une preuve à lui seul, mais significatif dans ce contexte.' } },
        { id: 'docm', correct: true, text: { en: 'A macro-enabled document opened from Downloads.', fr: 'Un document avec macros ouvert depuis Téléchargements.' }, feedback: { en: 'The likely delivery vector.', fr: 'Le vecteur de livraison probable.' } },
        { id: 'explorer', correct: false, text: { en: 'Explorer starting Word is abnormal.', fr: 'Explorer qui lance Word est anormal.' }, feedback: { en: 'This is how a user opens a document.', fr: 'C’est ainsi qu’un utilisateur ouvre un document.' } },
      ],
    },
    {
      id: 'decode',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['process'],
      references: [RS_AN_07],
      prompt: { en: 'How do you examine the encoded command safely?', fr: 'Comment examinez-vous la commande encodée sans risque ?' },
      options: [
        { id: 'decode-only', points: 10, text: { en: 'Decode it as text (Base64, UTF-16LE) without running it, for example with the toolbox Base64 tool, and keep a copy as evidence.', fr: 'La décoder comme du texte (Base64, UTF-16LE) sans l’exécuter, par exemple avec l’outil Base64 de la boîte à outils, et en garder une copie comme preuve.' }, feedback: { en: 'Decoding is safe; running is not. Here it decodes to an inert training string.', fr: 'Décoder est sans risque ; exécuter ne l’est pas. Ici, cela donne une chaîne d’entraînement inerte.' } },
        { id: 'run', points: 0, text: { en: 'Run it in PowerShell on your own workstation to see what it does.', fr: 'L’exécuter dans PowerShell sur votre poste pour voir ce qu’elle fait.' }, feedback: { en: 'Never run attacker code outside an isolated analysis environment.', fr: 'N’exécutez jamais de code d’attaquant hors d’un environnement d’analyse isolé.' } },
      ],
    },
    {
      id: 'decide',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['proxy'],
      references: [RS_AN_03],
      prompt: { en: 'The proxy shows a download and a request every 60 seconds since 10:06. What does it mean?', fr: 'Le proxy montre un téléchargement et une requête toutes les 60 secondes depuis 10 h 06. Qu’est-ce que cela signifie ?' },
      options: [
        { id: 'c2', points: 10, text: { en: 'A second stage was retrieved and the workstation is now polling a command server.', fr: 'Une seconde charge a été récupérée et le poste interroge désormais un serveur de commande.' }, feedback: { en: 'Regular beacons to an unknown domain are a sign of remote control.', fr: 'Des appels réguliers vers un domaine inconnu signalent une prise de contrôle à distance.' } },
        { id: 'update', points: 0, text: { en: 'A software update check.', fr: 'Une vérification de mise à jour logicielle.' }, feedback: { en: 'It starts right after the hidden PowerShell and the domain is unknown.', fr: 'Cela commence juste après le PowerShell masqué et le domaine est inconnu.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['proxy'],
      references: [RS_MI_01, RS_AN_07],
      prompt: { en: 'Which containment actions do you take?', fr: 'Quelles actions de confinement prenez-vous ?' },
      options: [
        { id: 'isolate', correct: true, text: { en: 'Isolate WKS-042 with the endpoint tool, keeping it running.', fr: 'Isoler WKS-042 avec l’outil de protection, en le laissant allumé.' }, feedback: { en: 'Stops the remote control and keeps memory for analysis.', fr: 'Arrête le contrôle à distance et préserve la mémoire pour l’analyse.' } },
        { id: 'block', correct: true, text: { en: 'Block invoice-share.example.org at the proxy and search for other hosts contacting it.', fr: 'Bloquer invoice-share.example.org au proxy et rechercher d’autres postes qui le contactent.' }, feedback: { en: 'Other recipients may have opened the same document.', fr: 'D’autres destinataires ont pu ouvrir le même document.' } },
        { id: 'credentials', correct: true, text: { en: 'Reset m.bernard’s password from another machine.', fr: 'Réinitialiser le mot de passe de m.bernard depuis une autre machine.' }, feedback: { en: 'Assume credentials typed on the machine are exposed.', fr: 'Considérez comme exposés les identifiants saisis sur le poste.' } },
        { id: 'delete-doc', correct: false, text: { en: 'Delete the document and close the alert.', fr: 'Supprimer le document et clore l’alerte.' }, feedback: { en: 'The second stage is already running; the document is also evidence.', fr: 'La seconde charge s’exécute déjà ; le document est aussi une preuve.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: [],
      references: [RS_MI_02, PR_PS_04, mitigation('M1042', 'Disable or Remove Feature or Program'), mitigation('M1040', 'Behavior Prevention on Endpoint'), mitigation('M1038', 'Execution Prevention')],
      prompt: { en: 'Which measures prevent this chain?', fr: 'Quelles mesures empêchent cette chaîne ?' },
      options: [
        { id: 'macros', correct: true, text: { en: 'Block macros in files from the Internet.', fr: 'Bloquer les macros des fichiers venant d’Internet.' }, feedback: { en: 'Removes the entry point used here.', fr: 'Supprime le point d’entrée utilisé ici.' } },
        { id: 'office-child', correct: true, text: { en: 'Prevent Office applications from creating child processes.', fr: 'Empêcher les applications Office de créer des processus enfants.' }, feedback: { en: 'Breaks the Word → PowerShell step.', fr: 'Casse l’étape Word → PowerShell.' } },
        { id: 'ps-logging', correct: true, text: { en: 'Enable PowerShell script block logging and keep command lines in process events.', fr: 'Activer la journalisation des blocs de script PowerShell et conserver les lignes de commande dans les événements de processus.' }, feedback: { en: 'Logs the decoded content for future investigations.', fr: 'Journalise le contenu décodé pour les prochaines investigations.' } },
        { id: 'remove-ps', correct: false, text: { en: 'Uninstall PowerShell everywhere and consider it solved.', fr: 'Désinstaller PowerShell partout et considérer le problème réglé.' }, feedback: { en: 'Administration depends on it and attackers have other interpreters; control its use instead.', fr: 'L’administration en dépend et les attaquants ont d’autres interpréteurs ; contrôlez plutôt son usage.' } },
      ],
    },
  ],
  debrief: {
    en: 'A macro in Order_2209.docm started a hidden PowerShell with an encoded command, which downloaded a second stage and began polling a command server every minute. Isolating the workstation, blocking the domain and resetting credentials contained it; blocking Internet macros and Office child processes prevents the chain.',
    fr: 'Une macro de Order_2209.docm a lancé un PowerShell masqué avec une commande encodée, qui a téléchargé une seconde charge et interrogé un serveur de commande chaque minute. Isoler le poste, bloquer le domaine et réinitialiser les identifiants ont contenu l’attaque ; bloquer les macros venant d’Internet et les processus enfants d’Office empêche la chaîne.',
  },
  lessons: [
    { en: 'Parent-child relationships between processes reveal more than any single process.', fr: 'Les relations parent-enfant entre processus en disent plus qu’un processus isolé.' },
    { en: 'Decode, never run, suspicious commands.', fr: 'Décodez, n’exécutez jamais, les commandes suspectes.' },
  ],
};
