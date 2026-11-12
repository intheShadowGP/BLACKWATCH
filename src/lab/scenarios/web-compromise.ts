import type { Scenario } from '../model';
import { DE_AE_03, mitigation, PR_PS_02, RS_AN_03, RS_AN_07, RS_MI_01, RS_MI_02 } from '../references';

const pad = (value: number) => String(value).padStart(2, '0');
const t = (seconds: number) => `21/Jul/2026:${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)} +0000`;
const line = (ip: string, seconds: number, request: string, status: number, bytes: number, agent: string) => `${ip} - - [${t(seconds)}] "${request}" ${status} ${bytes} "-" "${agent}"`;

const access = [
  line('198.51.100.30', 9 * 3600, 'GET /shop/ HTTP/1.1', 200, 18234, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
  ...['/admin/', '/backup.zip', '/.git/config', '/uploads/', '/api/profile/avatar', '/phpinfo.php'].map((path, index) => line('203.0.113.88', 9 * 3600 + 600 + index, `GET ${path} HTTP/1.1`, path === '/api/profile/avatar' || path === '/uploads/' ? 200 : 404, 312, 'WebScout/2.1 (security scanner)')),
  line('203.0.113.88', 9 * 3600 + 700, 'POST /api/profile/avatar HTTP/1.1', 200, 54, 'Mozilla/5.0 (X11; Linux x86_64)'),
  line('203.0.113.88', 9 * 3600 + 712, 'GET /uploads/avatars/u4512.php?c=id HTTP/1.1', 200, 61, 'Mozilla/5.0 (X11; Linux x86_64)'),
  line('203.0.113.88', 9 * 3600 + 730, 'GET /uploads/avatars/u4512.php?c=cat%20../../config/db.ini HTTP/1.1', 200, 214, 'Mozilla/5.0 (X11; Linux x86_64)'),
  line('203.0.113.88', 9 * 3600 + 760, 'GET /uploads/avatars/u4512.php?c=ls%20-la%20/var/backups HTTP/1.1', 200, 902, 'Mozilla/5.0 (X11; Linux x86_64)'),
  line('198.51.100.31', 9 * 3600 + 800, 'GET /shop/cart HTTP/1.1', 200, 8102, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)'),
].join('\n');

const code = `// api/profile/avatar handler (excerpt, fictitious)
saveUpload(file) {
  // Only the Content-Type header sent by the client is checked.
  if (!file.headers['content-type'].startsWith('image/')) reject();
  // The original file name and extension are kept.
  move(file, '/var/www/shop/uploads/avatars/' + userId + '.' + file.extension);
}
// The web server executes .php files in every directory, uploads included.`;

export const webCompromise: Scenario = {
  id: 'web-compromise',
  version: 1,
  title: { en: 'Web shell through an avatar upload', fr: 'Web shell via le téléversement d’un avatar' },
  difficulty: 'intermediate',
  minutes: 20,
  techniques: ['T1190', 'T1505.003'],
  context: {
    en: 'A small online shop (fictitious) runs a PHP application. Customers can upload an avatar to their profile. The database password is stored in config/db.ini.',
    fr: 'Une petite boutique en ligne (fictive) fait tourner une application PHP. Les clients peuvent téléverser un avatar sur leur profil. Le mot de passe de la base est stocké dans config/db.ini.',
  },
  incident: {
    en: 'The hosting provider reports outgoing traffic to an unknown address from the shop server. You retrieve the web server access log and the upload handler code.',
    fr: 'L’hébergeur signale du trafic sortant vers une adresse inconnue depuis le serveur de la boutique. Vous récupérez le journal d’accès du serveur web et le code de gestion des téléversements.',
  },
  evidence: [
    { id: 'access', kind: 'log', title: { en: 'Web server access log', fr: 'Journal d’accès du serveur web' }, content: `${access}\n`, logFormat: 'webAccess' },
    { id: 'code', kind: 'file', title: { en: 'Upload handler (excerpt)', fr: 'Gestion des téléversements (extrait)' }, content: code },
  ],
  steps: [
    {
      id: 'timeline',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['access'],
      references: [DE_AE_03, RS_AN_03],
      prompt: { en: 'Which steps of the attack do you see in the log?', fr: 'Quelles étapes de l’attaque voyez-vous dans le journal ?' },
      options: [
        { id: 'scan', correct: true, text: { en: 'A scan of common paths by 203.0.113.88.', fr: 'Un balayage de chemins courants par 203.0.113.88.' }, feedback: { en: 'Six probes in six seconds with a scanner user agent.', fr: 'Six requêtes en six secondes avec un user agent de scanner.' } },
        { id: 'upload', correct: true, text: { en: 'An upload to the avatar endpoint followed by requests to a .php file in uploads.', fr: 'Un téléversement sur l’avatar suivi de requêtes vers un fichier .php dans uploads.' }, feedback: { en: 'The uploaded file is a web shell.', fr: 'Le fichier téléversé est un web shell.' } },
        { id: 'commands', correct: true, text: { en: 'Commands passed in the "c" parameter, including reading the database configuration.', fr: 'Des commandes passées dans le paramètre « c », dont la lecture de la configuration de la base.' }, feedback: { en: 'The attacker obtained the database password.', fr: 'L’attaquant a obtenu le mot de passe de la base.' } },
        { id: 'customer', correct: false, text: { en: '198.51.100.31 took part in the attack.', fr: '198.51.100.31 a participé à l’attaque.' }, feedback: { en: 'A normal visit to the cart.', fr: 'Une visite normale du panier.' } },
      ],
    },
    {
      id: 'flaw',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['code'],
      references: [RS_AN_03],
      prompt: { en: 'What made the attack possible?', fr: 'Qu’est-ce qui a rendu l’attaque possible ?' },
      options: [
        { id: 'upload-flaw', points: 10, text: { en: 'The handler trusts the client Content-Type, keeps the extension, and the server executes PHP in uploads.', fr: 'Le code fait confiance au Content-Type du client, conserve l’extension, et le serveur exécute le PHP dans uploads.' }, feedback: { en: 'Three weaknesses combine into remote code execution.', fr: 'Trois faiblesses se combinent en exécution de code à distance.' } },
        { id: 'scanner', points: 2, text: { en: 'The scanner itself.', fr: 'Le scanner lui-même.' }, feedback: { en: 'Scans are constant; the flaw is in the upload handling.', fr: 'Les balayages sont permanents ; la faille est dans la gestion des téléversements.' } },
      ],
    },
    {
      id: 'decide',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['access'],
      references: [RS_MI_01],
      prompt: { en: 'What do you do with the shop?', fr: 'Que faites-vous de la boutique ?' },
      options: [
        { id: 'maintenance', points: 10, text: { en: 'Put the shop in maintenance, take a snapshot of the server, and keep the logs.', fr: 'Mettre la boutique en maintenance, prendre un instantané du serveur et conserver les journaux.' }, feedback: { en: 'Stops the attacker and preserves evidence of what was read or changed.', fr: 'Arrête l’attaquant et préserve la preuve de ce qui a été lu ou modifié.' } },
        { id: 'delete-shell', points: 4, text: { en: 'Delete u4512.php and leave the shop online.', fr: 'Supprimer u4512.php et laisser la boutique en ligne.' }, feedback: { en: 'The flaw remains and other files or accounts may have been planted.', fr: 'La faille demeure et d’autres fichiers ou comptes ont pu être déposés.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['access', 'code'],
      references: [RS_MI_01, RS_AN_07],
      prompt: { en: 'Which containment actions are needed?', fr: 'Quelles actions de confinement sont nécessaires ?' },
      options: [
        { id: 'db-password', correct: true, text: { en: 'Change the database password and check the database for unexpected accounts or changes.', fr: 'Changer le mot de passe de la base et y rechercher des comptes ou modifications inattendus.' }, feedback: { en: 'It was read through the shell.', fr: 'Il a été lu via le shell.' } },
        { id: 'find-others', correct: true, text: { en: 'Search the web root for other recently modified or unexpected script files.', fr: 'Rechercher dans le site d’autres scripts récemment modifiés ou inattendus.' }, feedback: { en: 'Attackers often leave several shells.', fr: 'Les attaquants laissent souvent plusieurs shells.' } },
        { id: 'block-ip', correct: true, text: { en: 'Block 203.0.113.88 and the destination of the outgoing traffic.', fr: 'Bloquer 203.0.113.88 et la destination du trafic sortant.' }, feedback: { en: 'Useful in addition, not alone: addresses change easily.', fr: 'Utile en complément, pas seul : les adresses changent facilement.' } },
        { id: 'restore-now', correct: false, text: { en: 'Restore yesterday’s backup and reopen immediately.', fr: 'Restaurer la sauvegarde d’hier et rouvrir immédiatement.' }, feedback: { en: 'The vulnerable handler would come back with it.', fr: 'Le code vulnérable reviendrait avec elle.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['code'],
      references: [RS_MI_02, PR_PS_02, mitigation('M1050', 'Exploit Protection'), mitigation('M1022', 'Restrict File and Directory Permissions'), mitigation('M1016', 'Vulnerability Scanning')],
      prompt: { en: 'Which fixes address the cause?', fr: 'Quels correctifs traitent la cause ?' },
      options: [
        { id: 'validate', correct: true, text: { en: 'Check the file content server-side, re-encode images and store them under a generated name without the original extension.', fr: 'Vérifier le contenu côté serveur, réencoder les images et les stocker sous un nom généré sans l’extension d’origine.' }, feedback: { en: 'The client-supplied type and name cannot be trusted.', fr: 'Le type et le nom fournis par le client ne sont pas fiables.' } },
        { id: 'noexec', correct: true, text: { en: 'Disable script execution in the uploads directory, or serve uploads from a separate domain.', fr: 'Désactiver l’exécution de scripts dans le répertoire des téléversements, ou servir les fichiers depuis un domaine séparé.' }, feedback: { en: 'Defence in depth if validation fails.', fr: 'Défense en profondeur si la validation échoue.' } },
        { id: 'secrets', correct: true, text: { en: 'Keep secrets outside the web root with read access limited to the application.', fr: 'Garder les secrets hors de l’arborescence web avec une lecture limitée à l’application.' }, feedback: { en: 'Limits what a shell can read.', fr: 'Limite ce qu’un shell peut lire.' } },
        { id: 'robots', correct: false, text: { en: 'Hide the uploads path in robots.txt.', fr: 'Masquer le chemin des téléversements dans robots.txt.' }, feedback: { en: 'robots.txt is public and only a hint to crawlers.', fr: 'robots.txt est public et n’est qu’une indication pour les robots.' } },
      ],
    },
  ],
  debrief: {
    en: 'After a scan, the attacker uploaded a PHP file as an avatar. The handler trusted the client content type and kept the extension, and the server executed PHP in uploads. Through the web shell the attacker read the database credentials. Maintenance mode, credential rotation and a fixed upload pipeline closed the incident.',
    fr: 'Après un balayage, l’attaquant a téléversé un fichier PHP comme avatar. Le code faisait confiance au type de contenu du client et conservait l’extension, et le serveur exécutait le PHP dans uploads. Via le web shell, l’attaquant a lu les identifiants de la base. Le mode maintenance, le changement des identifiants et un téléversement corrigé ont clos l’incident.',
  },
  lessons: [
    { en: 'Never trust client-supplied file types or names.', fr: 'Ne faites jamais confiance au type ou au nom de fichier fournis par le client.' },
    { en: 'Assume everything readable by the web server is known to the attacker.', fr: 'Considérez comme connu de l’attaquant tout ce que le serveur web peut lire.' },
  ],
};
