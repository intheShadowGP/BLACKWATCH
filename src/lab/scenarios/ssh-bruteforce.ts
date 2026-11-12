import type { Scenario } from '../model';
import { DE_AE_02, DE_AE_08, mitigation, PR_AA_03, RS_AN_03, RS_AN_07, RS_MI_01, RS_MI_02 } from '../references';

const pad = (value: number) => String(value).padStart(2, '0');
const at = (seconds: number) => `Mar 14 ${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;

function authLog(): string {
  const lines: string[] = [];
  let t = 2 * 3600 + 11 * 60;
  lines.push(`${at(t - 3000)} ledger-db sshd[811]: Accepted publickey for dba from 10.20.0.15 port 51022 ssh2: ED25519 SHA256:exampleKeyFingerprint`);
  const names = ['admin', 'oracle', 'test', 'postgres', 'ubuntu', 'git', 'ftpuser', 'guest', 'support', 'deploy', 'user', 'backup'];
  for (const [index, name] of names.entries()) {
    t += 6;
    lines.push(`${at(t)} ledger-db sshd[${2100 + index}]: Invalid user ${name} from 203.0.113.50 port ${40100 + index}`);
    lines.push(`${at(t + 2)} ledger-db sshd[${2100 + index}]: Failed password for invalid user ${name} from 203.0.113.50 port ${40100 + index} ssh2`);
  }
  for (let attempt = 0; attempt < 9; attempt += 1) {
    t += 5;
    lines.push(`${at(t)} ledger-db sshd[${2200 + attempt}]: Failed password for root from 203.0.113.50 port ${40200 + attempt} ssh2`);
  }
  t += 4;
  lines.push(`${at(t)} ledger-db sshd[2210]: Accepted password for root from 203.0.113.50 port 40210 ssh2`);
  lines.push(`${at(t + 1)} ledger-db sshd[2210]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)`);
  lines.push(`${at(t + 95)} ledger-db useradd[2251]: new user: name=sysupdate, UID=1003, GID=1003, home=/home/sysupdate, shell=/bin/bash`);
  lines.push(`${at(t + 96)} ledger-db usermod[2253]: add 'sysupdate' to group 'sudo'`);
  lines.push(`${at(t + 160)} ledger-db sshd[2210]: Received disconnect from 203.0.113.50 port 40210:11: disconnected by user`);
  return `${lines.join('\n')}\n`;
}

export const sshBruteforce: Scenario = {
  id: 'ssh-bruteforce',
  version: 1,
  title: { en: 'SSH brute force on a database server', fr: 'Force brute SSH sur un serveur de base de données' },
  difficulty: 'introductory',
  minutes: 15,
  techniques: ['T1110.001', 'T1078', 'T1136.001'],
  context: {
    en: 'Ledger-db is a Linux database server of a small accounting firm. SSH is reachable from the Internet so that the database administrator (account "dba") can work remotely with a key. Root login with a password was never disabled.',
    fr: 'Ledger-db est un serveur Linux de base de données d’un petit cabinet comptable. SSH est joignable depuis Internet pour que l’administrateur de la base (compte « dba ») travaille à distance avec une clé. La connexion root par mot de passe n’a jamais été désactivée.',
  },
  incident: {
    en: 'At 02:15 the monitoring tool raised an alert: "New local account created on ledger-db". Nobody on the team created an account. You have the server authentication log and a note from the administrator.',
    fr: 'À 02 h 15, l’outil de supervision a levé une alerte : « Nouveau compte local créé sur ledger-db ». Personne dans l’équipe n’a créé de compte. Vous disposez du journal d’authentification du serveur et d’une note de l’administrateur.',
  },
  evidence: [
    { id: 'auth', kind: 'log', title: { en: '/var/log/auth.log (excerpt)', fr: '/var/log/auth.log (extrait)' }, content: authLog(), logFormat: 'syslog' },
    {
      id: 'note',
      kind: 'note',
      title: { en: 'Note from the database administrator', fr: 'Note de l’administrateur de la base' },
      content: 'I only connect as "dba" with my SSH key, from the office VPN (10.20.0.0/16).\nI did not log in last night after 01:30 and I never use root over SSH.\nThe root password is the same one we used during the installation.',
    },
  ],
  steps: [
    {
      id: 'observations',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['auth'],
      references: [DE_AE_02, RS_AN_03],
      prompt: { en: 'Which statements are established by the evidence?', fr: 'Quelles affirmations les éléments permettent-ils d’établir ?' },
      options: [
        { id: 'rotation', correct: true, text: { en: '203.0.113.50 tried many different user names with passwords in a short time.', fr: '203.0.113.50 a essayé de nombreux noms d’utilisateur avec des mots de passe en peu de temps.' }, feedback: { en: 'Yes: twelve invalid user names in about a minute, then repeated attempts on root.', fr: 'Oui : douze noms invalides en une minute environ, puis des tentatives répétées sur root.' } },
        { id: 'root-success', correct: true, text: { en: 'A password login as root succeeded from the same address after the failures.', fr: 'Une connexion root par mot de passe a réussi depuis la même adresse après les échecs.' }, feedback: { en: 'Yes: "Accepted password for root from 203.0.113.50" right after nine failures.', fr: 'Oui : « Accepted password for root from 203.0.113.50 » juste après neuf échecs.' } },
        { id: 'account', correct: true, text: { en: 'The root session created an account "sysupdate" and added it to the sudo group.', fr: 'La session root a créé un compte « sysupdate » et l’a ajouté au groupe sudo.' }, feedback: { en: 'Yes: useradd and usermod run during the root session from the attacker address: a persistence mechanism.', fr: 'Oui : useradd et usermod pendant la session root ouverte depuis l’adresse de l’attaquant : un mécanisme de persistance.' } },
        { id: 'dba', correct: false, text: { en: 'The "dba" key login from 10.20.0.15 is part of the attack.', fr: 'La connexion par clé de « dba » depuis 10.20.0.15 fait partie de l’attaque.' }, feedback: { en: 'No: it comes from the office VPN range, uses the administrator key and precedes the attack, as the note describes.', fr: 'Non : elle vient de la plage du VPN du bureau, utilise la clé de l’administrateur et précède l’attaque, comme l’indique la note.' } },
        { id: 'exploit', correct: false, text: { en: 'The attacker exploited a vulnerability in the SSH server.', fr: 'L’attaquant a exploité une vulnérabilité du serveur SSH.' }, feedback: { en: 'Nothing supports this: the log shows password guessing that ends with a valid password, which needs no vulnerability.', fr: 'Rien ne l’indique : le journal montre des essais de mots de passe aboutissant à un mot de passe valide, sans vulnérabilité.' } },
      ],
    },
    {
      id: 'declare',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['auth', 'note'],
      references: [DE_AE_08],
      prompt: { en: 'How do you qualify the event?', fr: 'Comment qualifiez-vous l’événement ?' },
      options: [
        { id: 'incident', points: 10, text: { en: 'A security incident: an outside party has privileged access to the server.', fr: 'Un incident de sécurité : un tiers externe dispose d’un accès privilégié au serveur.' }, feedback: { en: 'Correct. Brute force alone is background noise on exposed SSH; a successful root login followed by account creation is a compromise.', fr: 'Exact. Une force brute seule est un bruit de fond sur un SSH exposé ; une connexion root réussie suivie d’une création de compte est une compromission.' } },
        { id: 'attempt', points: 3, text: { en: 'An unsuccessful attack attempt to keep under watch.', fr: 'Une tentative d’attaque infructueuse à surveiller.' }, feedback: { en: 'The attempt succeeded: "Accepted password for root" is in the log.', fr: 'La tentative a réussi : « Accepted password for root » figure dans le journal.' } },
        { id: 'noise', points: 0, text: { en: 'Internet background noise: no action needed.', fr: 'Du bruit de fond d’Internet : aucune action nécessaire.' }, feedback: { en: 'This ignores the successful login and the new privileged account.', fr: 'Cela ignore la connexion réussie et le nouveau compte privilégié.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['auth'],
      references: [RS_MI_01, RS_AN_07],
      prompt: { en: 'Which immediate containment actions do you take?', fr: 'Quelles mesures de confinement immédiates prenez-vous ?' },
      options: [
        { id: 'restrict', correct: true, text: { en: 'Restrict SSH on ledger-db to the office VPN range at the firewall.', fr: 'Restreindre SSH sur ledger-db à la plage du VPN du bureau au niveau du pare-feu.' }, feedback: { en: 'Cuts off this attacker and any other source at once, without stopping the database for its users.', fr: 'Coupe cet attaquant et toute autre source d’un coup, sans arrêter la base pour ses utilisateurs.' } },
        { id: 'lock', correct: true, text: { en: 'Lock the "sysupdate" account and change the root password.', fr: 'Verrouiller le compte « sysupdate » et changer le mot de passe root.' }, feedback: { en: 'Removes the access the attacker is known to hold. Note the account details before changing anything.', fr: 'Retire les accès connus de l’attaquant. Notez les détails du compte avant toute modification.' } },
        { id: 'preserve', correct: true, text: { en: 'Copy the logs and record current sessions and processes before changing the system.', fr: 'Copier les journaux et relever les sessions et processus en cours avant de modifier le système.' }, feedback: { en: 'Volatile evidence disappears with the next actions; collect it first.', fr: 'Les éléments volatils disparaissent avec les actions suivantes ; collectez-les d’abord.' } },
        { id: 'reboot', correct: false, text: { en: 'Reboot the server to end the attacker session.', fr: 'Redémarrer le serveur pour couper la session de l’attaquant.' }, feedback: { en: 'Destroys memory and session evidence and does not remove the account or the password the attacker knows.', fr: 'Détruit les traces en mémoire et de session sans retirer le compte ni le mot de passe connus de l’attaquant.' } },
        { id: 'wipe', correct: false, text: { en: 'Clear auth.log so the attacker cannot read it.', fr: 'Vider auth.log pour que l’attaquant ne puisse pas le lire.' }, feedback: { en: 'This destroys the main evidence of the incident.', fr: 'Cela détruit la principale preuve de l’incident.' } },
      ],
    },
    {
      id: 'scope',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['auth', 'note'],
      references: [RS_AN_03],
      prompt: { en: 'What do you check next to scope the compromise?', fr: 'Que vérifiez-vous ensuite pour mesurer l’étendue de la compromission ?' },
      options: [
        { id: 'persistence', points: 10, text: { en: 'Other persistence and actions of the session: SSH authorized_keys, cron jobs, services, shell history, database access, other servers sharing the root password.', fr: 'Les autres persistances et actions de la session : authorized_keys SSH, tâches cron, services, historique du shell, accès à la base, autres serveurs partageant le mot de passe root.' }, feedback: { en: 'Yes: one account was found, others may exist, and a password reused on other servers extends the scope.', fr: 'Oui : un compte a été trouvé, d’autres persistances peuvent exister, et un mot de passe réutilisé ailleurs étend le périmètre.' } },
        { id: 'geo', points: 2, text: { en: 'The country of 203.0.113.50.', fr: 'Le pays de 203.0.113.50.' }, feedback: { en: 'Of little use: the address is easily rented anywhere and does not tell what was done on the server.', fr: 'Peu utile : l’adresse se loue facilement n’importe où et n’indique pas ce qui a été fait sur le serveur.' } },
        { id: 'version', points: 0, text: { en: 'Only the OpenSSH version.', fr: 'Uniquement la version d’OpenSSH.' }, feedback: { en: 'The entry point is a guessed password, not a software flaw.', fr: 'Le point d’entrée est un mot de passe deviné, pas une faille logicielle.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['note'],
      references: [RS_MI_02, PR_AA_03, mitigation('M1032', 'Multi-factor Authentication'), mitigation('M1027', 'Password Policies'), mitigation('M1042', 'Disable or Remove Feature or Program')],
      prompt: { en: 'Which remediation measures prevent a recurrence?', fr: 'Quelles mesures de remédiation empêchent que cela se reproduise ?' },
      options: [
        { id: 'keys-only', correct: true, text: { en: 'Disable password authentication and direct root login over SSH; keep key-based access for named accounts.', fr: 'Désactiver l’authentification par mot de passe et la connexion root directe en SSH ; garder un accès par clé pour des comptes nominatifs.' }, feedback: { en: 'Removes the guessable entry point.', fr: 'Supprime le point d’entrée devinable.' } },
        { id: 'vpn', correct: true, text: { en: 'Keep SSH reachable only through the VPN, with multi-factor authentication on the VPN.', fr: 'Ne laisser SSH joignable que par le VPN, avec authentification multifacteur sur le VPN.' }, feedback: { en: 'Reduces exposure and adds a second factor.', fr: 'Réduit l’exposition et ajoute un second facteur.' } },
        { id: 'rotate', correct: true, text: { en: 'Change every password that matched the installation root password, on all servers.', fr: 'Changer tous les mots de passe identiques au mot de passe root d’installation, sur tous les serveurs.' }, feedback: { en: 'The attacker knows it; reuse elsewhere would leave other doors open.', fr: 'L’attaquant le connaît ; sa réutilisation ailleurs laisserait d’autres portes ouvertes.' } },
        { id: 'port', correct: false, text: { en: 'Move SSH to port 2222 and consider the issue closed.', fr: 'Déplacer SSH sur le port 2222 et considérer le problème réglé.' }, feedback: { en: 'Reduces log noise but does not stop a targeted guess of a weak password.', fr: 'Réduit le bruit dans les journaux mais n’arrête pas un essai ciblé d’un mot de passe faible.' } },
        { id: 'reinstall-ssh', correct: false, text: { en: 'Reinstall the SSH server package.', fr: 'Réinstaller le paquet du serveur SSH.' }, feedback: { en: 'The package was not at fault; the configuration and the password were.', fr: 'Le paquet n’était pas en cause ; la configuration et le mot de passe l’étaient.' } },
      ],
    },
  ],
  debrief: {
    en: 'An automated attacker tried common user names, then guessed the root password, which had been left from the installation. Within two minutes it created "sysupdate" with sudo rights to keep access. Restricting SSH to the VPN and locking the account contained it; removing password logins and changing the reused password closed the entry point.',
    fr: 'Un attaquant automatisé a essayé des noms d’utilisateur courants, puis deviné le mot de passe root resté de l’installation. En deux minutes, il a créé « sysupdate » avec des droits sudo pour conserver l’accès. Restreindre SSH au VPN et verrouiller le compte ont contenu l’attaque ; supprimer les connexions par mot de passe et changer le mot de passe réutilisé ont fermé le point d’entrée.',
  },
  lessons: [
    { en: 'Brute force is noise until one attempt succeeds: alert on success after failures, not on failures alone.', fr: 'La force brute est du bruit jusqu’à ce qu’une tentative réussisse : alertez sur un succès après des échecs, pas sur les échecs seuls.' },
    { en: 'Collect logs and session state before rebooting or changing accounts.', fr: 'Collectez journaux et état des sessions avant de redémarrer ou de modifier des comptes.' },
    { en: 'Look for persistence: a new account is rarely the only one.', fr: 'Cherchez les persistances : un nouveau compte est rarement le seul.' },
  ],
};
