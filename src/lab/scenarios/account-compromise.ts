import type { Scenario } from '../model';
import { DE_AE_03, mitigation, PR_AA_03, RS_AN_03, RS_AN_08, RS_MI_01, RS_MI_02 } from '../references';
import { iso, jsonLines } from './helpers';

const DAY = '2026-02-17';
const push = (seconds: number, result: string) => ({ timestamp: iso(DAY, seconds), user: 'n.leroy', src_ip: '203.0.113.201', app: 'identity', message: `MFA push sent to registered phone: ${result}` });

const signIns = jsonLines([
  { timestamp: iso(DAY, 22 * 3600 + 40 * 60), user: 'n.leroy', src_ip: '203.0.113.201', app: 'identity', message: 'Password correct, MFA required' },
  push(22 * 3600 + 40 * 60 + 5, 'denied'),
  push(22 * 3600 + 41 * 60, 'no answer'),
  push(22 * 3600 + 42 * 60, 'denied'),
  push(22 * 3600 + 43 * 60, 'no answer'),
  push(22 * 3600 + 44 * 60, 'denied'),
  push(22 * 3600 + 51 * 60, 'approved'),
  { timestamp: iso(DAY, 22 * 3600 + 51 * 60 + 20), user: 'n.leroy', src_ip: '203.0.113.201', app: 'identity', message: 'New MFA method registered: authenticator app on unknown device' },
  { timestamp: iso(DAY, 22 * 3600 + 53 * 60), user: 'n.leroy', src_ip: '203.0.113.201', app: 'mail', message: 'Inbox rule created: forward all messages to n.leroy.archive@mailbox-drop.example' },
  { timestamp: iso(DAY, 22 * 3600 + 58 * 60), user: 'n.leroy', src_ip: '203.0.113.201', app: 'files', message: 'Downloaded 214 files from the "Clients" shared library' },
]);

const statement = `Statement from n.leroy (next morning)
"My phone kept buzzing last night with login requests. I refused a few, then I accepted one so that it would stop. I did not log in myself."`;

export const accountCompromise: Scenario = {
  id: 'account-compromise',
  version: 1,
  title: { en: 'Account takeover by push fatigue', fr: 'Prise de contrôle de compte par fatigue des notifications' },
  difficulty: 'intermediate',
  minutes: 15,
  techniques: ['T1078.004', 'T1621', 'T1114', 'T1530'],
  context: {
    en: 'A consultancy (fictitious) uses cloud identity with password plus push approval on a phone. Mail and documents are in the same cloud suite.',
    fr: 'Un cabinet de conseil (fictif) utilise une identité en ligne avec mot de passe et validation par notification sur téléphone. Messagerie et documents sont dans la même suite en ligne.',
  },
  incident: {
    en: 'In the morning, the identity provider flags "New MFA method registered" for n.leroy, a senior consultant. You review the sign-in log and talk to the user.',
    fr: 'Le matin, le fournisseur d’identité signale « Nouvelle méthode MFA enregistrée » pour n.leroy, consultant senior. Vous examinez le journal de connexion et interrogez l’utilisateur.',
  },
  evidence: [
    { id: 'signins', kind: 'log', title: { en: 'Identity and application log (JSON Lines)', fr: 'Journal d’identité et des applications (JSON Lines)' }, content: signIns, logFormat: 'json' },
    { id: 'statement', kind: 'note', title: { en: 'User statement', fr: 'Déclaration de l’utilisateur' }, content: statement },
  ],
  steps: [
    {
      id: 'what',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['signins', 'statement'],
      references: [DE_AE_03, RS_AN_03],
      prompt: { en: 'What happened, according to the evidence?', fr: 'Que s’est-il passé, d’après les éléments ?' },
      options: [
        { id: 'password', correct: true, text: { en: 'The attacker already had the password.', fr: 'L’attaquant avait déjà le mot de passe.' }, feedback: { en: '"Password correct, MFA required" from an outside address.', fr: '« Password correct, MFA required » depuis une adresse externe.' } },
        { id: 'fatigue', correct: true, text: { en: 'Repeated push requests until the user approved one.', fr: 'Des demandes de validation répétées jusqu’à ce que l’utilisateur en accepte une.' }, feedback: { en: 'MFA request generation, also called push fatigue.', fr: 'Génération de demandes MFA, aussi appelée fatigue des notifications.' } },
        { id: 'persistence', correct: true, text: { en: 'A new MFA method and a forwarding rule were added to keep access.', fr: 'Une nouvelle méthode MFA et une règle de transfert ont été ajoutées pour garder l’accès.' }, feedback: { en: 'Both survive a simple password change.', fr: 'Les deux survivent à un simple changement de mot de passe.' } },
        { id: 'device', correct: false, text: { en: 'The user’s phone is infected.', fr: 'Le téléphone de l’utilisateur est infecté.' }, feedback: { en: 'Nothing suggests it: the phone received genuine requests.', fr: 'Rien ne l’indique : le téléphone a reçu de vraies demandes.' } },
      ],
    },
    {
      id: 'impact',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['signins'],
      references: [RS_AN_08],
      prompt: { en: 'How do you assess the impact?', fr: 'Comment évaluez-vous l’impact ?' },
      options: [
        { id: 'breach', points: 10, text: { en: 'Probable data breach: client files were downloaded and mail is being forwarded outside.', fr: 'Violation de données probable : des fichiers clients ont été téléchargés et le courrier est transféré à l’extérieur.' }, feedback: { en: 'This may trigger notification duties toward clients and authorities.', fr: 'Cela peut déclencher des obligations de notification envers les clients et les autorités.' } },
        { id: 'minor', points: 2, text: { en: 'Minor: the account was only used for a few minutes.', fr: 'Mineur : le compte n’a été utilisé que quelques minutes.' }, feedback: { en: '214 files in seven minutes and ongoing forwarding are significant.', fr: '214 fichiers en sept minutes et un transfert en cours sont significatifs.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['signins'],
      references: [RS_MI_01, PR_AA_03],
      prompt: { en: 'Which containment actions do you take?', fr: 'Quelles actions de confinement prenez-vous ?' },
      options: [
        { id: 'revoke', correct: true, text: { en: 'Reset the password and revoke all sessions and refresh tokens.', fr: 'Réinitialiser le mot de passe et révoquer toutes les sessions et jetons de rafraîchissement.' }, feedback: { en: 'Sessions outlive a password change.', fr: 'Les sessions survivent à un changement de mot de passe.' } },
        { id: 'mfa', correct: true, text: { en: 'Remove the MFA method registered by the attacker.', fr: 'Supprimer la méthode MFA enregistrée par l’attaquant.' }, feedback: { en: 'Otherwise the attacker can approve their own sign-ins.', fr: 'Sinon, l’attaquant peut valider ses propres connexions.' } },
        { id: 'rule', correct: true, text: { en: 'Record, then delete, the forwarding rule.', fr: 'Relever puis supprimer la règle de transfert.' }, feedback: { en: 'Stops the ongoing leak.', fr: 'Arrête la fuite en cours.' } },
        { id: 'new-phone', correct: false, text: { en: 'Replace the user’s phone and change nothing else.', fr: 'Remplacer le téléphone de l’utilisateur et ne rien changer d’autre.' }, feedback: { en: 'The phone was not compromised; the account was.', fr: 'Le téléphone n’était pas compromis ; le compte l’était.' } },
      ],
    },
    {
      id: 'origin',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['signins'],
      references: [RS_AN_03],
      prompt: { en: 'What do you investigate about the password?', fr: 'Que recherchez-vous au sujet du mot de passe ?' },
      options: [
        { id: 'leak', points: 10, text: { en: 'How it was obtained (reuse on another site, earlier phishing) and whether other accounts share it.', fr: 'Comment il a été obtenu (réutilisation sur un autre site, hameçonnage antérieur) et si d’autres comptes le partagent.' }, feedback: { en: 'The root cause is the known password, not the push.', fr: 'La cause profonde est le mot de passe connu, pas la notification.' } },
        { id: 'nothing', points: 0, text: { en: 'Nothing: MFA was the failure.', fr: 'Rien : c’est la MFA qui a échoué.' }, feedback: { en: 'Without the password, the push requests would never have been sent.', fr: 'Sans le mot de passe, aucune notification n’aurait été envoyée.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: ['statement'],
      references: [RS_MI_02, mitigation('M1032', 'Multi-factor Authentication'), mitigation('M1017', 'User Training'), mitigation('M1036', 'Account Use Policies')],
      prompt: { en: 'Which measures prevent a repeat?', fr: 'Quelles mesures empêchent une récidive ?' },
      options: [
        { id: 'number-match', correct: true, text: { en: 'Require number matching or phishing-resistant authentication instead of simple approve buttons.', fr: 'Exiger la saisie d’un nombre ou une authentification résistante à l’hameçonnage au lieu d’un simple bouton d’approbation.' }, feedback: { en: 'An approval needs information the attacker sees, not the user’s fatigue.', fr: 'L’approbation exige une information que voit l’attaquant, pas la lassitude de l’utilisateur.' } },
        { id: 'rate', correct: true, text: { en: 'Limit and alert on repeated push requests.', fr: 'Limiter les notifications répétées et alerter sur celles-ci.' }, feedback: { en: 'Five denials in a row are a clear signal.', fr: 'Cinq refus d’affilée sont un signal clair.' } },
        { id: 'teach', correct: true, text: { en: 'Tell users to report unexpected requests and never approve them.', fr: 'Demander aux utilisateurs de signaler les demandes inattendues et de ne jamais les approuver.' }, feedback: { en: 'The user noticed but had no instruction.', fr: 'L’utilisateur a remarqué mais n’avait pas de consigne.' } },
        { id: 'disable-mfa', correct: false, text: { en: 'Turn MFA off because it annoys users.', fr: 'Désactiver la MFA parce qu’elle gêne les utilisateurs.' }, feedback: { en: 'MFA stopped the first five attempts.', fr: 'La MFA a arrêté les cinq premières tentatives.' } },
      ],
    },
  ],
  debrief: {
    en: 'With a password obtained elsewhere, the attacker triggered repeated push requests late at night until n.leroy approved one. They registered their own MFA method, forwarded the mailbox outside and downloaded client files. Revoking sessions, removing the method and the rule contained it; number matching and alerting on repeated requests prevent it.',
    fr: 'Avec un mot de passe obtenu ailleurs, l’attaquant a déclenché des notifications répétées tard le soir jusqu’à ce que n.leroy en accepte une. Il a enregistré sa propre méthode MFA, transféré la boîte à l’extérieur et téléchargé des fichiers clients. Révoquer les sessions, supprimer la méthode et la règle ont contenu l’attaque ; la saisie d’un nombre et l’alerte sur les demandes répétées l’empêchent.',
  },
  lessons: [
    { en: 'Look for persistence in identity settings: MFA methods, mailbox rules, application consents.', fr: 'Cherchez la persistance dans les réglages d’identité : méthodes MFA, règles de messagerie, consentements d’applications.' },
    { en: 'An approved push after many denials is a compromise until proven otherwise.', fr: 'Une notification acceptée après plusieurs refus est une compromission jusqu’à preuve du contraire.' },
  ],
};
