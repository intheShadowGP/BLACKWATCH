import type { Scenario } from '../model';
import { DE_AE_03, mitigation, PR_AA_03, RS_AN_03, RS_AN_08, RS_MI_01, RS_MI_02 } from '../references';
import { iso, jsonLines } from './helpers';

const DAY = '2026-04-07';

const email = `Received: from mail.payroll-notice.example.net (198.51.100.23) by mx1.contoso-legal.example.com
From: "Payroll Department" <payroll@payroll-notice.example.net>
Reply-To: hr-support@payroll-notice.example.net
To: claire.martin@contoso-legal.example.com
Subject: ACTION REQUIRED: confirm your bank details before 18:00
Date: Tue, 7 Apr 2026 08:12:40 +0000
Authentication-Results: mx1.contoso-legal.example.com; spf=pass smtp.mailfrom=payroll-notice.example.net; dkim=none; dmarc=none

Dear employee,
Your April salary is on hold. Confirm your bank details before 18:00 today:
https://login-portal.payroll-notice.example.net/contoso-legal/verify
Payroll Department`;

const proxy = jsonLines([
  { timestamp: iso(DAY, 8 * 3600 + 14 * 60 + 2), src_ip: '10.40.3.27', user: 'claire.martin', method: 'GET', message: 'GET https://login-portal.payroll-notice.example.net/contoso-legal/verify 200', category: 'uncategorized' },
  { timestamp: iso(DAY, 8 * 3600 + 14 * 60 + 39), src_ip: '10.40.3.27', user: 'claire.martin', method: 'POST', message: 'POST https://login-portal.payroll-notice.example.net/contoso-legal/submit 302', category: 'uncategorized' },
  { timestamp: iso(DAY, 8 * 3600 + 15 * 60 + 5), src_ip: '10.40.3.31', user: 'paul.roux', method: 'GET', message: 'GET https://login-portal.payroll-notice.example.net/contoso-legal/verify 200', category: 'uncategorized' },
]);

const signIns = jsonLines([
  { timestamp: iso(DAY, 8 * 3600 + 21 * 60), user: 'claire.martin', src_ip: '203.0.113.140', message: 'Sign-in succeeded (password + SMS code) from an unfamiliar device', app: 'webmail' },
  { timestamp: iso(DAY, 8 * 3600 + 23 * 60), user: 'claire.martin', src_ip: '203.0.113.140', message: 'Mailbox rule created: move messages containing "invoice" to RSS Feeds', app: 'webmail' },
]);

export const phishing: Scenario = {
  id: 'phishing',
  version: 1,
  title: { en: 'Credential phishing in a law firm', fr: 'Hameçonnage d’identifiants dans un cabinet d’avocats' },
  difficulty: 'introductory',
  minutes: 15,
  techniques: ['T1566.002', 'T1078', 'T1114'],
  context: {
    en: 'Contoso Legal (a fictitious firm) uses a cloud webmail with SMS codes as a second factor. Staff can report suspicious messages to the IT desk.',
    fr: 'Contoso Legal (cabinet fictif) utilise une messagerie en ligne avec un code SMS comme second facteur. Le personnel peut signaler les messages suspects au service informatique.',
  },
  incident: {
    en: 'At 08:40 Paul reports an email about "salary on hold". He opened the link but did not type anything. You collect the message, the web proxy log and the webmail sign-in log.',
    fr: 'À 08 h 40, Paul signale un e-mail sur un « salaire bloqué ». Il a ouvert le lien sans rien saisir. Vous récupérez le message, le journal du proxy web et le journal de connexion de la messagerie.',
  },
  evidence: [
    { id: 'email', kind: 'email', title: { en: 'Reported email (headers and body)', fr: 'E-mail signalé (en-têtes et corps)' }, content: email },
    { id: 'proxy', kind: 'log', title: { en: 'Web proxy log (JSON Lines)', fr: 'Journal du proxy web (JSON Lines)' }, content: proxy, logFormat: 'json' },
    { id: 'signin', kind: 'log', title: { en: 'Webmail sign-in log (JSON Lines)', fr: 'Journal de connexion de la messagerie (JSON Lines)' }, content: signIns, logFormat: 'json' },
  ],
  steps: [
    {
      id: 'indicators',
      kind: 'investigation',
      mode: 'multiple',
      points: 10,
      evidence: ['email'],
      references: [DE_AE_03, mitigation('M1017', 'User Training')],
      prompt: { en: 'Which elements of the email indicate phishing?', fr: 'Quels éléments de l’e-mail indiquent un hameçonnage ?' },
      options: [
        { id: 'domain', correct: true, text: { en: 'The sender domain is not the firm’s own domain.', fr: 'Le domaine de l’expéditeur n’est pas celui du cabinet.' }, feedback: { en: 'Payroll messages come from the firm’s own domain or its known provider.', fr: 'Les messages de paie viennent du domaine du cabinet ou de son prestataire connu.' } },
        { id: 'urgency', correct: true, text: { en: 'Urgency and a threat on salary to push an immediate action.', fr: 'L’urgence et une menace sur le salaire pour pousser à agir immédiatement.' }, feedback: { en: 'Classic pressure lever.', fr: 'Levier de pression classique.' } },
        { id: 'link', correct: true, text: { en: 'A login link hosted on the sender’s look-alike domain.', fr: 'Un lien de connexion hébergé sur le domaine trompeur de l’expéditeur.' }, feedback: { en: 'The page imitates a login portal outside the firm.', fr: 'La page imite un portail de connexion hors du cabinet.' } },
        { id: 'spf', correct: false, text: { en: '"spf=pass" proves the message is legitimate.', fr: '« spf=pass » prouve que le message est légitime.' }, feedback: { en: 'SPF only shows the sending server is allowed for the attacker’s own domain; it says nothing about trust.', fr: 'SPF montre seulement que le serveur est autorisé pour le propre domaine de l’attaquant ; cela ne dit rien de sa fiabilité.' } },
      ],
    },
    {
      id: 'who',
      kind: 'investigation',
      mode: 'single',
      points: 10,
      evidence: ['proxy', 'signin'],
      references: [RS_AN_03, RS_AN_08],
      prompt: { en: 'What do the logs show about the users?', fr: 'Que montrent les journaux sur les utilisateurs ?' },
      options: [
        { id: 'claire', points: 10, text: { en: 'Claire submitted the form, then her account signed in from an outside address and created a mailbox rule.', fr: 'Claire a soumis le formulaire, puis son compte s’est connecté depuis une adresse externe et a créé une règle de messagerie.' }, feedback: { en: 'The POST, then a sign-in from 203.0.113.140 with an SMS code relayed in real time, then a hiding rule.', fr: 'Le POST, puis une connexion depuis 203.0.113.140 avec un code SMS relayé en temps réel, puis une règle de dissimulation.' } },
        { id: 'paul', points: 2, text: { en: 'Only Paul is affected, since he reported the email.', fr: 'Seul Paul est concerné, puisqu’il a signalé l’e-mail.' }, feedback: { en: 'Paul only loaded the page; Claire submitted credentials and was not the one who reported.', fr: 'Paul a seulement chargé la page ; Claire a soumis ses identifiants sans le signaler.' } },
        { id: 'nobody', points: 0, text: { en: 'Nobody is affected because the second factor protects the accounts.', fr: 'Personne n’est concerné, car le second facteur protège les comptes.' }, feedback: { en: 'A phishing page can relay the SMS code: the sign-in succeeded.', fr: 'Une page d’hameçonnage peut relayer le code SMS : la connexion a réussi.' } },
      ],
    },
    {
      id: 'declare',
      kind: 'decision',
      mode: 'single',
      points: 10,
      evidence: ['signin'],
      references: [RS_AN_08],
      prompt: { en: 'What is the right qualification?', fr: 'Quelle est la bonne qualification ?' },
      options: [
        { id: 'compromise', points: 10, text: { en: 'Account compromise with an active attacker in Claire’s mailbox.', fr: 'Compromission de compte avec un attaquant actif dans la boîte de Claire.' }, feedback: { en: 'The rule that hides "invoice" messages suggests preparation of invoice fraud.', fr: 'La règle qui masque les messages « facture » laisse présager une fraude au virement.' } },
        { id: 'spam', points: 0, text: { en: 'A spam campaign to block at the gateway.', fr: 'Une campagne de spam à bloquer à la passerelle.' }, feedback: { en: 'Blocking is needed but the campaign already succeeded once.', fr: 'Le blocage est utile mais la campagne a déjà réussi une fois.' } },
      ],
    },
    {
      id: 'contain',
      kind: 'containment',
      mode: 'multiple',
      points: 10,
      evidence: ['email', 'signin'],
      references: [RS_MI_01, PR_AA_03],
      prompt: { en: 'Which containment actions do you take now?', fr: 'Quelles actions de confinement prenez-vous maintenant ?' },
      options: [
        { id: 'reset', correct: true, text: { en: 'Reset Claire’s password and revoke all her active sessions.', fr: 'Réinitialiser le mot de passe de Claire et révoquer toutes ses sessions actives.' }, feedback: { en: 'A password change alone leaves the attacker’s session open.', fr: 'Changer le mot de passe seul laisse la session de l’attaquant ouverte.' } },
        { id: 'rule', correct: true, text: { en: 'Record, then remove, the mailbox rule.', fr: 'Relever puis supprimer la règle de messagerie.' }, feedback: { en: 'Keep it as evidence, then stop the hiding of messages.', fr: 'Gardez-la comme preuve, puis arrêtez la dissimulation.' } },
        { id: 'block', correct: true, text: { en: 'Block the phishing domain and purge copies of the email from all mailboxes.', fr: 'Bloquer le domaine d’hameçonnage et purger les copies de l’e-mail de toutes les boîtes.' }, feedback: { en: 'Stops further victims.', fr: 'Évite de nouvelles victimes.' } },
        { id: 'wipe', correct: false, text: { en: 'Reinstall Claire’s laptop.', fr: 'Réinstaller l’ordinateur de Claire.' }, feedback: { en: 'Nothing points to malware on the laptop: the credentials were typed into a web page.', fr: 'Rien n’indique de logiciel malveillant sur le poste : les identifiants ont été saisis dans une page web.' } },
      ],
    },
    {
      id: 'remediate',
      kind: 'remediation',
      mode: 'multiple',
      points: 10,
      evidence: [],
      references: [RS_MI_02, mitigation('M1032', 'Multi-factor Authentication'), mitigation('M1017', 'User Training'), mitigation('M1021', 'Restrict Web-Based Content')],
      prompt: { en: 'Which measures reduce the risk of a repeat?', fr: 'Quelles mesures réduisent le risque de récidive ?' },
      options: [
        { id: 'fido', correct: true, text: { en: 'Move to phishing-resistant authentication (security keys or passkeys).', fr: 'Passer à une authentification résistante à l’hameçonnage (clés de sécurité ou passkeys).' }, feedback: { en: 'SMS codes can be relayed by a fake page; origin-bound credentials cannot.', fr: 'Un code SMS peut être relayé par une fausse page ; des identifiants liés à l’origine ne le peuvent pas.' } },
        { id: 'rules-alert', correct: true, text: { en: 'Alert on new mailbox forwarding or hiding rules.', fr: 'Alerter sur toute nouvelle règle de transfert ou de masquage dans les boîtes.' }, feedback: { en: 'A frequent sign of mailbox takeover.', fr: 'Un signe fréquent de prise de contrôle de boîte.' } },
        { id: 'report', correct: true, text: { en: 'Thank Paul publicly and keep the reporting channel simple.', fr: 'Remercier Paul publiquement et garder le canal de signalement simple.' }, feedback: { en: 'Early reports shortened this incident.', fr: 'Un signalement précoce a raccourci cet incident.' } },
        { id: 'blame', correct: false, text: { en: 'Sanction Claire to set an example.', fr: 'Sanctionner Claire pour l’exemple.' }, feedback: { en: 'Punishment discourages reporting, which is the best early warning.', fr: 'Sanctionner décourage le signalement, qui est la meilleure alerte précoce.' } },
      ],
    },
  ],
  debrief: {
    en: 'A look-alike payroll message led Claire to a fake portal that relayed her password and SMS code. The attacker signed in within minutes and hid "invoice" messages, likely preparing invoice fraud. Revoking sessions, removing the rule and purging the campaign contained it.',
    fr: 'Un faux message de paie a conduit Claire vers un faux portail qui a relayé son mot de passe et son code SMS. L’attaquant s’est connecté en quelques minutes et a masqué les messages « facture », probablement pour préparer une fraude au virement. Révoquer les sessions, supprimer la règle et purger la campagne ont contenu l’attaque.',
  },
  lessons: [
    { en: 'One reporter does not mean one victim: check who else clicked and submitted.', fr: 'Un signalement ne signifie pas une seule victime : vérifiez qui d’autre a cliqué et saisi.' },
    { en: 'SMS and push codes can be relayed; phishing-resistant authentication cannot.', fr: 'Les codes SMS et push peuvent être relayés ; une authentification résistante à l’hameçonnage non.' },
  ],
};
