import type { MessageKey } from './en';

export const fr: Record<MessageKey, string> = {
  'app.tagline': 'Confidentialité d’abord. Guidé par le renseignement. Conçu pour les professionnels.',
  'app.loading': 'Chargement…',

  'nav.primary': 'Navigation principale',
  'nav.skip': 'Aller au contenu',
  'nav.openMenu': 'Ouvrir la navigation',
  'nav.closeMenu': 'Fermer la navigation',
  'nav.menuTitle': 'Navigation',
  'nav.overview': 'Vue d’ensemble',
  'nav.threatIntel': 'Renseignement sur les menaces',
  'nav.vulnerabilities': 'Centre des vulnérabilités',
  'nav.soc': 'Atelier SOC',
  'nav.attack': 'MITRE ATT&CK',
  'nav.toolbox': 'Boîte à outils',
  'nav.lab': 'Cyber Lab',
  'nav.settings': 'Paramètres et confidentialité',

  'lang.label': 'Langue',
  'lang.en': 'Anglais',
  'lang.fr': 'Français',

  'status.available': 'Disponible',
  'status.planned': 'Planifié',
  'status.milestone': 'Jalon {n}',

  'common.cancel': 'Annuler',
  'common.open': 'Ouvrir',

  'overview.title': 'Vue d’ensemble',
  'overview.intro':
    'Synthèse opérationnelle de cette version de BLACKWATCH. Chaque valeur affichée provient de ce navigateur ou des jeux de données publiés avec l’application.',
  'overview.modules.title': 'Modules',
  'overview.modules.note':
    'Les modules marqués comme planifiés ne sont pas encore fonctionnels. Ils n’exposent ni données ni commandes.',
  'overview.data.title': 'Jeux de données de renseignement',
  'overview.data.empty':
    'Aucun jeu de données de renseignement n’est publié avec cette version. Le pipeline de données statiques est prévu au jalon 1 ; d’ici là, aucun chiffre de vulnérabilité ou de menace n’est affiché.',
  'overview.storage.title': 'Stockage local',
  'overview.storage.ok':
    'IndexedDB est disponible. Les préférences et le travail sont stockés uniquement dans ce navigateur.',
  'overview.storage.unavailable':
    'IndexedDB est indisponible. Les préférences ne valent que pour cette session et rien n’est conservé.',
  'overview.storage.records': 'Enregistrements locaux : {n}',
  'overview.privacy.title': 'Modèle de confidentialité',
  'overview.privacy.body':
    'Aucun compte, aucune mesure d’audience, aucune télémétrie. L’application n’émet aucune requête vers des services tiers ; les fichiers importés sont traités dans ce navigateur.',

  'module.threatIntel.summary': 'Flux de menaces sélectionnés, explorateur d’IOC, référentiel d’acteurs.',
  'module.threatIntel.scope':
    'Validation et extraction d’IOC (IPv4, IPv6, domaines, URL, empreintes, adresses e-mail), flux avec attribution des sources, référentiel d’acteurs et de campagnes, notes d’investigation, export.',
  'module.vulnerabilities.summary': 'Recherche de CVE, CVSS, statut CISA KEV, listes de suivi.',
  'module.vulnerabilities.scope':
    'Recherche et détail des CVE, CVSS 3.1 et 4.0, références CWE, produits affectés, statut CISA KEV, priorisation transparente, listes de suivi, export CSV et PDF.',
  'module.soc.summary': 'Analyse locale de journaux, règles de détection, chronologie, investigations.',
  'module.soc.scope':
    'Import local de journaux JSON, CSV, syslog, authentification Linux, SSH, Apache, Nginx et Windows Event XML ; normalisation, filtrage, corrélation, règles de détection, chronologie, notes et rapports.',
  'module.attack.summary': 'Matrice Enterprise, techniques, groupes, logiciels, mesures d’atténuation.',
  'module.attack.scope':
    'Matrice ATT&CK Enterprise issue du jeu de données STIX officiel et versionné : tactiques, techniques, sous-techniques, groupes, logiciels, campagnes, mesures d’atténuation et leurs relations.',
  'module.toolbox.summary': 'Hachage, encodeurs, calculateurs réseau, décodeurs, visionneuses.',
  'module.toolbox.scope':
    'Utilitaires locaux : hachage SHA-2, Base64 et hexadécimal, entropie, décodage structurel de JWT, outils JSON, analyseur d’URL, extracteur d’IOC, testeur d’expressions régulières, calculateurs IPv4/IPv6/CIDR, références et visionneuses de règles.',
  'module.lab.summary': 'Scénarios synthétiques de réponse à incident avec notation.',
  'module.lab.scope':
    'Dix scénarios synthétiques de réponse à incident avec preuves, tâches d’investigation, points de décision, choix de confinement et de remédiation, notation et rapport final.',
  'module.settings.summary': 'Langue, apparence, maîtrise des données locales.',

  'planned.title': 'Pas encore disponible',
  'planned.body':
    'Ce module est prévu au {milestone}. Rien n’est encore fonctionnel sur cette page et aucune donnée n’est affichée.',
  'planned.scope': 'Périmètre prévu',

  'settings.title': 'Paramètres et confidentialité',
  'settings.intro': 'Les préférences sont stockées dans ce navigateur. Rien n’est envoyé à un serveur.',
  'settings.language.title': 'Langue',
  'settings.theme.title': 'Thème',
  'settings.theme.dark': 'Sombre',
  'settings.theme.light': 'Clair',
  'settings.theme.system': 'Système',
  'settings.density.title': 'Densité de l’interface',
  'settings.density.comfortable': 'Confortable',
  'settings.density.compact': 'Compacte',
  'settings.motion.title': 'Animations',
  'settings.motion.system': 'Système',
  'settings.motion.reduced': 'Réduites',
  'settings.motion.full': 'Complètes',
  'settings.appearance.title': 'Apparence',
  'settings.data.title': 'Données locales',
  'settings.data.help':
    'Tout ce que BLACKWATCH conserve se trouve dans la base IndexedDB de ce profil de navigateur. Vous pouvez l’exporter ou l’effacer à tout moment.',
  'settings.data.table': 'Magasin',
  'settings.data.count': 'Enregistrements',
  'settings.data.store.kv': 'Préférences',
  'settings.data.store.favorites': 'Favoris',
  'settings.data.store.notes': 'Notes',
  'settings.data.store.investigations': 'Investigations',
  'settings.data.store.labProgress': 'Progression d’entraînement',
  'settings.data.store.cache': 'Cache des jeux de données',
  'settings.data.export': 'Exporter les données locales',
  'settings.data.exported': 'Export généré : {file}',
  'settings.data.delete': 'Supprimer les données locales',
  'settings.data.deleteConfirmTitle': 'Supprimer toutes les données locales ?',
  'settings.data.deleteConfirmBody':
    'Les préférences, favoris, notes, investigations, la progression d’entraînement et les jeux de données en cache stockés dans ce navigateur seront définitivement effacés. Cette action est irréversible.',
  'settings.data.deleteConfirm': 'Tout supprimer',
  'settings.data.deleted':
    'Données locales supprimées. Les préférences ont été réinitialisées à leurs valeurs par défaut.',
  'settings.data.error': 'L’opération a échoué : le stockage local est indisponible.',
  'settings.data.unavailable': 'Le stockage local est indisponible dans cette session de navigateur.',
  'settings.pending.title': 'Pas encore disponible',
  'settings.pending.body':
    'La gestion des favoris et les commandes du cache des jeux de données arriveront avec les modules qui les utilisent (à partir du jalon 1).',
  'settings.version.title': 'Version',
  'settings.version.app': 'Application',
  'settings.version.schema': 'Schéma de la base locale',
  'settings.privacy.title': 'Confidentialité',
  'settings.privacy.p1':
    'BLACKWATCH n’a ni comptes, ni mesure d’audience, ni publicité, ni télémétrie, ni prise d’empreinte. Aucun script ni police tiers n’est embarqué.',
  'settings.privacy.p2':
    'Le navigateur ne demande que des fichiers hébergés avec l’application elle-même. Les jeux de données de renseignement sont préparés à l’avance et publiés sous forme de fichiers statiques ; votre navigateur ne contacte jamais les fournisseurs de renseignement.',
  'settings.privacy.p3':
    'L’hébergeur (GitHub Pages) voit néanmoins les métadonnées de connexion habituelles, comme votre adresse IP, lors du téléchargement de l’application. La politique de sécurité du contenu est fournie par un élément meta, moins robuste que des en-têtes de réponse HTTP.',

  'storage.banner':
    'Le stockage local est indisponible : les préférences et le travail ne seront pas conservés après cette session.',

  'notFound.title': 'Page introuvable',
  'notFound.body': 'Aucune page ne correspond à {path}.',
  'notFound.back': 'Retour à la vue d’ensemble',

  'error.title': 'Une erreur est survenue',
  'error.body': 'Cette vue n’a pas pu s’afficher. Vos données locales n’ont pas été modifiées.',
  'error.reload': 'Recharger l’application',
};
