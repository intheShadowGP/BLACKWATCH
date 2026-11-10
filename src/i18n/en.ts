export const en = {
  'app.tagline': 'Privacy first. Intelligence driven. Built for professionals.',
  'app.loading': 'Loading…',

  'nav.primary': 'Main navigation',
  'nav.skip': 'Skip to content',
  'nav.openMenu': 'Open navigation',
  'nav.closeMenu': 'Close navigation',
  'nav.menuTitle': 'Navigation',
  'nav.overview': 'Overview',
  'nav.threatIntel': 'Threat Intelligence',
  'nav.vulnerabilities': 'Vulnerability Center',
  'nav.soc': 'SOC Workbench',
  'nav.attack': 'MITRE ATT&CK',
  'nav.toolbox': 'Security Toolbox',
  'nav.lab': 'Cyber Lab',
  'nav.settings': 'Settings & Privacy',

  'lang.label': 'Language',
  'lang.en': 'English',
  'lang.fr': 'French',

  'status.available': 'Available',
  'status.planned': 'Planned',
  'status.milestone': 'Milestone {n}',

  'common.cancel': 'Cancel',
  'common.open': 'Open',

  'overview.title': 'Overview',
  'overview.intro':
    'Operational summary of this BLACKWATCH build. Every figure on this page is read from this browser or from datasets published with the application.',
  'overview.modules.title': 'Modules',
  'overview.modules.note':
    'Modules marked as planned are not functional yet. They expose no data and no controls.',
  'overview.data.title': 'Intelligence datasets',
  'overview.data.empty':
    'No intelligence dataset is published with this build. The static data pipeline is planned for Milestone 1; until then no vulnerability or threat figures are shown.',
  'overview.storage.title': 'Local storage',
  'overview.storage.ok': 'IndexedDB is available. Preferences and work are stored in this browser only.',
  'overview.storage.unavailable':
    'IndexedDB is unavailable. Preferences apply to this session only and nothing is persisted.',
  'overview.storage.records': 'Local records: {n}',
  'overview.privacy.title': 'Privacy model',
  'overview.privacy.body':
    'No account, no analytics, no telemetry. The application makes no request to third-party services; files you import are processed in this browser.',

  'module.threatIntel.summary': 'Curated threat feeds, IOC explorer, threat actor reference.',
  'module.threatIntel.scope':
    'IOC validation and extraction (IPv4, IPv6, domains, URLs, hashes, email addresses), source-attributed feeds, threat actor and campaign reference, investigation notes, export.',
  'module.vulnerabilities.summary': 'CVE search, CVSS, CISA KEV status, watchlists.',
  'module.vulnerabilities.scope':
    'CVE search and detail, CVSS 3.1 and 4.0, CWE references, affected products, CISA KEV status, transparent prioritisation, watchlists, CSV and PDF export.',
  'module.soc.summary': 'Local log parsing, detection rules, timeline, investigations.',
  'module.soc.scope':
    'Local import of JSON, CSV, syslog, Linux authentication, SSH, Apache, Nginx and Windows Event XML logs; normalisation, filtering, correlation, detection rules, timeline, notes and reports.',
  'module.attack.summary': 'Enterprise matrix, techniques, groups, software, mitigations.',
  'module.attack.scope':
    'Enterprise ATT&CK matrix from the official versioned STIX dataset: tactics, techniques, sub-techniques, groups, software, campaigns, mitigations and their relationships.',
  'module.toolbox.summary': 'Hashing, encoders, network calculators, decoders, viewers.',
  'module.toolbox.scope':
    'Local utilities: SHA-2 hashing, Base64 and hexadecimal, entropy, JWT structural decoding, JSON tools, URL parser, IOC extractor, regex tester, IPv4/IPv6/CIDR calculators, references and rule viewers.',
  'module.lab.summary': 'Synthetic incident response scenarios with scoring.',
  'module.lab.scope':
    'Ten synthetic incident response scenarios with evidence, investigation tasks, decision points, containment and remediation choices, scoring and a final report.',
  'module.settings.summary': 'Language, appearance, local data control.',

  'planned.title': 'Not available yet',
  'planned.body':
    'This module is planned for {milestone}. Nothing on this page is functional yet and no data is shown.',
  'planned.scope': 'Planned scope',

  'settings.title': 'Settings & Privacy',
  'settings.intro': 'Preferences are stored in this browser. Nothing is sent to a server.',
  'settings.language.title': 'Language',
  'settings.theme.title': 'Theme',
  'settings.theme.dark': 'Dark',
  'settings.theme.light': 'Light',
  'settings.theme.system': 'System',
  'settings.density.title': 'Interface density',
  'settings.density.comfortable': 'Comfortable',
  'settings.density.compact': 'Compact',
  'settings.motion.title': 'Motion',
  'settings.motion.system': 'System',
  'settings.motion.reduced': 'Reduced',
  'settings.motion.full': 'Full',
  'settings.appearance.title': 'Appearance',
  'settings.data.title': 'Local data',
  'settings.data.help':
    'Everything BLACKWATCH stores lives in the IndexedDB database of this browser profile. You can export it or erase it at any time.',
  'settings.data.table': 'Store',
  'settings.data.count': 'Records',
  'settings.data.store.kv': 'Preferences',
  'settings.data.store.favorites': 'Favorites',
  'settings.data.store.notes': 'Notes',
  'settings.data.store.investigations': 'Investigations',
  'settings.data.store.labProgress': 'Training progress',
  'settings.data.store.cache': 'Dataset cache',
  'settings.data.export': 'Export local data',
  'settings.data.exported': 'Export generated: {file}',
  'settings.data.delete': 'Delete local data',
  'settings.data.deleteConfirmTitle': 'Delete all local data?',
  'settings.data.deleteConfirmBody':
    'Preferences, favorites, notes, investigations, training progress and cached datasets stored in this browser will be permanently erased. This cannot be undone.',
  'settings.data.deleteConfirm': 'Delete everything',
  'settings.data.deleted': 'Local data deleted. Preferences were reset to their defaults.',
  'settings.data.error': 'The operation failed: local storage is unavailable.',
  'settings.data.unavailable': 'Local storage is unavailable in this browser session.',
  'settings.pending.title': 'Not available yet',
  'settings.pending.body':
    'Favorites management and dataset cache controls arrive with the modules that use them (Milestone 1 onwards).',
  'settings.version.title': 'Version',
  'settings.version.app': 'Application',
  'settings.version.schema': 'Local database schema',
  'settings.privacy.title': 'Privacy',
  'settings.privacy.p1':
    'BLACKWATCH has no accounts, analytics, advertising, telemetry or fingerprinting. It ships no third-party scripts or fonts.',
  'settings.privacy.p2':
    'The browser only requests files hosted with the application itself. Intelligence datasets are prepared ahead of time and published as static files; your browser never contacts intelligence providers.',
  'settings.privacy.p3':
    'The hosting provider (GitHub Pages) can still see standard connection metadata such as your IP address when the application is downloaded. The Content Security Policy is delivered through a meta element, which is weaker than HTTP response headers.',

  'storage.banner':
    'Local storage is unavailable: preferences and work will not be kept after this session.',

  'notFound.title': 'Page not found',
  'notFound.body': 'No page matches {path}.',
  'notFound.back': 'Back to overview',

  'error.title': 'Something went wrong',
  'error.body': 'This view failed to render. Your local data has not been modified.',
  'error.reload': 'Reload the application',
} as const;

export type MessageKey = keyof typeof en;
