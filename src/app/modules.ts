import type { MessageKey } from '../i18n';
import type { IconName } from '../components/Icon';

export type ModuleStatus = 'available' | 'planned';

export interface ModuleDefinition {
  id: string;
  /** Route path, relative to the application root. Empty string is the index route. */
  path: string;
  icon: IconName;
  titleKey: MessageKey;
  summaryKey?: MessageKey;
  scopeKey?: MessageKey;
  status: ModuleStatus;
  /** Milestone that delivers the module. */
  milestone: number;
}

/**
 * Single source of truth for navigation and for the status shown on the
 * overview. A module is only marked "available" once it is implemented and tested.
 */
export const MODULES: readonly ModuleDefinition[] = [
  { id: 'overview', path: '', icon: 'overview', titleKey: 'nav.overview', status: 'available', milestone: 0 },
  {
    id: 'threatIntel',
    path: 'threat-intel',
    icon: 'threatIntel',
    titleKey: 'nav.threatIntel',
    summaryKey: 'module.threatIntel.summary',
    scopeKey: 'module.threatIntel.scope',
    status: 'planned',
    milestone: 1,
  },
  {
    id: 'vulnerabilities',
    path: 'vulnerabilities',
    icon: 'vulnerabilities',
    titleKey: 'nav.vulnerabilities',
    summaryKey: 'module.vulnerabilities.summary',
    scopeKey: 'module.vulnerabilities.scope',
    status: 'planned',
    milestone: 1,
  },
  {
    id: 'soc',
    path: 'soc',
    icon: 'soc',
    titleKey: 'nav.soc',
    summaryKey: 'module.soc.summary',
    scopeKey: 'module.soc.scope',
    status: 'planned',
    milestone: 3,
  },
  {
    id: 'attack',
    path: 'attack',
    icon: 'attack',
    titleKey: 'nav.attack',
    summaryKey: 'module.attack.summary',
    scopeKey: 'module.attack.scope',
    status: 'planned',
    milestone: 1,
  },
  {
    id: 'toolbox',
    path: 'toolbox',
    icon: 'toolbox',
    titleKey: 'nav.toolbox',
    summaryKey: 'module.toolbox.summary',
    scopeKey: 'module.toolbox.scope',
    status: 'planned',
    milestone: 2,
  },
  {
    id: 'lab',
    path: 'lab',
    icon: 'lab',
    titleKey: 'nav.lab',
    summaryKey: 'module.lab.summary',
    scopeKey: 'module.lab.scope',
    status: 'planned',
    milestone: 4,
  },
  {
    id: 'settings',
    path: 'settings',
    icon: 'settings',
    titleKey: 'nav.settings',
    summaryKey: 'module.settings.summary',
    status: 'available',
    milestone: 0,
  },
];

export const PLANNED_MODULES = MODULES.filter((module) => module.status === 'planned');
