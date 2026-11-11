import type { ModuleDefinition } from '../app/modules';
import { useI18n } from '../app/preferences-context';
import { PageHeader, Panel, StatusBadge } from '../components/ui';

/**
 * Honest placeholder for a module that is not implemented yet: it states that
 * nothing works and describes the intended scope, without mock data or controls.
 */
export default function PlannedModulePage({ module }: { module: ModuleDefinition }) {
  const { t } = useI18n();
  const milestone = t('status.milestone', { n: module.milestone }).toLowerCase();

  return (
    <>
      <PageHeader
        title={t(module.titleKey)}
        intro={module.summaryKey ? t(module.summaryKey) : undefined}
        aside={<StatusBadge status={module.status} milestone={module.milestone} />}
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title={t('planned.title')}>
          <p className="text-sm text-muted">{t('planned.body', { milestone })}</p>
        </Panel>
        {module.scopeKey ? (
          <Panel title={t('planned.scope')}>
            <p className="text-sm text-muted">{t(module.scopeKey)}</p>
          </Panel>
        ) : null}
      </div>
    </>
  );
}
