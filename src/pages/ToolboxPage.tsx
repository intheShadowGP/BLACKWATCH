import { Suspense } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { Icon } from '../components/Icon';
import { PageHeader, Panel } from '../components/ui';
import type { MessageKey } from '../i18n';
import { CATEGORIES, TOOLS, findTool } from '../toolbox/registry';
import NotFoundPage from './NotFoundPage';

export function ToolboxIndexPage() {
  const { t } = useI18n();
  return (
    <>
      <PageHeader title={t('nav.toolbox')} intro={t('toolbox.intro')} />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {CATEGORIES.map((category) => {
          const tools = TOOLS.filter((tool) => tool.category === category);
          if (tools.length === 0) return null;
          return (
            <Panel key={category} title={t(`toolbox.category.${category}` as MessageKey)}>
              <ul className="-my-2 divide-y divide-line">
                {tools.map((tool) => (
                  <li key={tool.id}>
                    <Link to={`/toolbox/${tool.id}`} className="group block py-2 text-sm">
                      <span className="font-medium text-fg group-hover:underline">{t(tool.titleKey)}</span>
                      <span className="block text-muted">{t(tool.summaryKey)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
          );
        })}
      </div>
    </>
  );
}

export function ToolPage() {
  const { t } = useI18n();
  const { toolId = '' } = useParams();
  const tool = findTool(toolId);
  if (!tool) return <NotFoundPage />;
  const Component = tool.component;
  return (
    <>
      <Link to="/toolbox" className="mb-4 inline-flex items-center gap-2 text-sm text-muted hover:text-fg">
        <Icon name="arrow" className="rotate-180" />
        {t('toolbox.back')}
      </Link>
      <PageHeader title={t(tool.titleKey)} intro={t(tool.summaryKey)} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="min-w-0">
          <ErrorBoundary resetKey={tool.id}>
            <Suspense fallback={<p className="text-sm text-muted">{t('app.loading')}</p>}>
              <Component />
            </Suspense>
          </ErrorBoundary>
        </div>
        <aside aria-label={t('toolbox.limits')} className="self-start rounded-sm border border-line bg-surface p-4 text-sm">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-muted">{t('toolbox.limits')}</h2>
          <p className="text-muted">{t(tool.limitsKey)}</p>
        </aside>
      </div>
    </>
  );
}
