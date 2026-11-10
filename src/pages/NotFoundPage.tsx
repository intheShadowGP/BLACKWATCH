import { Link, useLocation } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { Icon } from '../components/Icon';
import { PageHeader } from '../components/ui';

const MAX_PATH_LENGTH = 120;

export default function NotFoundPage() {
  const { t } = useI18n();
  const { pathname } = useLocation();
  // The path is attacker-controllable: it is truncated and rendered as text only.
  const path = pathname.length > MAX_PATH_LENGTH ? `${pathname.slice(0, MAX_PATH_LENGTH)}…` : pathname;

  return (
    <>
      <PageHeader title={t('notFound.title')} />
      <p className="break-all font-mono text-sm text-muted">{t('notFound.body', { path })}</p>
      <Link to="/" className="mt-4 inline-flex items-center gap-2 text-sm text-accent hover:underline">
        {t('notFound.back')}
        <Icon name="arrow" />
      </Link>
    </>
  );
}
