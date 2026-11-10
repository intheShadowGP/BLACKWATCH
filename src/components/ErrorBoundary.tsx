import { Component, type ReactNode } from 'react';
import { useI18n } from '../app/preferences-context';
import { Button } from './ui';

function ErrorFallback() {
  const { t } = useI18n();
  return (
    <div role="alert" className="rounded-sm border border-accent-fill bg-surface p-5">
      <h1 className="text-base font-semibold text-fg">{t('error.title')}</h1>
      <p className="mt-2 text-sm text-muted">{t('error.body')}</p>
      <Button className="mt-4" onClick={() => window.location.reload()}>
        {t('error.reload')}
      </Button>
    </div>
  );
}

/**
 * Contains rendering failures to the current view. The error itself is not
 * displayed: messages may embed untrusted input.
 */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override componentDidUpdate(previous: { resetKey?: string }): void {
    if (this.state.failed && previous.resetKey !== this.props.resetKey) {
      this.setState({ failed: false });
    }
  }

  override render(): ReactNode {
    return this.state.failed ? <ErrorFallback /> : this.props.children;
  }
}
