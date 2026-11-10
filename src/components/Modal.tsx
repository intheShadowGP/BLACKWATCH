import { useEffect, useId, useRef, type ReactNode } from 'react';
import { useI18n } from '../app/preferences-context';
import { Button } from './ui';

/**
 * Modal built on the native dialog element: the browser provides the focus
 * trap, Escape handling and inert background, with no injected styles
 * (which keeps the Content Security Policy free of 'unsafe-inline').
 */
export function Modal({
  open,
  onClose,
  labelledBy,
  describedBy,
  role,
  className = '',
  children,
}: {
  open: boolean;
  onClose: () => void;
  labelledBy: string;
  describedBy?: string;
  role?: 'alertdialog';
  className?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      role={role}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      onClose={onClose}
      onClick={(event) => {
        // A click that lands on the dialog element itself is a click on the backdrop.
        if (event.target === event.currentTarget) onClose();
      }}
      className={`bg-transparent text-fg backdrop:bg-scrim ${className}`}
    >
      {open ? children : null}
    </dialog>
  );
}

/** Confirmation step required before any destructive action. */
export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  body: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const titleId = useId();
  const bodyId = useId();
  return (
    <Modal
      open={open}
      onClose={onCancel}
      labelledBy={titleId}
      describedBy={bodyId}
      role="alertdialog"
      className="fixed inset-0 m-auto w-[min(28rem,calc(100vw-2rem))]"
    >
      <div className="rounded-sm border border-line-strong bg-surface p-5 shadow-2xl shadow-black/60">
        <h2 id={titleId} className="text-base font-semibold text-fg">
          {title}
        </h2>
        <p id={bodyId} className="mt-2 text-sm text-muted">
          {body}
        </p>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          {/* Cancel comes first so it receives initial focus: the safe choice is the default. */}
          <Button onClick={onCancel} autoFocus>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
