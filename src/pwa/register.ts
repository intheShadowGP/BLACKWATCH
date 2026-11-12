// Registers the service worker of production builds (offline application shell)
// and exposes the update state. A new version is only activated when the user
// asks for it, and only the tab where they asked reloads, so open work (an SOC
// import held in memory, an unsaved note) is never lost to an automatic reload.
// Other open tabs are then served by the new version while still running the
// previous code: they are told to reload when convenient.

type Listener = () => void;

export interface UpdateState {
  /**
   * none: nothing to do. waiting: a new version is installed and waits for the user.
   * replaced: another tab activated a new version; this tab still runs the previous code.
   */
  status: 'none' | 'waiting' | 'replaced';
}

let state: UpdateState = { status: 'none' };
let waitingWorker: ServiceWorker | null = null;
let requestedHere = false;
const listeners = new Set<Listener>();

function setState(next: UpdateState) {
  state = next;
  for (const listener of listeners) listener();
}

export function subscribeUpdate(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getUpdateState(): UpdateState {
  return state;
}

/** Activates the waiting version (reloading this tab once it takes over), or reloads a replaced tab. */
export function applyUpdate(): void {
  if (state.status === 'replaced') {
    window.location.reload();
    return;
  }
  const worker = waitingWorker;
  if (!worker) return;
  requestedHere = true;
  worker.postMessage({ type: 'SKIP_WAITING' });
}

export async function registerServiceWorker(): Promise<void> {
  if (!('serviceWorker' in navigator)) return;
  let registration: ServiceWorkerRegistration | undefined;
  try {
    // Relative to the document: works under any hosting sub-path.
    registration = await navigator.serviceWorker.register('./sw.js', { scope: './' });
  } catch {
    // Offline support is an enhancement: the application works without it.
    return;
  }
  // Some environments (automation that blocks workers, for one) resolve without a registration.
  if (!registration) return;

  // A worker waiting while another one controls the page is an update. On a first visit there is
  // no controller yet and the new worker simply activates.
  const check = () => {
    if (registration.waiting && navigator.serviceWorker.controller) {
      waitingWorker = registration.waiting;
      setState({ status: 'waiting' });
    }
  };
  const watch = (installing: ServiceWorker | null) => {
    installing?.addEventListener('statechange', () => {
      if (installing.state === 'installed') check();
    });
  };
  check();
  // An installation may already be under way when registration resolves.
  watch(registration.installing);
  registration.addEventListener('updatefound', () => watch(registration.installing));

  let hadController = navigator.serviceWorker.controller !== null;
  let reloading = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (requestedHere) {
      if (!reloading) {
        reloading = true;
        window.location.reload();
      }
      return;
    }
    // The first worker taking control of this page is not an update.
    if (hadController) {
      waitingWorker = null;
      setState({ status: 'replaced' });
    }
    hadController = true;
  });

  // The application stays open for long sessions: look for a new version when it is shown again.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') void registration.update().catch(() => undefined);
  });
}
