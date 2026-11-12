// Registers the service worker of production builds (offline application shell)
// and exposes whether a new version is waiting. A new version is only activated
// when the user asks for it, in the tab where they asked, so open work (an SOC
// import held in memory, an unsaved note) is never lost to an automatic reload.

type Listener = () => void;

export interface UpdateState {
  /** A new version is installed and waits for the user. */
  waiting: boolean;
}

let state: UpdateState = { waiting: false };
let waitingWorker: ServiceWorker | null = null;
const listeners = new Set<Listener>();

function setWaiting(worker: ServiceWorker | null) {
  waitingWorker = worker;
  state = { waiting: worker !== null };
  for (const listener of listeners) listener();
}

export function subscribeUpdate(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getUpdateState(): UpdateState {
  return state;
}

/** Activates the waiting version and reloads this tab once it controls the page. */
export function applyUpdate(): void {
  const worker = waitingWorker;
  if (!worker) return;
  let reloading = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloading) return;
    reloading = true;
    window.location.reload();
  });
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
    if (registration.waiting && navigator.serviceWorker.controller) setWaiting(registration.waiting);
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
  // The application stays open for long sessions: look for a new version when it is shown again.
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') void registration.update().catch(() => undefined);
  });
}
