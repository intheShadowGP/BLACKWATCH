import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import { AppRoutes } from './app/AppRoutes';
import { PreferencesProvider } from './app/PreferencesProvider';
import { registerServiceWorker } from './pwa/register';
import './styles/index.css';

const container = document.getElementById('root');
if (!container) throw new Error('Root element is missing');

// Hash routing: GitHub Pages serves a single index.html and has no rewrite rules.
createRoot(container).render(
  <StrictMode>
    <PreferencesProvider>
      <HashRouter>
        <AppRoutes />
      </HashRouter>
    </PreferencesProvider>
  </StrictMode>,
);

// Production builds only: the development server serves modules that must not be cached. Registered
// after the page has loaded, so precaching the application does not compete with the first visit.
if (import.meta.env.PROD) {
  if (document.readyState === 'complete') void registerServiceWorker();
  else window.addEventListener('load', () => void registerServiceWorker(), { once: true });
}
