import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import { AppRoutes } from './app/AppRoutes';
import { PreferencesProvider } from './app/PreferencesProvider';
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
