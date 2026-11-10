import { lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { PLANNED_MODULES } from './modules';
import { Shell } from './Shell';

// Each view is its own chunk: the initial load only carries the shell.
const OverviewPage = lazy(() => import('../pages/OverviewPage'));
const SettingsPage = lazy(() => import('../pages/SettingsPage'));
const PlannedModulePage = lazy(() => import('../pages/PlannedModulePage'));
const NotFoundPage = lazy(() => import('../pages/NotFoundPage'));

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<OverviewPage />} />
        {PLANNED_MODULES.map((module) => (
          <Route key={module.id} path={module.path} element={<PlannedModulePage module={module} />} />
        ))}
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
