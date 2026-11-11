import { lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { PLANNED_MODULES } from './modules';
import { Shell } from './Shell';

// Each view is its own chunk: the initial load only carries the shell.
const OverviewPage = lazy(() => import('../pages/OverviewPage'));
const SettingsPage = lazy(() => import('../pages/SettingsPage'));
const PlannedModulePage = lazy(() => import('../pages/PlannedModulePage'));
const NotFoundPage = lazy(() => import('../pages/NotFoundPage'));
const VulnerabilitiesPage = lazy(() => import('../pages/VulnerabilitiesPage'));
const CveDetailPage = lazy(() => import('../pages/CveDetailPage'));
const AttackPage = lazy(() => import('../pages/AttackPage'));
const AttackDetailPage = lazy(() => import('../pages/AttackDetailPage'));
const ThreatIntelPage = lazy(() => import('../pages/ThreatIntelPage'));

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<OverviewPage />} />
        {PLANNED_MODULES.map((module) => (
          <Route key={module.id} path={module.path} element={<PlannedModulePage module={module} />} />
        ))}
        <Route path="threat-intel" element={<ThreatIntelPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="vulnerabilities/:cveId" element={<CveDetailPage />} />
        <Route path="attack" element={<AttackPage />} />
        <Route path="attack/:attackId" element={<AttackDetailPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
