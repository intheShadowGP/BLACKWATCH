import { useEffect, useState } from 'react';
import { loadDataset, loadManifest, loadOverview, type DatasetResult, type ManifestResult, type OverviewResult } from './loader';
import type { DatasetId, DatasetTypes } from './schemas';

export type Loading = { status: 'loading' };

export function useDataset<K extends DatasetId>(id: K): DatasetResult<DatasetTypes[K]> | Loading {
  const [state, setState] = useState<{ id: K; result: DatasetResult<DatasetTypes[K]> } | null>(null);

  useEffect(() => {
    let cancelled = false;
    void loadDataset(id).then((result) => {
      if (!cancelled) setState({ id, result });
    });
    return () => {
      cancelled = true;
    };
  }, [id]);

  return state && state.id === id ? state.result : { status: 'loading' };
}

export function useManifest(): ManifestResult | Loading {
  const [state, setState] = useState<ManifestResult | Loading>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void loadManifest().then((result) => {
      if (!cancelled) setState(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

export function useOverview(): OverviewResult | Loading {
  const [state, setState] = useState<OverviewResult | Loading>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void loadOverview().then((result) => {
      if (!cancelled) setState(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
