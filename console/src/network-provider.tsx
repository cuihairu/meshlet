import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { api, ApiError, type Network } from './api';
import { NetworkContext, type NetworkContextValue } from './network-context';

const STORAGE_KEY = 'meshlet-network';

function initialSelection(): string | null {
  const stored = localStorage.getItem(STORAGE_KEY);
  return stored || null;
}

/** Loads the network list and owns the console-global selection.
 *  The selection is persisted (survives refresh) and auto-selects the first
 *  network when nothing valid is chosen, so the network-scoped domains never
 *  start on a dead-end empty state. */
export function NetworkProvider({ children }: { children: ReactNode }) {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(initialSelection);

  const refresh = useCallback(() => {
    api
      .listNetworks()
      .then((rows) => {
        setNetworks(rows);
        setError(null);
        // Keep a selection that still exists; otherwise fall back to the first
        // network so the network-scoped domains have a working context.
        setSelectedId((prev) => {
          if (prev && rows.some((n) => n.id === prev)) return prev;
          if (rows.length > 0) {
            const first = rows[0].id;
            localStorage.setItem(STORAGE_KEY, first);
            return first;
          }
          localStorage.removeItem(STORAGE_KEY);
          return null;
        });
      })
      .catch((e) => {
        setNetworks([]);
        setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const select = useCallback((id: string | null) => {
    setSelectedId(id);
    if (id) {
      localStorage.setItem(STORAGE_KEY, id);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  const selectedNetwork = networks.find((n) => n.id === selectedId) ?? null;

  const value: NetworkContextValue = {
    networks,
    loading,
    error,
    selectedId,
    selectedNetwork,
    select,
    refresh,
  };

  return (
    <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>
  );
}
