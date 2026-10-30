import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { api, ApiError, type Network } from './api';
import { NetworkContext, type NetworkContextValue } from './network-context';

/** Loads the network list and owns the console-global selection. */
export function NetworkProvider({ children }: { children: ReactNode }) {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api
      .listNetworks()
      .then((rows) => {
        setNetworks(rows);
        setError(null);
        // Drop a selection that no longer exists (deleted network).
        setSelectedId((prev) =>
          prev && rows.some((n) => n.id === prev) ? prev : null,
        );
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

  const selectedNetwork = networks.find((n) => n.id === selectedId) ?? null;

  const value: NetworkContextValue = {
    networks,
    loading,
    error,
    selectedId,
    selectedNetwork,
    select: setSelectedId,
    refresh,
  };

  return (
    <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>
  );
}
