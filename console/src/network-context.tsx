import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { api, ApiError, type Network } from './api';

/**
 * The selected network is console-global state: every domain page (/access,
 * /devices, /diagnostics) operates on it, and the top bar can switch it. The
 * provider owns the network list and the selection so pages stay props-free.
 */
interface NetworkContextValue {
  networks: Network[];
  loading: boolean;
  error: string | null;
  selectedId: string | null;
  selectedNetwork: Network | null;
  select: (id: string | null) => void;
  /** Reloads the network list; sections call it after a mutating action. */
  refresh: () => void;
}

const NetworkContext = createContext<NetworkContextValue | null>(null);

export function NetworkProvider({ children }: { children: ReactNode }) {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .listNetworks()
      .then((rows) => {
        setNetworks(rows);
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

  return (
    <NetworkContext.Provider
      value={{
        networks,
        loading,
        error,
        selectedId,
        selectedNetwork,
        select: setSelectedId,
        refresh,
      }}
    >
      {children}
    </NetworkContext.Provider>
  );
}

export function useNetwork(): NetworkContextValue {
  const ctx = useContext(NetworkContext);
  if (!ctx) throw new Error('useNetwork must be used within NetworkProvider');
  return ctx;
}
