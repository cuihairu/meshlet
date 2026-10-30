import { createContext, useContext } from 'react';
import type { Network } from './api';

/**
 * The selected network is console-global state: every domain page (/access,
 * /devices, /diagnostics) operates on it, and the top bar can switch it.
 * [NetworkProvider] owns the list and the selection so pages stay props-free.
 */
export interface NetworkContextValue {
  networks: Network[];
  loading: boolean;
  error: string | null;
  selectedId: string | null;
  selectedNetwork: Network | null;
  select: (id: string | null) => void;
  /** Reloads the network list; sections call it after a mutating action. */
  refresh: () => void;
}

export const NetworkContext = createContext<NetworkContextValue | null>(null);

export function useNetwork(): NetworkContextValue {
  const ctx = useContext(NetworkContext);
  if (!ctx) throw new Error('useNetwork must be used within NetworkProvider');
  return ctx;
}
