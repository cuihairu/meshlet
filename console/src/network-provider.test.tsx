import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { NetworkProvider } from './network-provider';
import { useNetwork } from './network-context';

const netA: api.Network = {
  id: 'net-a',
  name: 'alpha',
  overlay_cidr: '10.240.0.0/16',
  revision_id: 1,
  apply_status: 'applied',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
};
const netB: api.Network = { ...netA, id: 'net-b', name: 'beta' };

function Probe() {
  const { selectedId, selectedNetwork } = useNetwork();
  return (
    <div>
      <span data-testid="sel">{selectedId ?? 'none'}</span>
      <span data-testid="name">{selectedNetwork?.name ?? 'none'}</span>
    </div>
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('NetworkProvider selection', () => {
  it('auto-selects the first network when no stored selection exists', async () => {
    vi.spyOn(api.api, 'listNetworks').mockResolvedValue([netA, netB]);
    render(
      <NetworkProvider>
        <Probe />
      </NetworkProvider>,
    );
    await waitFor(() => expect(screen.getByTestId('sel').textContent).toBe('net-a'));
    expect(screen.getByTestId('name').textContent).toBe('alpha');
    expect(localStorage.getItem('meshlet-network')).toBe('net-a');
  });

  it('restores a persisted selection across reload', async () => {
    localStorage.setItem('meshlet-network', 'net-b');
    vi.spyOn(api.api, 'listNetworks').mockResolvedValue([netA, netB]);
    render(
      <NetworkProvider>
        <Probe />
      </NetworkProvider>,
    );
    await waitFor(() => expect(screen.getByTestId('sel').textContent).toBe('net-b'));
    expect(screen.getByTestId('name').textContent).toBe('beta');
  });

  it('drops a selection that no longer exists and falls back to first', async () => {
    localStorage.setItem('meshlet-network', 'net-gone');
    vi.spyOn(api.api, 'listNetworks').mockResolvedValue([netA]);
    render(
      <NetworkProvider>
        <Probe />
      </NetworkProvider>,
    );
    await waitFor(() => expect(screen.getByTestId('sel').textContent).toBe('net-a'));
  });
});
