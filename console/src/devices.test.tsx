import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { DevicesSection } from './pages/devices/DevicesSection';

const hub: api.Device = {
  id: 'dev-hub',
  network_id: 'net-1',
  name: 'hub',
  virtual_ipv4: '10.240.0.1',
  public_key: 'pk-hub',
  fingerprint: 'fp-hub',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  last_seen_at: null,
  online_state: 'online',
  presence_source: 'agent_report',
  dataplane_evidence: null,
  approved_at: '2026-01-01T00:00:00Z',
  direct_links: [],
};

const edge: api.Device = {
  id: 'dev-edge',
  network_id: 'net-1',
  name: 'edge',
  virtual_ipv4: '10.240.0.2',
  public_key: 'pk-edge',
  fingerprint: 'fp-edge',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  last_seen_at: null,
  online_state: 'online',
  presence_source: 'agent_report',
  dataplane_evidence: null,
  approved_at: '2026-01-01T00:00:00Z',
  // 对 hub 已建立直连（握手 12s 前）；对 pending 对端尚未握上手。
  direct_links: [
    {
      public_key: 'pk-hub',
      virtual_ipv4: '10.240.0.1',
      link_state: 'direct',
      last_handshake_age_secs: 12,
    },
    {
      public_key: 'pk-b',
      virtual_ipv4: '10.240.0.3',
      link_state: 'direct_pending',
      last_handshake_age_secs: null,
    },
  ],
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DevicesSection direct links', () => {
  it('renders P2P tags for direct peers and the relay hint when none', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge, hub]);
    render(<DevicesSection networkId="net-1" />);

    // edge 行：对 hub 的「P2P」标签 + 对 pending 对端的「P2P pending」标签。
    expect(await screen.findByText(/hub · P2P/)).toBeTruthy();
    expect(screen.getByText(/10.240.0.3 · P2P pending/)).toBeTruthy();
    // hub 行：无直连链路 → 「全部经 hub 中继」提示。
    expect(screen.getAllByText(/all relay via hub/).length).toBeGreaterThan(0);
  });
});
