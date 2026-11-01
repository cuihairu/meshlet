import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { DirectPeersBlock } from './pages/diagnostics/DirectPeersBlock';

const device = (over: Partial<api.Device>): api.Device => ({
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
  direct_links: [],
  ...over,
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DirectPeersBlock', () => {
  it('renders direct links as rows with mode/endpoint/RTT/traffic', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([
      device({
        direct_links: [
          {
            public_key: 'pk-hub',
            virtual_ipv4: '10.240.0.1',
            link_state: 'direct',
            last_handshake_age_secs: 12,
            peer_name: 'hub-node',
            connection_mode: 'p2p_direct',
            endpoint: '192.168.1.50:51821',
            rtt_ms: 3,
            rx_bytes: 2048,
            tx_bytes: 111,
          },
        ],
      }),
    ]);
    render(<DirectPeersBlock networkId="net-1" />);

    // 列标题与各字段可见（原始数值不译，UI 标签按默认 en）。
    expect(await screen.findByText('edge')).toBeTruthy();
    expect(screen.getByText('hub-node')).toBeTruthy();
    expect(screen.getByText('P2P')).toBeTruthy();
    expect(screen.getByText('192.168.1.50:51821')).toBeTruthy();
    expect(screen.getByText('3 ms')).toBeTruthy();
    expect(screen.getByText(/2\.0K↑ 111B↓/)).toBeTruthy();
    expect(screen.getByText(/12s ago/)).toBeTruthy();
  });

  it('shows the empty hint when no device reports a direct link', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([device({ direct_links: [] })]);
    render(<DirectPeersBlock networkId="net-1" />);
    expect(await screen.findByText(/no device reported a direct link/)).toBeTruthy();
  });
});
