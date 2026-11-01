import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { DirectPeersBlock } from './pages/diagnostics/DirectPeersBlock';
import { NetworkSnapshotBlock } from './pages/diagnostics/NetworkSnapshotBlock';

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
  diagnostics: null,
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

describe('NetworkSnapshotBlock', () => {
  const snap = {
    collected_at: '2026-11-01T04:00:00Z',
    route_table: ['default via 10.0.0.1 dev eth0', '10.240.0.0/16 dev wg-mlt proto kernel'],
    interfaces: [
      { name: 'wg-mlt', ipv4: '10.240.0.4', prefix: 24, state: 'up', mtu: 1420 },
      { name: 'eth0', ipv4: '', prefix: null, state: 'up', mtu: 1500 },
    ],
    wg: [
      {
        public_key: 'pk-hub',
        endpoint: '106.14.216.177:51820',
        allowed_ips: '10.240.0.0/16',
        last_handshake: 1_730_000_000,
        rx_bytes: 4096,
        tx_bytes: 128,
      },
    ],
  };

  it('renders routes, interfaces and wg readings for a device that reported', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([device({ diagnostics: snap })]);
    render(<NetworkSnapshotBlock networkId="net-1" />);

    expect(await screen.findByText('edge')).toBeTruthy();
    // route table raw lines (whole <pre> is one text node → substring match)
    expect(screen.getByText(/default via 10\.0\.0\.1 dev eth0/)).toBeTruthy();
    // interface row
    expect(screen.getByText('wg-mlt')).toBeTruthy();
    expect(screen.getByText('10.240.0.4/24')).toBeTruthy();
    // wg row
    expect(screen.getByText('106.14.216.177:51820')).toBeTruthy();
    expect(screen.getByText('10.240.0.0/16')).toBeTruthy();
    expect(screen.getByText(/4\.0K↑ 128B↓/)).toBeTruthy();
    // absolute handshake time (same locale call the component makes)
    expect(
      screen.getByText(new Date(1_730_000_000 * 1000).toLocaleString()),
    ).toBeTruthy();
  });

  it('shows the empty hint when no device reported a snapshot', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([device({ diagnostics: null })]);
    render(<NetworkSnapshotBlock networkId="net-1" />);
    expect(await screen.findByText(/no device reported a network snapshot/)).toBeTruthy();
  });
});
