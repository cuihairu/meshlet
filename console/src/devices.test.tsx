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
  diagnostics: null,
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
      // R-DIAG-2 富化字段（旧服务端可省略）。
      peer_name: 'hub-node',
      connection_mode: 'p2p_direct',
      endpoint: '192.168.1.50:51821',
      rtt_ms: 3,
      last_handshake_at: 1793507027,
      rx_bytes: 111,
      tx_bytes: 2048,
    },
    {
      public_key: 'pk-b',
      virtual_ipv4: '10.240.0.3',
      link_state: 'direct_pending',
      last_handshake_age_secs: null,
      connection_mode: 'direct_pending',
    },
  ],
  diagnostics: null,
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DevicesSection direct links', () => {
  it('renders P2P tags for direct peers and the relay hint when none', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge, hub]);
    render(<DevicesSection networkId="net-1" />);

    // edge 行：对 hub 的「P2P」标签（peer_name 优先于设备名回退）+ 对
    // pending 对端无 peer_name → 回退 overlay IP 的「P2P pending」标签。
    expect(await screen.findByText(/hub-node · P2P$/)).toBeTruthy();
    expect(screen.getByText(/10.240.0.3 · P2P pending/)).toBeTruthy();
    // hub 行：无直连链路 → 「全部经 hub 中继」提示。
    expect(screen.getAllByText(/all relay via hub/).length).toBeGreaterThan(0);
  });

  it('renders the enriched direct detail (endpoint · RTT · traffic) from new fields', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge, hub]);
    render(<DevicesSection networkId="net-1" />);

    // hub 直连链路携带 endpoint/RTT/流量 → 详情行可见。
    expect(await screen.findByText(/192\.168\.1\.50:51821/)).toBeTruthy();
    expect(screen.getByText(/3 ms/)).toBeTruthy();
    expect(screen.getByText(/111B↑ 2\.0K↓/)).toBeTruthy();
    // pending 对端无端点/流量 → 「暂无端点或流量」占位。
    expect(screen.getByText(/no endpoint or traffic yet/)).toBeTruthy();
  });
});
