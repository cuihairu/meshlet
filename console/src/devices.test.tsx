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
  // P2P-⑤: the hub observed this device publicly → observed and public share the same value.
  observed_endpoint: '203.0.113.7:51820',
  public_endpoint: '203.0.113.7:51820',
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
  // Direct link to the hub established (last handshake 12s ago); the handshake with the pending peer is not complete yet.
  direct_links: [
    {
      public_key: 'pk-hub',
      virtual_ipv4: '10.240.0.1',
      link_state: 'direct',
      last_handshake_age_secs: 12,
      // R-DIAG-2 enriched fields (older servers may omit them).
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
  // P2P-⑤: the hub observed the device on the same LAN → observed kept, public absent.
  observed_endpoint: '192.168.1.11:51820',
  public_endpoint: null,
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DevicesSection direct links', () => {
  it('renders P2P tags for direct peers and the relay hint when none', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge, hub]);
    render(<DevicesSection networkId="net-1" />);

    // edge row: the "P2P" tag for the hub (peer_name preferred over the device-name fallback) +
    // the pending peer has no peer_name → fall back to the overlay IP "P2P pending" tag.
    expect(await screen.findByText(/hub-node · P2P$/)).toBeTruthy();
    expect(screen.getByText(/10.240.0.3 · P2P pending/)).toBeTruthy();
    // hub row: no direct links → the "all relay via hub" hint.
    expect(screen.getAllByText(/all relay via hub/).length).toBeGreaterThan(0);
  });

  it('renders the enriched direct detail (endpoint · RTT · traffic) from new fields', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge, hub]);
    render(<DevicesSection networkId="net-1" />);

    // The hub direct link carries endpoint/RTT/traffic → the detail line is visible.
    expect(await screen.findByText(/192\.168\.1\.50:51821/)).toBeTruthy();
    expect(screen.getByText(/3 ms/)).toBeTruthy();
    expect(screen.getByText(/111B↑ 2\.0K↓/)).toBeTruthy();
    // The pending peer has no endpoint/traffic → the "no endpoint or traffic yet" placeholder.
    expect(screen.getByText(/no endpoint or traffic yet/)).toBeTruthy();
  });

  it('renders hub-observed and public endpoints per device (P2P-⑤)', async () => {
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge, hub]);
    render(<DevicesSection networkId="net-1" />);

    // hub row: observed and public share the same value (public observation).
    expect(await screen.findByText(/observed 203\.0\.113\.7:51820/)).toBeTruthy();
    expect(screen.getByText(/public 203\.0\.113\.7:51820/)).toBeTruthy();
    // edge row: observed on the same LAN → observed present, no public (no public label that would mislead hole punching).
    expect(screen.getByText(/observed 192\.168\.1\.11:51820/)).toBeTruthy();
    expect(screen.queryByText(/public 192\.168\.1\.11:51820/)).toBeNull();
  });
});
