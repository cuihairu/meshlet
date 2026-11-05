import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type * as api from './api';
import { topologyState } from './lib/topology';
import { TopologyDiagram } from './pages/topology/TopologyDiagram';

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
  observed_endpoint: null,
  public_endpoint: null,
  ...over,
});

afterEach(() => {
  cleanup();
});

describe('topologyState', () => {
  it('classifies the three states from reported links only', () => {
    const direct = device({
      direct_links: [
        {
          public_key: 'pk-hub-node',
          virtual_ipv4: '10.240.0.3',
          link_state: 'direct',
          last_handshake_age_secs: 3,
          connection_mode: 'p2p_direct',
          rtt_ms: 4,
        },
      ],
    });
    const pending = device({
      direct_links: [
        {
          public_key: 'pk-hub-node',
          virtual_ipv4: '10.240.0.3',
          link_state: 'direct_pending',
          last_handshake_age_secs: null,
          connection_mode: 'direct_pending',
        },
      ],
    });
    // 建立直连 → direct；仅 pending 不算（流量仍走 hub 中继）。
    expect(topologyState([direct, device({ id: 'd2', name: 'b' })])).toBe('direct');
    expect(topologyState([pending, device({ id: 'd2', name: 'b' })])).toBe('relay-only');
    expect(topologyState([device({})])).toBe('single');
    expect(topologyState([])).toBe('single');
  });
});

describe('TopologyDiagram three rendering states (TOPO-1)', () => {
  it('state direct: solid chord with RTT label, honest online_state per node', () => {
    const a = device({
      direct_links: [
        {
          public_key: 'pk-b',
          virtual_ipv4: '10.240.0.3',
          link_state: 'direct',
          last_handshake_age_secs: 7,
          peer_name: 'branch',
          connection_mode: 'p2p_direct',
          endpoint: '192.168.1.60:51821',
          rtt_ms: 3,
        },
      ],
    });
    const b = device({ id: 'dev-branch', name: 'branch', virtual_ipv4: '10.240.0.3' });
    const { container } = render(<TopologyDiagram devices={[a, b]} />);

    // hub + both node cards with name / virtual IP / reported online_state
    expect(screen.getByText('Hub')).toBeTruthy();
    expect(screen.getByText('edge')).toBeTruthy();
    expect(screen.getByText('branch')).toBeTruthy();
    expect(screen.getAllByText('10.240.0.2').length).toBeGreaterThan(0);
    expect(screen.getAllByText('10.240.0.3').length).toBeGreaterThan(0);
    expect(screen.getAllByText('online').length).toBe(2);
    // solid direct chord + RTT label at its midpoint
    expect(container.querySelectorAll('line.topo-link-direct').length).toBe(1);
    expect(screen.getByText('3 ms')).toBeTruthy();
    expect(screen.getByText(/Direct links active\./)).toBeTruthy();
    // no honest-rendering violation: no "single node" guidance in this state
    expect(screen.queryByText(/off by default/)).toBeNull();
  });

  it('state relay-only: every device dashed to the hub, no solid chord, guide shown', () => {
    const a = device({});
    const b = device({ id: 'dev-branch', name: 'branch', virtual_ipv4: '10.240.0.3' });
    const { container } = render(<TopologyDiagram devices={[a, b]} />);

    expect(container.querySelectorAll('line.topo-link-direct').length).toBe(0);
    expect(container.querySelectorAll('line.topo-link-relay').length).toBe(2);
    expect(screen.getByText(/No direct links — all peer traffic relays through the hub\./)).toBeTruthy();
    // guide explains the default-off toggle and how to enable it
    expect(screen.getByText(/off by default on every agent/)).toBeTruthy();
    expect(screen.getByText(/\[dataplane\.direct_connect\]/)).toBeTruthy();
    expect(screen.getByText(/enabled = true/)).toBeTruthy();
    expect(screen.getByText(/never assumes a peer is online/)).toBeTruthy();
  });

  it('state single: honest guidance — no second peer, toggle off by default', () => {
    const { container } = render(<TopologyDiagram devices={[device({})]} />);
    expect(container.querySelectorAll('line.topo-link-direct').length).toBe(0);
    expect(container.querySelectorAll('line.topo-link-relay').length).toBe(1);
    expect(screen.getByText(/Single node — there is no second peer to dial/)).toBeTruthy();
    expect(screen.getByText(/off by default on every agent/)).toBeTruthy();
    expect(screen.getByText(/\[dataplane\.direct_connect\]/)).toBeTruthy();
  });
});
