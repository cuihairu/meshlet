import type { Device, DirectLink } from '../api';

/**
 * Topology rendering states (TOPO-1), derived only from what devices actually
 * reported — never assume a peer is online or direct-connected:
 * - direct:     at least one established P2P direct link (solid line, RTT label)
 * - relay-only: two or more nodes, but every peer still relays via the hub
 * - single:     fewer than two nodes — no peer exists to dial, show guidance
 */
export type TopologyState = 'direct' | 'relay-only' | 'single';

/** An established direct link (`p2p_direct`); pending attempts stay relayed. */
export const isEstablished = (link: DirectLink): boolean =>
  link.connection_mode === 'p2p_direct' ||
  (link.connection_mode == null && link.link_state === 'direct');

export function topologyState(devices: Device[]): TopologyState {
  const established = devices.some((d) =>
    (d.direct_links ?? []).some(isEstablished),
  );
  if (established) return 'direct';
  if (devices.length >= 2) return 'relay-only';
  return 'single';
}
