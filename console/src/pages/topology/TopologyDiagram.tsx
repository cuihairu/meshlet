import type { Device } from '../../api';
import { isEstablished, topologyState } from '../../lib/topology';
import { useLanguage } from '../../i18n/language-context';
import { tagColor } from '../../lib/status-tag';

interface Placed {
  device: Device;
  x: number;
  y: number;
}

/** One deduplicated direct edge between two devices, labelled with its RTT. */
interface DirectEdge {
  key: string;
  a: Placed;
  b: Placed;
  rttMs: number | null;
}

// Canvas the percentage positions are computed against (matches the SVG viewBox).
const W = 1000;
const H = 620;
const HUB = { x: W / 2, y: H / 2 };
const RX = W * 0.34;
const RY = H * 0.36;

const pctX = (x: number) => `${(x / W) * 100}%`;
const pctY = (y: number) => `${(y / H) * 100}%`;

/**
 * Pure topology diagram (TOPO-1): the hub at the center, devices on a ring.
 * Every device is joined to the hub by a dashed line (the relay path its
 * traffic actually takes); established P2P direct links draw solid chords
 * between the two device nodes, labelled with the reported RTT. Node cards
 * show name / virtual IP / the online_state the device itself reported.
 */
export function TopologyDiagram({ devices }: { devices: Device[] }) {
  const { t } = useLanguage();
  const state = topologyState(devices);

  const ring: Placed[] = devices.map((d, i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / devices.length;
    return {
      device: d,
      x: HUB.x + RX * Math.cos(angle),
      y: HUB.y + RY * Math.sin(angle),
    };
  });

  const byIp = new Map(ring.map((p) => [p.device.virtual_ipv4, p]));
  const edges: DirectEdge[] = [];
  const seen = new Set<string>();
  for (const p of ring) {
    for (const link of p.device.direct_links ?? []) {
      if (!isEstablished(link)) continue;
      const peer = byIp.get(link.virtual_ipv4);
      if (!peer) continue; // peer not enrolled/visible — nothing to draw to
      const key = [p.device.id, peer.device.id].sort().join('|');
      if (seen.has(key)) continue; // the peer reports the same link back
      seen.add(key);
      edges.push({ key, a: p, b: peer, rttMs: link.rtt_ms ?? null });
    }
  }

  const mid = (e: DirectEdge) => ({
    x: (e.a.x + e.b.x) / 2,
    y: (e.a.y + e.b.y) / 2,
  });

  return (
    <div className="topology">
      <p className="topo-state" aria-live="polite">
        {state === 'direct'
          ? t('topology.stateDirect')
          : state === 'relay-only'
            ? t('topology.stateRelayOnly')
            : t('topology.stateSingle')}
      </p>
      <div className="topo-canvas">
        <svg
          className="topo-links"
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          {/* dashed device–hub lines: every peer relays via the hub tunnel */}
          {ring.map((p) => (
            <line
              key={`relay-${p.device.id}`}
              className="topo-link-relay"
              x1={HUB.x}
              y1={HUB.y}
              x2={p.x}
              y2={p.y}
            />
          ))}
          {/* solid chords: established direct links only */}
          {edges.map((e) => (
            <line
              key={e.key}
              className="topo-link-direct"
              x1={e.a.x}
              y1={e.a.y}
              x2={e.b.x}
              y2={e.b.y}
            />
          ))}
        </svg>
        {/* hub node */}
        <div
          className="topo-node topo-hub"
          style={{ left: pctX(HUB.x), top: pctY(HUB.y) }}
        >
          <span className="topo-node-name">{t('topology.hub')}</span>
        </div>
        {/* device nodes on the ring */}
        {ring.map((p) => (
          <div
            key={p.device.id}
            className={`topo-node topo-device state-${p.device.online_state}`}
            style={{ left: pctX(p.x), top: pctY(p.y) }}
          >
            <span className="topo-node-name">{p.device.name}</span>
            <code className="topo-node-ip">{p.device.virtual_ipv4}</code>
            {/* 如实展示设备自己上报的 online_state，不臆测在线 */}
            <span className={`topo-tag tag-${tagColor(p.device.online_state)}`}>
              {p.device.online_state}
            </span>
          </div>
        ))}
        {/* RTT labels on direct chords */}
        {edges.map((e) => {
          const m = mid(e);
          return (
            <span
              key={`rtt-${e.key}`}
              className="topo-rtt mono"
              style={{ left: pctX(m.x), top: pctY(m.y) }}
            >
              {e.rttMs != null ? `${e.rttMs} ms` : '—'}
            </span>
          );
        })}
      </div>
      <div className="topo-legend">
        <h3 className="muted">{t('topology.legendTitle')}</h3>
        <div>
          <span className="topo-legend-line topo-legend-direct" aria-hidden="true" />{' '}
          {t('topology.legendDirect')}
        </div>
        <div>
          <span className="topo-legend-line topo-legend-relay" aria-hidden="true" />{' '}
          {t('topology.legendRelay')}
        </div>
      </div>
      {state !== 'direct' && <TopologyGuide />}
    </div>
  );
}

/**
 * Honest guidance shown whenever no direct link exists: why (direct_connect is
 * off by default / only one node enrolled), how to enable it, and the explicit
 * statement that the page only renders what devices reported.
 */
export function TopologyGuide() {
  const { t } = useLanguage();
  return (
    <div className="topo-guide">
      <h3>{t('topology.guideTitle')}</h3>
      <p>{t('topology.guideOff')}</p>
      <pre className="mono">{`[dataplane.direct_connect]
enabled = true`}</pre>
      <p className="muted">{t('topology.guideWhy')}</p>
    </div>
  );
}
