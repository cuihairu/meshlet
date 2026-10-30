import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../../api';
import { formatTime } from '../../lib/format';

export function DevicesSection({
  networkId,
  onChanged,
  refreshKey = 0,
}: {
  networkId: string;
  onChanged?: () => void;
  /** Bumped by sibling sections (approve/deny) to force a reload. */
  refreshKey?: number;
}) {
  const [devices, setDevices] = useState<import('../../api').Device[] | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [revoked, setRevoked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.listDevices(networkId).then(setDevices).catch(() => setDevices([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const revoke = async (deviceId: string) => {
    setBusy(true);
    setError(null);
    try {
      const ref = await api.revokeDevice(networkId, deviceId);
      setConfirming(null);
      setRevoked(`Device ${deviceId} revoked → revision #${ref.revision_id} (${ref.apply_status}).`);
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h3>Devices</h3>
      {devices === null ? (
        <p className="muted">Loading…</p>
      ) : devices.length === 0 ? (
        <p className="muted">
          No devices. Create an invite below and enroll an agent with the token.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Virtual IP</th>
              <th>Status</th>
              <th>Online</th>
              <th>Tunnel</th>
              <th>Fingerprint</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} title={d.public_key} className={`state-${d.online_state}`}>
                <td>{d.name}</td>
                <td>
                  <code>{d.virtual_ipv4}</code>
                </td>
                <td>{d.status}</td>
                <td title={`source: ${d.presence_source}`}>
                  <span className={`dot ${d.online_state}`}>{d.online_state}</span>
                  <span className="muted"> · {SOURCE_LABELS[d.presence_source] ?? d.presence_source}</span>
                  <span className="muted"> · updated {formatTime(d.last_seen_at)}</span>
                </td>
                <td>
                  <span className="muted" title="dataplane readings from the device's last heartbeat">
                    {d.dataplane_evidence ? (
                      [
                        `mtu ${d.dataplane_evidence.tunnel_mtu ?? '?'}`,
                        `probe ${d.dataplane_evidence.mtu_probe_payload ?? '—'}`,
                        d.dataplane_evidence.nat_rules_present != null
                          ? [
                              `nat ${d.dataplane_evidence.nat_rules_present ? '✓' : '✗'}`,
                              d.dataplane_evidence.nat_rules_present &&
                              d.dataplane_evidence.nat_snat_rules_present != null
                                ? `snat ${d.dataplane_evidence.nat_snat_rules_present ? '✓' : '✗'}`
                                : null,
                            ]
                          : null,
                      ]
                        .filter(Boolean)
                        .join(' · ')
                    ) : (
                      'no evidence'
                    )}
                  </span>
                </td>
                <td>
                  <code className="fingerprint">{d.fingerprint.slice(0, 16)}…</code>
                </td>
                <td>
                  {/* Defensive: only approved devices (never "pending" — that
                     state lives in the registrations queue) can be revoked. */}
                  {d.status === 'revoked' || d.status === 'pending' ? (
                    <span className="muted">—</span>
                  ) : confirming === d.id ? (
                    <>
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => revoke(d.id)}
                      >
                        Confirm revoke
                      </button>{' '}
                      <button
                        type="button"
                        className="link"
                        onClick={() => setConfirming(null)}
                      >
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="link"
                      onClick={() => {
                        setConfirming(d.id);
                        setRevoked(null);
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {revoked && <p className="muted">{revoked}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
/** Presence data sources (archive §12.2: a green dot must say why). */
const SOURCE_LABELS: Record<string, string> = {
  agent_report: 'agent report',
  handshake: 'wireguard handshake only',
  enrollment: 'enrollment',
  none: 'no evidence',
};
