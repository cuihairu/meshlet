import { useEffect, useState } from 'react';
import { api } from '../../api';
import type { Device } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { formatBytes, formatTime } from '../../lib/format';

/** R-DIAG: the network-snapshot block on the diagnostics page — for every device
 *  that reported one, the route table / interface list / wg-mlt readings from its
 *  latest heartbeat. Absence of a device here = it never reported (or collection
 *  failed); raw values are rendered verbatim so operators can compare them with
 *  the real kernel state. */
export function NetworkSnapshotBlock({ networkId }: { networkId: string }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const { t } = useLanguage();

  useEffect(() => {
    api.listDevices(networkId).then(setDevices).catch(() => setDevices([]));
  }, [networkId]);

  const withSnap = (devices ?? []).filter((d) => d.diagnostics != null);

  return (
    <div className="snapshots-block">
      <h2>{t('diagnostics.snapshotsTitle')}</h2>
      {withSnap.length === 0 ? (
        <p className="muted">{t('diagnostics.snapshotsNone')}</p>
      ) : (
        withSnap.map((device) => {
          const snap = device.diagnostics!;
          return (
            <section className="snapshot" key={device.id}>
              <h3 className="snapshot-head">
                {device.name}
                {snap.collected_at ? (
                  <span className="muted">
                    {t('diagnostics.snapshotsCollectedAt')} {formatTime(snap.collected_at)}
                  </span>
                ) : null}
              </h3>

              {/* P2P-⑤: hub-observed endpoints for this device (node drill-down). */}
              {device.observed_endpoint || device.public_endpoint ? (
                <p className="muted mono snapshot-endpoints">
                  {[
                    device.observed_endpoint
                      ? t('devices.endpointObserved', { ep: device.observed_endpoint })
                      : null,
                    device.public_endpoint
                      ? t('devices.endpointPublic', { ep: device.public_endpoint })
                      : null,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </p>
              ) : null}

              <h4>{t('diagnostics.snapshotsRoutes')}</h4>
              {snap.route_table.length === 0 ? (
                <p className="muted">{t('diagnostics.snapshotsEmpty')}</p>
              ) : (
                <pre className="snapshot-pre mono">{snap.route_table.join('\n')}</pre>
              )}

              <h4>{t('diagnostics.snapshotsInterfaces')}</h4>
              {snap.interfaces.length === 0 ? (
                <p className="muted">{t('diagnostics.snapshotsEmpty')}</p>
              ) : (
                <table className="direct-peers">
                  <thead>
                    <tr>
                      <th>{t('diagnostics.snapshotsIfName')}</th>
                      <th>{t('diagnostics.snapshotsIfAddr')}</th>
                      <th>{t('diagnostics.snapshotsIfState')}</th>
                      <th>{t('diagnostics.snapshotsIfMtu')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snap.interfaces.map((iface) => (
                      <tr key={iface.name}>
                        <td className="mono">{iface.name}</td>
                        <td className="mono">
                          {iface.ipv4}
                          {iface.prefix != null ? `/${iface.prefix}` : ''}
                        </td>
                        <td>{iface.state}</td>
                        <td className="mono">{iface.mtu ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              <h4>{t('diagnostics.snapshotsWg')}</h4>
              {snap.wg.length === 0 ? (
                <p className="muted">{t('diagnostics.snapshotsEmpty')}</p>
              ) : (
                <table className="direct-peers">
                  <thead>
                    <tr>
                      <th>{t('diagnostics.snapshotsWgPeer')}</th>
                      <th>{t('diagnostics.snapshotsWgEndpoint')}</th>
                      <th>{t('diagnostics.snapshotsWgAllowed')}</th>
                      <th>{t('diagnostics.snapshotsWgHandshake')}</th>
                      <th>{t('diagnostics.snapshotsWgTraffic')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snap.wg.map((peer) => (
                      <tr key={peer.public_key}>
                        <td className="mono">{peer.public_key}</td>
                        <td className="mono">{peer.endpoint || '—'}</td>
                        <td className="mono">{peer.allowed_ips || '—'}</td>
                        <td>
                          {peer.last_handshake > 0
                            ? formatTime(new Date(peer.last_handshake * 1000).toISOString())
                            : t('diagnostics.snapshotsHandshakeNever')}
                        </td>
                        <td className="mono">
                          {`${formatBytes(peer.rx_bytes)}↑ ${formatBytes(peer.tx_bytes)}↓`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          );
        })
      )}
    </div>
  );
}
