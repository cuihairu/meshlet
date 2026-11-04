import { useEffect, useState } from 'react';
import { Tag } from 'antd';
import { api } from '../../api';
import type { Device, DirectCandidate, DirectLink } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { formatBytes } from '../../lib/format';

/** R-DIAG-2: the 直连 peers block on the diagnostics page — every direct link
 *  any device in the network reported, with mode/endpoint/RTT/handshake/traffic.
 *  Relay peers are not in `direct_links` (absence = relay via hub). */
export function DirectPeersBlock({ networkId }: { networkId: string }) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const { t } = useLanguage();

  useEffect(() => {
    api.listDevices(networkId).then(setDevices).catch(() => setDevices([]));
  }, [networkId]);

  const links: { device: Device; link: DirectLink }[] = (devices ?? [])
    .flatMap((d) => (d.direct_links ?? []).map((link) => ({ device: d, link })));

  const lossPct = (rate: number | undefined) =>
    rate == null ? '—' : `${(rate * 100).toFixed(0)}%`;

  const CandidateRow = ({ c }: { c: DirectCandidate }) => (
    <tr className={c.selected ? 'candidate-selected' : undefined}>
      <td className="mono">
        {c.endpoint}
        {c.selected ? <Tag color="green">{t('diagnostics.directPeersCandidateSelected')}</Tag> : null}
      </td>
      <td>{c.kind}</td>
      <td className="mono">{c.rtt_ms != null ? `${c.rtt_ms} ms` : '—'}</td>
      <td className="mono">{lossPct(c.loss_rate)}</td>
      <td>{c.reason}</td>
    </tr>
  );

  return (
    <div className="direct-peers-block">
      <h2>{t('diagnostics.directPeersTitle')}</h2>
      {links.length === 0 ? (
        <p className="muted">{t('diagnostics.directPeersNone')}</p>
      ) : (
        <table className="direct-peers">
          <thead>
            <tr>
              <th>{t('diagnostics.directPeersDevice')}</th>
              <th>{t('diagnostics.directPeersPeer')}</th>
              <th>{t('diagnostics.directPeersMode')}</th>
              <th>{t('diagnostics.directPeersEndpoint')}</th>
              <th>{t('diagnostics.directPeersRtt')}</th>
              <th>{t('diagnostics.directPeersHandshake')}</th>
              <th>{t('diagnostics.directPeersTraffic')}</th>
            </tr>
          </thead>
          <tbody>
            {links.map(({ device, link }) => {
              const direct =
                link.connection_mode === 'p2p_direct' ||
                (link.connection_mode == null && link.link_state === 'direct');
              const handshake =
                link.last_handshake_age_secs == null
                  ? t('devices.directAgeUnknown')
                  : t('devices.directAge', { secs: String(link.last_handshake_age_secs) });
              return (
                <tr key={`${device.id}:${link.public_key}`}>
                  <td>
                    {device.name}
                    {/* SEL-004: peer 详情展开，展示全部候选端点。 */}
                    <div className="direct-candidates">
                      <h4>{t('diagnostics.directPeersCandidates')}</h4>
                      {(link.candidates?.length ?? 0) === 0 ? (
                        <p className="muted">{t('diagnostics.directPeersCandidateNone')}</p>
                      ) : (
                        <table className="direct-candidates-table">
                          <thead>
                            <tr>
                              <th>{t('diagnostics.directPeersCandidateEndpoint')}</th>
                              <th>{t('diagnostics.directPeersCandidateKind')}</th>
                              <th>{t('diagnostics.directPeersCandidateRtt')}</th>
                              <th>{t('diagnostics.directPeersCandidateLoss')}</th>
                              <th>{t('diagnostics.directPeersCandidateReason')}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(link.candidates ?? []).map((c) => (
                              <CandidateRow key={c.endpoint} c={c} />
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  </td>
                  <td>{link.peer_name || link.virtual_ipv4}</td>
                  <td>
                    <Tag color={direct ? 'green' : 'orange'}>
                      {direct ? t('devices.directOk') : t('devices.directPending')}
                    </Tag>
                  </td>
                  <td className="mono">{link.endpoint || '—'}</td>
                  <td className="mono">{link.rtt_ms != null ? `${link.rtt_ms} ms` : '—'}</td>
                  <td>{handshake}</td>
                  <td className="mono">
                    {`${formatBytes(link.rx_bytes ?? 0)}↑ ${formatBytes(link.tx_bytes ?? 0)}↓`}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
