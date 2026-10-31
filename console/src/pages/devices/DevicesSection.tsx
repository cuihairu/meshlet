import { useCallback, useEffect, useState } from 'react';
import { Button, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import type { MessageKey } from '../../i18n/en';
import { formatTime } from '../../lib/format';
import { tagColor } from '../../lib/status-tag';

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
  const { t } = useLanguage();

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
      setRevoked(
        t('devices.revokedNotice', {
          device: deviceId,
          revision: String(ref.revision_id),
          status: ref.apply_status,
        }),
      );
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const columns: TableProps<import('../../api').Device>['columns'] = [
    { title: t('devices.colName'), key: 'name', render: (_, d) => d.name },
    {
      title: t('devices.colVirtualIp'),
      key: 'virtual_ipv4',
      render: (_, d) => <code>{d.virtual_ipv4}</code>,
    },
    {
      title: t('devices.colStatus'),
      key: 'status',
      render: (_, d) => <Tag color={tagColor(d.status)}>{d.status}</Tag>,
    },
    {
      title: t('devices.colOnline'),
      key: 'online',
      render: (_, d) => (
        <>
          <Tag color={tagColor(d.online_state)}>{d.online_state}</Tag>
          <span className="muted">
            {' '}
            · {SOURCE_KEY[d.presence_source] ? t(SOURCE_KEY[d.presence_source]) : d.presence_source}
          </span>
          <span className="muted"> · {t('devices.updated', { time: formatTime(d.last_seen_at) })}</span>
        </>
      ),
    },
    {
      title: t('devices.colTunnel'),
      key: 'tunnel',
      render: (_, d) => (
        <span className="muted" title={t('devices.tunnelTitle')}>
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
            t('devices.noEvidence')
          )}
        </span>
      ),
    },
    {
      title: t('devices.colDirect'),
      key: 'direct',
      render: (_, d) => {
        // Version skew: an older server omits direct_links instead of [].
        const links = d.direct_links ?? [];
        return links.length === 0 ? (
          <span className="muted" title={t('devices.directRelay')}>
            {t('devices.directRelay')}
          </span>
        ) : (
          links.map((link) => {
            const peer = devices?.find((p) => p.virtual_ipv4 === link.virtual_ipv4);
            const label = peer ? peer.name : link.virtual_ipv4;
            const direct = link.link_state === 'direct';
            const title =
              link.last_handshake_age_secs == null
                ? t('devices.directAgeUnknown')
                : t('devices.directAge', { secs: String(link.last_handshake_age_secs) });
            return (
              <Tag
                key={link.public_key}
                color={direct ? 'green' : 'orange'}
                title={`${label} · ${title}`}
              >
                {label} · {direct ? t('devices.directOk') : t('devices.directPending')}
              </Tag>
            );
          })
        );
      },
    },
    {
      title: t('devices.colFingerprint'),
      key: 'fingerprint',
      render: (_, d) => <code className="fingerprint">{d.fingerprint.slice(0, 16)}…</code>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, d) =>
        // Defensive: only approved devices (never "pending" — that state lives
        // in the registrations queue) can be revoked.
        d.status === 'revoked' || d.status === 'pending' ? (
          <span className="muted">—</span>
        ) : confirming === d.id ? (
          <>
            <Button size="small" danger loading={busy} onClick={() => revoke(d.id)}>
              {t('devices.confirmRevoke')}
            </Button>{' '}
            <Button size="small" type="link" onClick={() => setConfirming(null)}>
              {t('devices.cancel')}
            </Button>
          </>
        ) : (
          <Button
            size="small"
            type="link"
            onClick={() => {
              setConfirming(d.id);
              setRevoked(null);
            }}
          >
            {t('devices.revoke')}
          </Button>
        ),
    },
  ];

  return (
    <div>
      <h3>{t('devices.title')}</h3>
      {devices === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : devices.length === 0 ? (
        <p className="muted">{t('devices.none')}</p>
      ) : (
        <Table<import('../../api').Device>
          rowKey="id"
          columns={columns}
          dataSource={devices}
          size="middle"
          pagination={false}
          rowClassName={(d) => `state-${d.online_state}`}
        />
      )}
      {revoked && <p className="muted">{revoked}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
/** Presence data sources (archive §12.2: a green dot must say why). */
const SOURCE_KEY: Record<string, MessageKey> = {
  agent_report: 'devices.sourceAgentReport',
  handshake: 'devices.sourceHandshake',
  enrollment: 'devices.sourceEnrollment',
  none: 'devices.sourceNone',
};
