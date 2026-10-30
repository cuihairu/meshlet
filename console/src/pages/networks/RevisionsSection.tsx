import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Empty, Table, Tag, Tooltip } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError, type ConfigRevision } from '../../api';
import { useLanguage, type Translate } from '../../i18n/language-context';
import { formatTime } from '../../lib/format';
import { tagColor } from '../../lib/status-tag';

const DEVICE_STATUS_KEY = {
  pending: 'revisions.devicesWaiting',
  applied: 'revisions.devicesApplied',
  failed: 'revisions.devicesFailed',
  not_configured: 'revisions.devicesNotConfigured',
} as const;

function deviceStatusLabel(t: Translate, status: string): string {
  const key = DEVICE_STATUS_KEY[status as keyof typeof DEVICE_STATUS_KEY];
  return key ? t(key) : status;
}

export function RevisionsSection({ networkId }: { networkId: string }) {
  const [revisions, setRevisions] = useState<ConfigRevision[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const requestRef = useRef<AbortController | null>(null);
  const { t } = useLanguage();

  const load = useCallback(() => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    api
      .listRevisions(networkId, controller.signal)
      // The API returns ascending order; the console shows the newest first.
      .then((rows) => {
        if (requestRef.current !== controller || controller.signal.aborted) return;
        setRevisions([...rows].reverse());
        setError(null);
      })
      .catch((e) => {
        if (
          requestRef.current !== controller ||
          (e instanceof DOMException && e.name === 'AbortError')
        ) {
          return;
        }
        setError(e instanceof ApiError ? `${e.status} ${e.code}: ${e.message}` : String(e));
      });
  }, [networkId]);

  useEffect(() => {
    load();
    return () => requestRef.current?.abort();
  }, [load]);

  const waitingForDevices =
    revisions?.[0]?.convergence?.device_apply_status === 'pending';

  useEffect(() => {
    if (!waitingForDevices) return;
    const timer = window.setInterval(() => {
      void load();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [load, waitingForDevices]);

  const act = async (action: 'apply' | 'rollback', revision: number) => {
    setBusy(revision);
    setError(null);
    try {
      if (action === 'apply') await api.applyRevision(networkId, revision);
      else await api.rollbackRevision(networkId, revision);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.status} ${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(null);
      load();
    }
  };

  // Newest first, so the head of the list is the current desired config — the
  // only revision the server accepts a rollback for.
  const currentRevision = revisions?.[0]?.revision;

  const columns: TableProps<ConfigRevision>['columns'] = [
    {
      title: t('revisions.colRevision'),
      key: 'revision',
      render: (_, r) => `#${r.revision}`,
    },
    {
      title: t('revisions.colCreated'),
      key: 'created',
      render: (_, r) => formatTime(r.created_at),
    },
    {
      title: t('revisions.colStatus'),
      key: 'status',
      render: (_, r) => (
        <>
          <Tag color={tagColor(r.apply_status)}>
            {t('revisions.hubStatus', { status: r.apply_status })}
          </Tag>
          {r.convergence && (
            <div className="muted">
              <div>
                {t('revisions.devicesStatus', {
                  status: deviceStatusLabel(t, r.convergence.device_apply_status),
                })}
              </div>
              {r.convergence.pending_device_ids.length > 0 && (
                <div>
                  {t('revisions.waitingFor', {
                    ids: r.convergence.pending_device_ids.join(', '),
                  })}
                </div>
              )}
              {Object.entries(r.convergence.device_errors).map(([device, message]) => (
                <div key={device}>
                  {device}: {message}
                </div>
              ))}
              {r.convergence.hub_recovery_error && (
                <div>
                  {t('revisions.hubRecovery', {
                    error: r.convergence.hub_recovery_error,
                  })}
                </div>
              )}
              <div>
                {t('revisions.connectivity', {
                  status:
                    r.convergence.business_health === 'not_probed'
                      ? t('revisions.notProbed')
                      : r.convergence.business_health,
                })}
              </div>
            </div>
          )}
          {r.error_summary && <span className="muted"> · {r.error_summary}</span>}
        </>
      ),
    },
    {
      title: t('revisions.colHash'),
      key: 'hash',
      render: (_, r) => (
        <code className="hash">{r.desired_config_hash.slice(0, 16)}…</code>
      ),
    },
    {
      title: '',
      key: 'actions',
      render: (_, r) => {
        const isCurrent = r.revision === currentRevision;
        const canRollback =
          r.apply_status === 'failed' || r.apply_status === 'rollback_pending';
        return (
          <>
            {isCurrent && (
              <Button
                size="small"
                type="primary"
                disabled={busy === r.revision}
                onClick={() => act('apply', r.revision)}
              >
                {t('revisions.apply')}
              </Button>
            )}
            {canRollback && isCurrent && (
              <Button
                size="small"
                disabled={busy === r.revision}
                onClick={() => act('rollback', r.revision)}
              >
                {t('revisions.rollback')}
              </Button>
            )}
            {canRollback && !isCurrent && (
              <Tooltip
                title={t('revisions.supersededTitle', {
                  current: String(currentRevision),
                })}
              >
                <span className="muted">{t('revisions.superseded')}</span>
              </Tooltip>
            )}
          </>
        );
      },
    },
  ];

  return (
    <div>
      <h3>{t('revisions.title')}</h3>
      <p className="muted">{t('revisions.intro')}</p>
      {revisions === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : revisions.length === 0 ? (
        <Empty description={t('revisions.none')} />
      ) : (
        <Table<ConfigRevision>
          rowKey="revision"
          columns={columns}
          dataSource={revisions}
          size="middle"
          pagination={{ pageSize: 10, showSizeChanger: false }}
        />
      )}
      {error && (
        <p className="error">
          {t('revisions.loadFailed', { error })} <Button type="link" onClick={load}>{t('revisions.retry')}</Button>
        </p>
      )}
    </div>
  );
}
