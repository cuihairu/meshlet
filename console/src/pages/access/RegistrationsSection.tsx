import { useCallback, useEffect, useState } from 'react';
import { Button, Table } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { formatTime } from '../../lib/format';

/**
 * Pending device self-registrations (ZeroTier-style bootstrap entry). Approve
 * allocates the overlay IP and records a revision; deny drops the request and
 * the device may re-register. No credential is re-issued either way — the
 * device keeps the agent token it received at registration.
 */
export function RegistrationsSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [registrations, setRegistrations] = useState<
    import('../../api').DeviceRegistration[] | null
  >(null);
  const [confirming, setConfirming] = useState<{
    id: string;
    action: 'approve' | 'deny';
  } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

  const load = useCallback(() => {
    api
      .listRegistrations(networkId)
      .then(setRegistrations)
      .catch(() => setRegistrations([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const act = async (
    deviceId: string,
    name: string,
    action: 'approve' | 'deny',
  ) => {
    setBusy(true);
    setError(null);
    try {
      if (action === 'approve') {
        const res = await api.approveRegistration(networkId, deviceId);
        setNotice(
          t('registrations.approvedNotice', {
            name,
            virtual_ipv4: res.virtual_ipv4,
            revision_id: String(res.revision_id),
          }),
        );
      } else {
        await api.denyRegistration(networkId, deviceId);
        setNotice(t('registrations.deniedNotice', { name }));
      }
      setConfirming(null);
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const columns: TableProps<import('../../api').DeviceRegistration>['columns'] = [
    { title: t('registrations.colName'), key: 'name', render: (_, r) => r.name },
    { title: t('registrations.colPlatform'), key: 'platform', render: (_, r) => r.platform },
    {
      title: t('registrations.colId'),
      key: 'id',
      render: (_, r) => <code>{r.id}</code>,
    },
    {
      title: t('registrations.colRequested'),
      key: 'requested_at',
      render: (_, r) => formatTime(r.requested_at),
    },
    {
      title: t('registrations.colLastReport'),
      key: 'last_report_at',
      render: (_, r) =>
        r.last_report_at ? (
          formatTime(r.last_report_at)
        ) : (
          <span className="muted">{t('registrations.notReported')}</span>
        ),
    },
    {
      title: '',
      key: 'actions',
      render: (_, r) => {
        const confirmingRow =
          confirming && confirming.id === r.id ? confirming : null;
        return confirmingRow ? (
          <>
            <Button
              size="small"
              danger={confirmingRow.action === 'deny'}
              loading={busy}
              onClick={() => act(r.id, r.name, confirmingRow.action)}
            >
              {confirmingRow.action === 'approve'
                ? t('registrations.confirmApprove')
                : t('registrations.confirmDeny')}
            </Button>{' '}
            <Button size="small" type="link" onClick={() => setConfirming(null)}>
              {t('registrations.cancel')}
            </Button>
          </>
        ) : (
          <>
            <Button
              size="small"
              type="link"
              onClick={() => {
                setConfirming({ id: r.id, action: 'approve' });
                setNotice(null);
                setError(null);
              }}
            >
              {t('registrations.approve')}
            </Button>{' '}
            <Button
              size="small"
              type="link"
              onClick={() => {
                setConfirming({ id: r.id, action: 'deny' });
                setNotice(null);
                setError(null);
              }}
            >
              {t('registrations.deny')}
            </Button>
          </>
        );
      },
    },
  ];

  return (
    <div>
      <h3>{t('registrations.title')}</h3>
      <p className="muted">{t('registrations.intro')}</p>
      {registrations === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : registrations.length === 0 ? (
        <p className="muted">{t('registrations.none')}</p>
      ) : (
        <Table<import('../../api').DeviceRegistration>
          rowKey="id"
          columns={columns}
          dataSource={registrations}
          size="middle"
          pagination={false}
          rowClassName={(r) => (r.id === confirming?.id ? 'row-confirming' : '')}
        />
      )}
      {notice && <p className="muted">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
