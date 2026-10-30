import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../../api';
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
        setNotice(`已批准 ${name}：虚拟地址 ${res.virtual_ipv4} · 修订 #${res.revision_id}`);
      } else {
        await api.denyRegistration(networkId, deviceId);
        setNotice(`已拒绝 ${name} 的注册申请。`);
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

  return (
    <div>
      <h3>待审批设备</h3>
      <p className="muted">
        设备用自举码自助注册后在此排队，批准前不参与数据面。批准即分配
        overlay 地址并记入新修订；拒绝则丢弃申请（设备可重新注册）。设备
        继续沿用注册时领取的凭证。
      </p>
      {registrations === null ? (
        <p className="muted">加载中…</p>
      ) : registrations.length === 0 ? (
        <p className="muted">无待审批申请</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>名称</th>
              <th>平台</th>
              <th>ID</th>
              <th>申请时间</th>
              <th>最后上报</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {registrations.map((r) => {
              const confirmingRow =
                confirming && confirming.id === r.id ? confirming : null;
              return (
                <tr key={r.id} title={r.public_key}>
                  <td>{r.name}</td>
                  <td>{r.platform}</td>
                  <td>
                    <code>{r.id}</code>
                  </td>
                  <td>{formatTime(r.requested_at)}</td>
                  <td>
                    {r.last_report_at ? (
                      formatTime(r.last_report_at)
                    ) : (
                      <span className="muted">未上报</span>
                    )}
                  </td>
                  <td>
                    {confirmingRow ? (
                      <>
                        <button
                          type="button"
                          className={confirmingRow.action === 'deny' ? 'danger' : undefined}
                          disabled={busy}
                          onClick={() => act(r.id, r.name, confirmingRow.action)}
                        >
                          {confirmingRow.action === 'approve' ? '确认批准' : '确认拒绝'}
                        </button>{' '}
                        <button
                          type="button"
                          className="link"
                          onClick={() => setConfirming(null)}
                        >
                          取消
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          className="link"
                          onClick={() => {
                            setConfirming({ id: r.id, action: 'approve' });
                            setNotice(null);
                            setError(null);
                          }}
                        >
                          批准
                        </button>{' '}
                        <button
                          type="button"
                          className="link"
                          onClick={() => {
                            setConfirming({ id: r.id, action: 'deny' });
                            setNotice(null);
                            setError(null);
                          }}
                        >
                          拒绝
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {notice && <p className="muted">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
