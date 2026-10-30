import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, type ConfigRevision } from '../../api';
import { formatTime } from '../../lib/format';

export function RevisionsSection({ networkId }: { networkId: string }) {
  const [revisions, setRevisions] = useState<ConfigRevision[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const requestRef = useRef<AbortController | null>(null);

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

  return (
    <div>
      <h3>Config revisions</h3>
      <p className="muted">
        A new revision is recorded for every config change (network, device join,
        route, revoke). Apply publishes the current revision to the hub. Device
        receipts are tracked separately; business connectivity requires a probe.
        Rollback restores the last successful hub plan for the current failed revision.
      </p>
      {revisions === null ? (
        <p className="muted">Loading…</p>
      ) : revisions.length === 0 ? (
        <p className="muted">No config revisions yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Revision</th>
              <th>Created</th>
              <th>Status</th>
              <th>Desired config hash</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {revisions.map((r) => (
              <tr key={r.revision}>
                <td>#{r.revision}</td>
                <td>{formatTime(r.created_at)}</td>
                <td>
                  <span className={`status status-${r.apply_status}`}>
                    Hub: {r.apply_status}
                  </span>
                  {r.convergence && (
                    <div className="muted">
                      <div>Devices: {({ pending: 'Waiting for receipts', applied: 'All devices applied', failed: 'Apply failed', not_configured: 'Data plane not configured' } as Record<string, string>)[r.convergence.device_apply_status] ?? r.convergence.device_apply_status}</div>
                      {r.convergence.pending_device_ids.length > 0 && (
                        <div>Waiting for: {r.convergence.pending_device_ids.join(', ')}</div>
                      )}
                      {Object.entries(r.convergence.device_errors).map(([device, error]) => (
                        <div key={device}>{device}: {error}</div>
                      ))}
                      {r.convergence.hub_recovery_error && <div>Hub recovery: {r.convergence.hub_recovery_error}</div>}
                      <div>Connectivity: {r.convergence.business_health === 'not_probed' ? 'Not probed' : r.convergence.business_health}</div>
                    </div>
                  )}
                  {r.error_summary && (
                    <span className="muted"> · {r.error_summary}</span>
                  )}
                </td>
                <td>
                  <code className="hash">{r.desired_config_hash.slice(0, 16)}…</code>
                </td>
                <td>
                  {r.revision === currentRevision && (
                    <button
                      type="button"
                      disabled={busy === r.revision}
                      onClick={() => act('apply', r.revision)}
                    >
                      Apply
                    </button>
                  )}
                  {(r.apply_status === 'failed' ||
                    r.apply_status === 'rollback_pending') &&
                    r.revision === currentRevision && (
                      <button
                        type="button"
                        className="link"
                        disabled={busy === r.revision}
                        onClick={() => act('rollback', r.revision)}
                      >
                        Rollback
                      </button>
                    )}
                  {(r.apply_status === 'failed' ||
                    r.apply_status === 'rollback_pending') &&
                    r.revision !== currentRevision && (
                      <span
                        className="muted"
                        title="Superseded by revision #{currentRevision}. Rolling this back would cross-touch objects the newer revision owns, so the server refuses it (409). Record a new revision instead."
                      >
                        superseded
                      </span>
                    )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {error && (
        <p className="error">
          Failed to load config revisions: {error}.{' '}
          <button type="button" className="link" onClick={load}>
            Retry
          </button>
        </p>
      )}
    </div>
  );
}
