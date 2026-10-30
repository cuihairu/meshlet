import { useEffect, useState } from 'react';
import { api, ApiError } from '../../api';
import { formatTime } from '../../lib/format';

// §12.7 diagnostics: fixed layer order for grouping; status vocabulary is the
// API contract (pass / fail / warning / unavailable / not_applicable).
const LAYER_ORDER = ['tunnel', 'routing', 'forwarding', 'alias', 'control_plane'];
const LAYER_LABELS: Record<string, string> = {
  tunnel: 'Tunnel',
  routing: 'Routing',
  forwarding: 'Forwarding',
  alias: 'Alias',
  control_plane: 'Control plane',
};
const STATUS_LABELS: Record<string, string> = {
  pass: 'pass',
  fail: 'fail',
  warning: 'warning',
  unavailable: 'unavailable',
  not_applicable: 'not applicable',
};
const STATUS_COUNT_ORDER = ['pass', 'fail', 'warning', 'unavailable', 'not_applicable'];

export function DiagnosticsSection({ networkId }: { networkId: string }) {
  const [report, setReport] = useState<import('../../api').DiagnosticsReport | null>(null);
  const [notRun, setNotRun] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getDiagnostics(networkId)
      .then(setReport)
      .catch((e) => {
        // Never run: not an error state, just an empty page with a hint.
        if (e instanceof ApiError && e.status === 404) setNotRun(true);
        else setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      });
  }, [networkId]);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setReport(await api.runDiagnostics(networkId));
      setNotRun(false);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const counts = (report?.checks ?? []).reduce<Record<string, number>>((acc, c) => {
    acc[c.status] = (acc[c.status] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      <h3>
        Diagnostics{' '}
        <button type="button" onClick={run} disabled={busy}>
          Run checks
        </button>
      </h3>
      <p className="muted">
        13 checks across fault layers. <strong>unavailable</strong> means the
        control plane cannot observe a host-local fact — it is not a pass; run
        the given command on the device itself.
      </p>
      {notRun && !report && (
        <p className="muted">No diagnostics run yet — run the checks to take a snapshot.</p>
      )}
      {error && <p className="error">{error}</p>}
      {report && (
        <>
          <p className="muted">
            Checked {formatTime(report.checked_at)} ·{' '}
            {STATUS_COUNT_ORDER.filter((s) => counts[s])
              .map((s) => `${counts[s]} ${STATUS_LABELS[s]}`)
              .join(' · ')}
          </p>
          {LAYER_ORDER.map((layer) => {
            const items = report.checks.filter((c) => c.layer === layer);
            if (items.length === 0) return null;
            return (
              <div key={layer} className="diag-layer">
                <h4>{LAYER_LABELS[layer] ?? layer}</h4>
                <ul className="diag-list">
                  {items.map((c) => (
                    <li key={c.id}>
                      <span className={`diag diag-${c.status}`}>
                        {STATUS_LABELS[c.status] ?? c.status}
                      </span>{' '}
                      <strong>{c.name}</strong>
                      <div className="muted">{c.detail}</div>
                      {c.suggestion && <div className="diag-suggestion">{c.suggestion}</div>}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}
