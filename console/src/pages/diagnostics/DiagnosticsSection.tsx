import { useEffect, useState } from 'react';
import { Button, Tag } from 'antd';
import { api, ApiError } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import type { MessageKey } from '../../i18n/en';
import { formatTime } from '../../lib/format';
import { tagColor } from '../../lib/status-tag';

// §12.7 diagnostics: fixed layer order for grouping; status vocabulary is the
// API contract (pass / fail / warning / unavailable / not_applicable).
const LAYER_ORDER = ['tunnel', 'routing', 'forwarding', 'alias', 'control_plane'];
const LAYER_KEY: Record<string, MessageKey> = {
  tunnel: 'diagnostics.layerTunnel',
  routing: 'diagnostics.layerRouting',
  forwarding: 'diagnostics.layerForwarding',
  alias: 'diagnostics.layerAlias',
  control_plane: 'diagnostics.layerControlPlane',
};
const STATUS_KEY: Record<string, MessageKey> = {
  pass: 'diagnostics.statusPass',
  fail: 'diagnostics.statusFail',
  warning: 'diagnostics.statusWarning',
  unavailable: 'diagnostics.statusUnavailable',
  not_applicable: 'diagnostics.statusNotApplicable',
};
const STATUS_COUNT_ORDER = ['pass', 'fail', 'warning', 'unavailable', 'not_applicable'];

export function DiagnosticsSection({ networkId }: { networkId: string }) {
  const [report, setReport] = useState<import('../../api').DiagnosticsReport | null>(null);
  const [notRun, setNotRun] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

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
        {t('diagnostics.title')}{' '}
        <Button onClick={run} loading={busy}>
          {t('diagnostics.run')}
        </Button>
      </h3>
      <p className="muted">
        {t('diagnostics.intro1')}
        <strong>{t('diagnostics.unavailable')}</strong>
        {t('diagnostics.intro2')}
      </p>
      {notRun && !report && (
        <p className="muted">{t('diagnostics.notRun')}</p>
      )}
      {error && <p className="error">{error}</p>}
      {report && (
        <>
          <p className="muted">
            {t('diagnostics.checked', { time: formatTime(report.checked_at) })} ·{' '}
            {STATUS_COUNT_ORDER.filter((s) => counts[s])
              .map((s) => `${counts[s]} ${STATUS_KEY[s] ? t(STATUS_KEY[s]) : s}`)
              .join(' · ')}
          </p>
          {LAYER_ORDER.map((layer) => {
            const items = report.checks.filter((c) => c.layer === layer);
            if (items.length === 0) return null;
            return (
              <div key={layer} className="diag-layer">
                <h4>{LAYER_KEY[layer] ? t(LAYER_KEY[layer]) : layer}</h4>
                <ul className="diag-list">
                  {items.map((c) => (
                    <li key={c.id}>
                      <Tag color={tagColor(c.status)}>
                        {STATUS_KEY[c.status] ? t(STATUS_KEY[c.status]) : c.status}
                      </Tag>{' '}
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
