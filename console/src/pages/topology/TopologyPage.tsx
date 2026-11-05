import { useCallback, useEffect, useState } from 'react';
import { api, type Device } from '../../api';
import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useLanguage } from '../../i18n/language-context';
import { formatTime } from '../../lib/format';
import { useNetwork } from '../../network-context';
import { TopologyDiagram } from './TopologyDiagram';

/**
 * /topology (TOPO-1) — live network topology: hub at the center, nodes on a
 * ring, direct links solid (RTT labelled), hub relay dashed. Data source is
 * the existing devices API (peers + direct links + heartbeat online_state);
 * refresh follows the console polling convention (5s interval, as in
 * RevisionsSection).
 */
export function TopologyPage() {
  const { selectedNetwork } = useNetwork();
  const { t } = useLanguage();
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [refreshedAt, setRefreshedAt] = useState<string | null>(null);

  const networkId = selectedNetwork?.id;
  const load = useCallback(() => {
    if (!networkId) return;
    api
      .listDevices(networkId)
      .then((ds) => {
        setDevices(ds);
        setRefreshedAt(new Date().toISOString());
      })
      .catch(() => setDevices([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!networkId) return;
    const timer = window.setInterval(() => {
      void load();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [load, networkId]);

  if (!selectedNetwork) return <NoNetworkSelected />;

  return (
    <div className="panel">
      <h1>{t('page.topology')}</h1>
      {refreshedAt && (
        <p className="muted">{t('topology.updated', { time: formatTime(refreshedAt) })}</p>
      )}
      {devices === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : (
        <TopologyDiagram devices={devices} />
      )}
    </div>
  );
}
