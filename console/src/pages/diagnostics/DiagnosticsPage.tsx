import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useLanguage } from '../../i18n/language-context';
import { useNetwork } from '../../network-context';
import { DiagnosticsSection } from './DiagnosticsSection';
import { DirectPeersBlock } from './DirectPeersBlock';
import { NetworkSnapshotBlock } from './NetworkSnapshotBlock';
import { PublishSection } from './PublishSection';

/** /diagnostics — health checks, direct peers, snapshots and service publishing. */
export function DiagnosticsPage() {
  const { selectedNetwork, refresh } = useNetwork();
  const { t } = useLanguage();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <h1>{t('page.diagnostics')}</h1>
      <DiagnosticsSection networkId={id} />
      <DirectPeersBlock networkId={id} />
      <NetworkSnapshotBlock networkId={id} />
      <PublishSection networkId={id} onChanged={refresh} />
    </div>
  );
}
