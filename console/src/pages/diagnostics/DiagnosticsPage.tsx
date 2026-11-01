import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useNetwork } from '../../network-context';
import { DiagnosticsSection } from './DiagnosticsSection';
import { DirectPeersBlock } from './DirectPeersBlock';
import { NetworkSnapshotBlock } from './NetworkSnapshotBlock';
import { PublishSection } from './PublishSection';

/** /diagnostics — health checks, direct peers, snapshots and service publishing. */
export function DiagnosticsPage() {
  const { selectedNetwork, refresh } = useNetwork();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <DiagnosticsSection networkId={id} />
      <DirectPeersBlock networkId={id} />
      <NetworkSnapshotBlock networkId={id} />
      <PublishSection networkId={id} onChanged={refresh} />
    </div>
  );
}
