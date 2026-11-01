import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useNetwork } from '../../network-context';
import { DirectPeersBlock } from './DirectPeersBlock';
import { DiagnosticsSection } from './DiagnosticsSection';
import { PublishSection } from './PublishSection';

/** /diagnostics — health checks, direct peers and service publishing. */
export function DiagnosticsPage() {
  const { selectedNetwork, refresh } = useNetwork();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <DiagnosticsSection networkId={id} />
      <DirectPeersBlock networkId={id} />
      <PublishSection networkId={id} onChanged={refresh} />
    </div>
  );
}
