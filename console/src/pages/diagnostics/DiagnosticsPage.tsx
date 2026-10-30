import { DiagnosticsSection, PublishSection } from '../../App';
import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useNetwork } from '../../network-context';

/** /diagnostics — health checks and service publishing. */
export function DiagnosticsPage() {
  const { selectedNetwork, refresh } = useNetwork();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <DiagnosticsSection networkId={id} />
      <PublishSection networkId={id} onChanged={refresh} />
    </div>
  );
}
