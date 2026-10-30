import { useNetwork } from '../../network-context';
import { NetworkDetail } from './NetworkDetail';
import { NetworksPanel } from './NetworksPanel';

/** /networks — network list, create, detail header, routes, revisions. */
export function NetworksPage() {
  const { selectedNetwork, select, refresh } = useNetwork();
  return (
    <div className="panel">
      <NetworksPanel />
      {selectedNetwork && (
        <NetworkDetail
          network={selectedNetwork}
          onClose={() => select(null)}
          onChanged={refresh}
        />
      )}
    </div>
  );
}
