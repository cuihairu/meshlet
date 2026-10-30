import { AliasesSection, DevicesSection, HostForwardsSection } from '../../App';
import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useNetwork } from '../../network-context';

/** /devices — enrolled devices, alias mappings, host forwarding. */
export function DevicesPage() {
  const { selectedNetwork, refresh } = useNetwork();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <DevicesSection networkId={id} onChanged={refresh} />
      <AliasesSection networkId={id} onChanged={refresh} />
      <HostForwardsSection networkId={id} onChanged={refresh} />
    </div>
  );
}
