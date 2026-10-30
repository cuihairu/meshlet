import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useNetwork } from '../../network-context';
import { BootstrapTokensSection } from './BootstrapTokensSection';
import { InvitesSection } from './InvitesSection';
import { RegistrationsSection } from './RegistrationsSection';
import { SegmentGrantsSection } from './SegmentGrantsSection';

/** /access — pending registrations, invites, bootstrap tokens, segment grants. */
export function AccessPage() {
  const { selectedNetwork, refresh } = useNetwork();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <RegistrationsSection networkId={id} onChanged={refresh} />
      <InvitesSection networkId={id} />
      <BootstrapTokensSection networkId={id} />
      <SegmentGrantsSection networkId={id} onChanged={refresh} />
    </div>
  );
}
