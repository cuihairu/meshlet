import {
  BootstrapTokensSection,
  InvitesSection,
  RegistrationsSection,
  SegmentGrantsSection,
} from '../../App';
import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useNetwork } from '../../network-context';

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
