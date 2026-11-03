import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useLanguage } from '../../i18n/language-context';
import { useNetwork } from '../../network-context';
import { BootstrapTokensSection } from './BootstrapTokensSection';
import { InvitesSection } from './InvitesSection';
import { RegistrationsSection } from './RegistrationsSection';
import { SegmentGrantsSection } from './SegmentGrantsSection';

/** /access — pending registrations, invites, bootstrap tokens, segment grants. */
export function AccessPage() {
  const { selectedNetwork, refresh } = useNetwork();
  const { t } = useLanguage();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <h1>{t('page.access')}</h1>
      <RegistrationsSection networkId={id} onChanged={refresh} />
      <InvitesSection networkId={id} />
      <BootstrapTokensSection networkId={id} />
      <SegmentGrantsSection networkId={id} onChanged={refresh} />
    </div>
  );
}
