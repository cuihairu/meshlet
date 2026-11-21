import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useLanguage } from '../../i18n/language-context';
import { useNetwork } from '../../network-context';
import { HostForwardsSection } from '../devices/HostForwardsSection';

/** /forwards — host forwards as a standalone page (promoted from the devices page). */
export function ForwardsPage() {
  const { selectedNetwork, refresh } = useNetwork();
  const { t } = useLanguage();
  if (!selectedNetwork) return <NoNetworkSelected />;
  return (
    <div className="panel">
      <h1>{t('page.forwards')}</h1>
      <HostForwardsSection networkId={selectedNetwork.id} onChanged={refresh} />
    </div>
  );
}
