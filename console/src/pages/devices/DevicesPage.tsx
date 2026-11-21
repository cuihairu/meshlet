import { NoNetworkSelected } from '../../components/NoNetworkSelected';
import { useLanguage } from '../../i18n/language-context';
import { useNetwork } from '../../network-context';
import { AliasesSection } from './AliasesSection';
import { DevicesSection } from './DevicesSection';
import { TasksSection } from './TasksSection';

/** /devices — enrolled devices, alias mappings, task queue. Host forwarding
 * lives on its own /forwards page. */
export function DevicesPage() {
  const { selectedNetwork, refresh } = useNetwork();
  const { t } = useLanguage();
  if (!selectedNetwork) return <NoNetworkSelected />;
  const id = selectedNetwork.id;
  return (
    <div className="panel">
      <h1>{t('page.devices')}</h1>
      <DevicesSection networkId={id} onChanged={refresh} />
      <AliasesSection networkId={id} onChanged={refresh} />
      <TasksSection networkId={id} onChanged={refresh} />
    </div>
  );
}
