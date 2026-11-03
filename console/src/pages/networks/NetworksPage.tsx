import { useNetwork } from '../../network-context';
import { useLanguage } from '../../i18n/language-context';
import { NetworkDetail } from './NetworkDetail';
import { NetworksPanel } from './NetworksPanel';

/** /networks — network list, create, detail header, routes, revisions. */
export function NetworksPage() {
  const { selectedNetwork, select, refresh } = useNetwork();
  const { t } = useLanguage();
  return (
    <div className="panel">
      <h1>{t('page.networks')}</h1>
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
