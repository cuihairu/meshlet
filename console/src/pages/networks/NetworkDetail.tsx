import { Button, Tag } from 'antd';
import type { Network } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { tagColor } from '../../lib/status-tag';
import { RevisionsSection } from './RevisionsSection';
import { RoutesSection } from './RoutesSection';

export function NetworkDetail({
  network,
  onClose,
  onChanged,
}: {
  network: Network;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const { t } = useLanguage();
  return (
    <section className="detail">
      <h2>
        {network.name} <code>{network.overlay_cidr}</code>
        <Button type="link" onClick={onClose}>
          {t('networks.close')}
        </Button>
      </h2>
      <p className="muted">
        {t('networks.currentRevision', {
          revision_id: String(network.revision_id),
        })}{' '}
        ·{' '}
        <Tag color={tagColor(network.apply_status)}>
          {t('revisions.hubStatus', { status: network.apply_status })}
        </Tag>
      </p>
      <RoutesSection
        networkId={network.id}
        overlayCidr={network.overlay_cidr}
        onChanged={onChanged}
      />
      <RevisionsSection key={network.id} networkId={network.id} />
    </section>
  );
}
