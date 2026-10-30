import type { Network } from '../../api';
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
  return (
    <section className="detail">
      <h2>
        {network.name} <code>{network.overlay_cidr}</code>
        <button type="button" className="link" onClick={onClose}>
          Close
        </button>
      </h2>
      <p className="muted">
        Current config revision {network.revision_id} ·{' '}
        <span className={`status status-${network.apply_status}`}>
          Hub: {network.apply_status}
        </span>
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
