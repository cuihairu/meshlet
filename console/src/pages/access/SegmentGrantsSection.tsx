import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../../api';

/**
 * Segment grants (ADR-012). A grant starts Pending and does not change plans
 * until Apply succeeds; revoke immediately removes it from the desired state.
 */
export function SegmentGrantsSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [segments, setSegments] = useState<import('../../api').Segment[] | null>(null);
  const [grants, setGrants] = useState<import('../../api').SegmentGrant[] | null>(null);
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.listSegments(networkId).then(setSegments).catch(() => setSegments([]));
    api.listSegmentGrants(networkId).then(setGrants).catch(() => setGrants([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const report = (e: unknown) =>
    setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));

  const createSegment = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createSegment(networkId, name, cidr);
      setName('');
      setCidr('');
      load();
      onChanged?.();
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };

  const createGrant = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createSegmentGrant(networkId, source, destination);
      setSource('');
      setDestination('');
      load();
      onChanged?.();
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };

  const transition = async (
    action: 'apply' | 'revoke',
    grantId: string,
  ) => {
    setBusy(true);
    setError(null);
    try {
      if (action === 'apply') {
        await api.applySegmentGrant(networkId, grantId);
      } else {
        await api.revokeSegmentGrant(networkId, grantId);
      }
      load();
      onChanged?.();
    } catch (e) {
      report(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h3>Segments and grants</h3>
      <p className="muted">
        A segment is a strict overlay subnet. Same-segment traffic is trusted;
        cross-segment traffic is blocked until the source-to-destination grant
        is applied (ADR-012).
      </p>
      {segments === null || grants === null ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>CIDR</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {segments.map((segment) => (
                <tr key={segment.id}>
                  <td>{segment.name}</td>
                  <td><code>{segment.cidr}</code></td>
                  <td>{segment.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {grants.length === 0 ? (
            <p className="muted">No segment grants.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Grant</th>
                  <th>Direction</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {grants.map((grant) => (
                  <tr key={grant.id}>
                    <td><code>{grant.id}</code></td>
                    <td>
                      <code>
                        {grant.source_segment_id} → {grant.destination_segment_id}
                      </code>
                    </td>
                    <td>{grant.status}</td>
                    <td>
                      {grant.status === 'pending' && (
                        <button type="button" className="link" disabled={busy}
                          onClick={() => transition('apply', grant.id)}>
                          Apply
                        </button>
                      )}
                      {grant.status !== 'revoked' && (
                        <button type="button" className="link danger" disabled={busy}
                          onClick={() => transition('revoke', grant.id)}>
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <form className="inline" onSubmit={createSegment}>
            <input placeholder="segment name" required value={name}
              onChange={(e) => setName(e.target.value)} />
            <input placeholder="strict overlay subnet CIDR" required value={cidr}
              onChange={(e) => setCidr(e.target.value)} />
            <button type="submit" disabled={busy}>Create segment</button>
          </form>
          <form className="inline" onSubmit={createGrant}>
            <select aria-label="source segment" required value={source}
              onChange={(e) => setSource(e.target.value)}>
              <option value="" disabled>source segment</option>
              {segments.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <select aria-label="destination segment" required value={destination}
              onChange={(e) => setDestination(e.target.value)}>
              <option value="" disabled>destination segment</option>
              {segments.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <button type="submit" disabled={busy || segments.length < 2}>
              Create grant
            </button>
          </form>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
