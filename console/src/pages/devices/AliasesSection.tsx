import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type DataplaneEvidence } from '../../api';
import { natReading } from '../../lib/nat';

/**
 * Alias mappings (ADR-006/§12.6). Creating one publishes an alias-mode route
 * and binds the mapping to it — the target is derived server-side and shown
 * back. Deleting removes the mapping AND its route in one revision; the
 * confirm step says so explicitly.
 */
export function AliasesSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [aliases, setAliases] = useState<import('../../api').AliasMapping[] | null>(null);
  const [devices, setDevices] = useState<import('../../api').Device[]>([]);
  const [routes, setRoutes] = useState<import('../../api').LanRoute[]>([]);
  const [gateway, setGateway] = useState('');
  const [target, setTarget] = useState('');
  const [aliasCidr, setAliasCidr] = useState('');
  const [mode, setMode] = useState('dnat_snat');
  const [conflict, setConflict] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = useCallback(() => {
    api.listAliases(networkId).then(setAliases).catch(() => setAliases([]));
    api
      .listDevices(networkId)
      .then((rows) => setDevices(rows.filter((d) => d.status === 'active')))
      .catch(() => setDevices([]));
    api.listRoutes(networkId).then(setRoutes).catch(() => setRoutes([]));
  }, [networkId]);

  /** The mapping's bound route decides which gateway must carry its rules. */
  const gatewayEvidenceOf = (mapping: import('../../api').AliasMapping): DataplaneEvidence | null => {
    const route = routes.find((r) => r.id === mapping.lan_route_id);
    if (!route) return null;
    return devices.find((d) => d.id === route.gateway_device_id)
      ?.dataplane_evidence ?? null;
  };

  useEffect(() => {
    load();
  }, [load]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setConflict(null);
    let routeId: string | null = null;
    try {
      // One ownership unit (§12.6): alias-mode route first, then the mapping.
      const route = await api.createRoute(
        networkId,
        gateway,
        target,
        'dual_route',
        'alias',
      );
      routeId = route.id;
      await api.createAlias(networkId, route.id, aliasCidr, mode);
      setTarget('');
      setAliasCidr('');
      load();
      onChanged?.();
    } catch (e) {
      // Nothing half-published: if the mapping was refused, remove the route
      // it was meant for so a rejected create leaves no trace (§8.3).
      if (routeId !== null) {
        try {
          await api.deleteRoute(networkId, routeId);
        } catch {
          // Surface the original error; the orphan route stays listed and removable.
        }
      }
      if (e instanceof ApiError && e.status === 409) {
        setConflict(e.message);
      } else {
        setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  const remove = async (aliasId: string) => {
    setError(null);
    setConflict(null);
    try {
      await api.deleteAlias(networkId, aliasId);
      setConfirming(null);
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    }
  };

  return (
    <div>
      <h3>Alias mappings</h3>
      <p className="muted">
        An alias rewrites an equal-length prefix at the gateway, so two sites
        with overlapping LAN space can still reach each other (ADR-006). Each
        mapping owns its route: deleting one removes both in a single revision.
        The virtual prefix must stay disjoint from the overlay and every other
        LAN prefix; broadcasts and L2 discovery do not cross an alias (§9.6).{' '}
        <strong>Gateway kernel</strong> is that gateway's own reading (§7.5):
        the kernel scan is per device, so one reading covers every alias it
        serves — mixed modes on one gateway show the same reading on both rows.
      </p>
      {aliases === null ? (
        <p className="muted">Loading…</p>
      ) : aliases.length === 0 ? (
        <p className="muted">No alias mappings.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Alias</th>
              <th>Real target</th>
              <th>NAT mode</th>
              <th>Gateway kernel</th>
              <th>Status</th>
              <th>Route</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {aliases.map((a) => (
              <tr key={a.id}>
                <td>
                  <code>{a.alias_cidr}</code>
                </td>
                <td>
                  <code>{a.target_cidr}</code>
                </td>
                <td>{a.translation_mode}</td>
                <td className="muted">{natReading(gatewayEvidenceOf(a))}</td>
                <td>{a.status}</td>
                <td>
                  <code>{a.lan_route_id}</code>
                </td>
                <td>
                  {confirming === a.id ? (
                    <>
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => remove(a.id)}
                      >
                        Confirm delete
                      </button>{' '}
                      <button
                        type="button"
                        className="link"
                        onClick={() => setConfirming(null)}
                      >
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="link"
                      onClick={() => {
                        setConfirming(a.id);
                        setConflict(null);
                        setError(null);
                      }}
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {confirming && (
        <p className="muted">
          Deleting an alias also removes its bound route — both sides lose the
          translation (§12.6).
        </p>
      )}
      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>Alias conflict — nothing was published.</strong>
          </p>
          <p>{conflict}</p>
        </div>
      )}
      <form className="inline" onSubmit={submit}>
        <select
          required
          value={gateway}
          onChange={(e) => setGateway(e.target.value)}
          aria-label="gateway device"
        >
          <option value="" disabled>
            gateway device
          </option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </select>
        <input
          placeholder="real LAN CIDR (target)"
          required
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <input
          placeholder="alias CIDR (same prefix length)"
          required
          value={aliasCidr}
          onChange={(e) => setAliasCidr(e.target.value)}
        />
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          aria-label="translation mode"
        >
          <option value="dnat_snat">dnat_snat</option>
          <option value="dnat_only">dnat_only</option>
        </select>
        <button type="submit" disabled={busy || devices.length === 0}>
          Create alias
        </button>
      </form>
      {devices.length === 0 && (
        <p className="muted">Enroll an active device first — it becomes the gateway.</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
