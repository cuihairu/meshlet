import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../../api';
import { natReading } from '../../lib/nat';

/**
 * LAN routes (ADR-005). A rejected create is never silent: the server answers
 * 409 naming the conflicting route, and the console surfaces it with the
 * Alias suggestion (archive §8.3 — never install a conflicting plain route).
 */
export function RoutesSection({
  networkId,
  overlayCidr,
  onChanged,
}: {
  networkId: string;
  overlayCidr: string;
  onChanged?: () => void;
}) {
  const [routes, setRoutes] = useState<import('../../api').LanRoute[] | null>(null);
  const [devices, setDevices] = useState<import('../../api').Device[]>([]);
  const [gateway, setGateway] = useState('');
  const [destination, setDestination] = useState('');
  const [returnPath, setReturnPath] = useState('dual_route');
  const [conflict, setConflict] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.listRoutes(networkId).then(setRoutes).catch(() => setRoutes([]));
    api
      .listDevices(networkId)
      .then((rows) => setDevices(rows.filter((d) => d.status === 'active')))
      .catch(() => setDevices([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setConflict(null);
    try {
      await api.createRoute(networkId, gateway, destination, returnPath);
      setDestination('');
      load();
      onChanged?.();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        // The server message names the conflicting route — show it as-is.
        setConflict(e.message);
      } else {
        setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  const remove = async (routeId: string) => {
    setError(null);
    setConflict(null);
    try {
      await api.deleteRoute(networkId, routeId);
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    }
  };

  return (
    <div>
      <h3>LAN routes</h3>
      <p className="muted">
        Desired state only: a published route waits for the config apply
        (ADR-005/ADR-009). Destinations inside the overlay{' '}
        <code>{overlayCidr}</code> are refused — overlay traffic never goes
        through a LAN route. <strong>Gateway kernel</strong> is the gateway
        device's own reading from its agent (§7.5): the kernel scan is per
        device, so one reading covers every route and alias that gateway
        serves — it points at the gateway, it does not certify this row.
      </p>
      {routes === null ? (
        <p className="muted">Loading…</p>
      ) : routes.length === 0 ? (
        <p className="muted">No LAN routes published.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Route</th>
              <th>Gateway</th>
              <th>Destination</th>
              <th>Return path</th>
              <th>Gateway kernel</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {routes.map((r) => (
              <tr key={r.id}>
                <td>
                  <code>{r.id}</code>
                </td>
                <td>
                  {devices.find((d) => d.id === r.gateway_device_id)?.name ??
                    r.gateway_device_id}
                </td>
                <td>
                  <code>{r.destination_cidr}</code>
                </td>
                <td>{r.return_path_mode}</td>
                <td className="muted">
                  {natReading(
                    devices.find((d) => d.id === r.gateway_device_id)
                      ?.dataplane_evidence ?? null,
                  )}
                </td>
                <td>{r.status}</td>
                <td>
                  <button
                    type="button"
                    className="link"
                    disabled={busy}
                    onClick={() => remove(r.id)}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>Route conflict — nothing was published.</strong>
          </p>
          <p>{conflict}</p>
          <p className="muted">
            Same-subnet conflict? Publish the remote LAN as an equal-prefix
            Alias mapping instead of a plain route: the alias prefix is
            translated at the gateway, so both sides keep their own address
            space (archive §8.3/§9).
          </p>
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
          placeholder="destination CIDR"
          required
          value={destination}
          onChange={(e) => setDestination(e.target.value)}
        />
        <select
          value={returnPath}
          onChange={(e) => setReturnPath(e.target.value)}
          aria-label="return path mode"
        >
          <option value="dual_route">dual_route</option>
          <option value="controlled_snat">controlled_snat</option>
        </select>
        <button type="submit" disabled={busy || devices.length === 0}>
          Publish route
        </button>
      </form>
      {devices.length === 0 && (
        <p className="muted">Enroll an active device first — it becomes the gateway.</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
