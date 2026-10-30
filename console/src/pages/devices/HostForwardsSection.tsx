import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../../api';
import { natReading } from '../../lib/nat';

export function HostForwardsSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [forwards, setForwards] = useState<import('../../api').HostForward[] | null>(null);
  const [devices, setDevices] = useState<import('../../api').Device[]>([]);
  const [gateway, setGateway] = useState('');
  const [target, setTarget] = useState('');
  const [aliasIp, setAliasIp] = useState('');
  const [mode, setMode] = useState('dnat_snat');
  const [conflict, setConflict] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = useCallback(() => {
    api.listHostForwards(networkId).then(setForwards).catch(() => setForwards([]));
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
      await api.createHostForward(networkId, gateway, target, aliasIp, mode);
      setTarget('');
      setAliasIp('');
      load();
      onChanged?.();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setConflict(e.message);
      else setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (aliasId: string) => {
    setError(null);
    setConflict(null);
    try {
      await api.deleteHostForward(networkId, aliasId);
      setConfirming(null);
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    }
  };

  return (
    <div>
      <h3>Host forwarding</h3>
      <p className="muted">
        Forward every protocol and port for one LAN host. The server creates a{' '}
        <code>/32</code> alias unit in one revision; clients use the virtual
        host address, and the selected gateway translates it to the real host.
        Deleting removes both sides atomically.
      </p>
      {forwards === null ? (
        <p className="muted">Loading…</p>
      ) : forwards.length === 0 ? (
        <p className="muted">No host forwards.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Virtual host</th>
              <th>Real host</th>
              <th>Gateway</th>
              <th>NAT mode</th>
              <th>Gateway kernel</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {forwards.map((forward) => (
              <tr key={forward.id}>
                <td>
                  <code>{forward.alias_ipv4}</code>
                </td>
                <td>
                  <code>{forward.target_ipv4}</code>
                </td>
                <td>
                  {devices.find((d) => d.id === forward.gateway_device_id)?.name ??
                    forward.gateway_device_id}
                </td>
                <td>{forward.translation_mode}</td>
                <td className="muted">
                  {natReading(
                    devices.find((d) => d.id === forward.gateway_device_id)
                      ?.dataplane_evidence ?? null,
                  )}
                </td>
                <td>{forward.status}</td>
                <td>
                  {confirming === forward.id ? (
                    <>
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => remove(forward.id)}
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
                        setConfirming(forward.id);
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
      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>Host forwarding conflict — nothing was published.</strong>
          </p>
          <p>{conflict}</p>
        </div>
      )}
      <form className="inline" onSubmit={submit}>
        <select
          required
          value={gateway}
          onChange={(e) => setGateway(e.target.value)}
          aria-label="host forwarding gateway"
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
          placeholder="real host IPv4"
          required
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <input
          placeholder="virtual host IPv4"
          required
          value={aliasIp}
          onChange={(e) => setAliasIp(e.target.value)}
        />
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          aria-label="host forwarding NAT mode"
        >
          <option value="dnat_snat">dnat_snat</option>
          <option value="dnat_only">dnat_only</option>
        </select>
        <button type="submit" disabled={busy || devices.length === 0}>
          Forward host
        </button>
      </form>
      {devices.length === 0 && (
        <p className="muted">Enroll an active device first — it becomes the gateway.</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
