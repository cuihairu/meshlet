import { useState } from 'react';
import { api, ApiError } from '../../api';
import { useNetwork } from '../../network-context';

export function NetworksPanel() {
  const { networks, loading, error, select, refresh } = useNetwork();
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('10.240.0.0/16');
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await api.createNetwork(name, cidr);
      setName('');
      refresh();
    } catch (e) {
      setFormError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <section>
        <h2>Networks</h2>
        {loading ? (
          <p className="muted">Loading…</p>
        ) : networks.length === 0 ? (
          <p className="muted">No networks yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Overlay</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {networks.map((n) => (
                <tr key={n.id}>
                  <td>{n.name}</td>
                  <td>
                    <code>{n.overlay_cidr}</code>
                  </td>
                  <td>{n.status}</td>
                  <td>
                    <button type="button" onClick={() => select(n.id)}>
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <form className="inline" onSubmit={create}>
          <input
            placeholder="network name"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <input
            placeholder="overlay CIDR"
            required
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
          />
          <button type="submit" disabled={busy}>
            Create network
          </button>
        </form>
        {error && <p className="error">{error}</p>}
        {formError && <p className="error">{formError}</p>}
      </section>
    </div>
  );
}
