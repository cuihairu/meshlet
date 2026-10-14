import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type Network, type SessionUser } from './api';
import './App.css';

type AuthState =
  | { kind: 'checking' }
  | { kind: 'signed-out' }
  | { kind: 'signed-in'; user: SessionUser };

function App() {
  const [auth, setAuth] = useState<AuthState>({ kind: 'checking' });
  const [networks, setNetworks] = useState<Network[] | null>(null);

  const refreshNetworks = useCallback(() => {
    api
      .listNetworks()
      .then(setNetworks)
      .catch(() => setNetworks([]));
  }, []);

  useEffect(() => {
    api
      .me()
      .then((user) => {
        setAuth({ kind: 'signed-in', user });
        refreshNetworks();
      })
      .catch(() => setAuth({ kind: 'signed-out' }));
  }, [refreshNetworks]);

  const onSignedIn = (user: SessionUser) => {
    setAuth({ kind: 'signed-in', user });
    setNetworks(null);
    refreshNetworks();
  };

  const onLogout = async () => {
    try {
      await api.logout();
    } catch {
      // Even a failed logout drops the session locally.
    }
    setAuth({ kind: 'signed-out' });
    setNetworks(null);
  };

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">meshlet</span>
        {auth.kind === 'signed-in' && (
          <span className="user">
            {auth.user.email}
            <button type="button" onClick={onLogout}>
              Sign out
            </button>
          </span>
        )}
      </header>
      <main>
        {auth.kind === 'checking' && <p className="muted">Loading…</p>}
        {auth.kind === 'signed-out' && <AuthGate onSignedIn={onSignedIn} />}
        {auth.kind === 'signed-in' && (
          <NetworksPanel networks={networks} onChanged={refreshNetworks} />
        )}
      </main>
    </div>
  );
}

function AuthGate({ onSignedIn }: { onSignedIn: (user: SessionUser) => void }) {
  const [mode, setMode] = useState<'login' | 'bootstrap'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const user =
        mode === 'login'
          ? await api.login(email, password)
          : await api.bootstrap(email, password);
      onSignedIn(user);
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.code}: ${e.message}`);
        // Bootstrap closes once an admin exists — send the user to login.
        if (mode === 'bootstrap' && e.code === 'conflict') setMode('login');
      } else {
        setError(String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="auth" onSubmit={submit}>
      <h1>{mode === 'login' ? 'Sign in' : 'Create first admin'}</h1>
      {mode === 'bootstrap' && (
        <p className="muted">No admin exists yet. This form is available only once.</p>
      )}
      <label>
        Email
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
        />
      </label>
      <label>
        Password
        <input
          type="password"
          required
          minLength={mode === 'bootstrap' ? 12 : 0}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
        />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" disabled={busy}>
        {mode === 'login' ? 'Sign in' : 'Create admin'}
      </button>
      <button
        type="button"
        className="link"
        onClick={() => {
          setMode(mode === 'login' ? 'bootstrap' : 'login');
          setError(null);
        }}
      >
        {mode === 'login' ? 'First run? Create the first admin' : 'Back to sign in'}
      </button>
    </form>
  );
}

function NetworksPanel({
  networks,
  onChanged,
}: {
  networks: Network[] | null;
  onChanged: () => void;
}) {
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('10.240.0.0/16');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createNetwork(name, cidr);
      setName('');
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const current = networks?.find((n) => n.id === selected) ?? null;

  return (
    <div className="panel">
      <section>
        <h2>Networks</h2>
        {networks === null ? (
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
                    <button type="button" onClick={() => setSelected(n.id)}>
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
      </section>

      {current && <NetworkDetail network={current} onClose={() => setSelected(null)} />}
    </div>
  );
}

function NetworkDetail({ network, onClose }: { network: Network; onClose: () => void }) {
  return (
    <section className="detail">
      <h2>
        {network.name} <code>{network.overlay_cidr}</code>
        <button type="button" className="link" onClick={onClose}>
          Close
        </button>
      </h2>
      <DevicesSection networkId={network.id} />
      <InvitesSection networkId={network.id} />
    </section>
  );
}

function DevicesSection({ networkId }: { networkId: string }) {
  const [devices, setDevices] = useState<import('./api').Device[] | null>(null);

  useEffect(() => {
    api.listDevices(networkId).then(setDevices).catch(() => setDevices([]));
  }, [networkId]);

  return (
    <div>
      <h3>Devices</h3>
      {devices === null ? (
        <p className="muted">Loading…</p>
      ) : devices.length === 0 ? (
        <p className="muted">
          No devices. Create an invite below and enroll an agent with the token.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Virtual IP</th>
              <th>Status</th>
              <th>Online</th>
              <th>Fingerprint</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} title={d.public_key} className={`state-${d.online_state}`}>
                <td>{d.name}</td>
                <td>
                  <code>{d.virtual_ipv4}</code>
                </td>
                <td>{d.status}</td>
                <td title={`source: ${d.presence_source}`}>
                  <span className={`dot ${d.online_state}`}>{d.online_state}</span>
                  <span className="muted"> · {SOURCE_LABELS[d.presence_source] ?? d.presence_source}</span>
                  <span className="muted"> · updated {formatTime(d.last_seen_at)}</span>
                </td>
                <td>
                  <code className="fingerprint">{d.fingerprint.slice(0, 16)}…</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/** Presence data sources (archive §12.2: a green dot must say why). */
const SOURCE_LABELS: Record<string, string> = {
  agent_report: 'agent report',
  handshake: 'wireguard handshake only',
  enrollment: 'enrollment',
  none: 'no evidence',
};

function formatTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function InvitesSection({ networkId }: { networkId: string }) {
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<import('./api').InviteCreated | null>(null);
  const [revoked, setRevoked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setCreated(await api.createInvite(networkId, maxUses));
      setRevoked(null);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (inviteId: string) => {
    setError(null);
    try {
      await api.revokeInvite(networkId, inviteId);
      setRevoked(inviteId);
      if (created?.invite_id === inviteId) setCreated(null);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    }
  };

  return (
    <div>
      <h3>Invites</h3>
      <p className="muted">
        The raw token is shown once at creation; the server stores only its SHA-256 digest.
      </p>
      {created && (
        <div className="token-box">
          <p>Invite token (copy now, shown once):</p>
          <code>{created.token}</code>
          {created.invite_id && (
            <button type="button" onClick={() => revoke(created.invite_id)}>
              Revoke this invite
            </button>
          )}
        </div>
      )}
      {revoked && <p className="muted">Invite {revoked} revoked.</p>}
      <div className="inline">
        <label>
          Max uses
          <input
            type="number"
            min={1}
            value={maxUses}
            onChange={(e) => setMaxUses(Number(e.target.value))}
          />
        </label>
        <button type="button" onClick={create} disabled={busy}>
          Create invite
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

export default App;
