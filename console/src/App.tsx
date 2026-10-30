import { useEffect, useState } from 'react';
import {
  BrowserRouter,
  Navigate,
  NavLink,
  Route,
  Routes,
} from 'react-router-dom';
import { api, ApiError, type SessionUser } from './api';
import { useNetwork } from './network-context';
import { NetworkProvider } from './network-provider';
import { AccessPage } from './pages/access/AccessPage';
import { DevicesPage } from './pages/devices/DevicesPage';
import { DiagnosticsPage } from './pages/diagnostics/DiagnosticsPage';
import { NetworksPage } from './pages/networks/NetworksPage';
import './App.css';

type AuthState =
  | { kind: 'checking' }
  | { kind: 'signed-out' }
  | { kind: 'signed-in'; user: SessionUser };

function App() {
  const [auth, setAuth] = useState<AuthState>({ kind: 'checking' });

  useEffect(() => {
    api
      .me()
      .then((user) => setAuth({ kind: 'signed-in', user }))
      .catch(() => setAuth({ kind: 'signed-out' }));
  }, []);

  const onSignedIn = (user: SessionUser) => {
    setAuth({ kind: 'signed-in', user });
  };

  const onLogout = async () => {
    try {
      await api.logout();
    } catch {
      // Even a failed logout drops the session locally.
    }
    setAuth({ kind: 'signed-out' });
  };

  return (
    <BrowserRouter>
      <div className="app">
        {auth.kind === 'signed-in' && (
          <NetworkProvider>
            <ConsoleLayout user={auth.user} onLogout={onLogout} />
          </NetworkProvider>
        )}
        <main>
          {auth.kind === 'checking' && <p className="muted">Loading…</p>}
          {auth.kind === 'signed-out' && <AuthGate onSignedIn={onSignedIn} />}
        </main>
      </div>
    </BrowserRouter>
  );
}

/**
 * Signed-in shell: top bar (brand, network picker, user) + left nav for the
 * four functional domains, with each domain on its own route.
 */
function ConsoleLayout({
  user,
  onLogout,
}: {
  user: SessionUser;
  onLogout: () => void;
}) {
  return (
    <>
      <header className="topbar">
        <span className="brand">meshlet</span>
        <NetworkSelector />
        <span className="user">
          {user.email}
          <button type="button" onClick={onLogout}>
            Sign out
          </button>
        </span>
      </header>
      <main className="shell">
        <nav className="sidenav" aria-label="console domains">
          <NavLink to="/networks">Networks</NavLink>
          <NavLink to="/access">Access</NavLink>
          <NavLink to="/devices">Devices</NavLink>
          <NavLink to="/diagnostics">Diagnostics</NavLink>
        </nav>
        <div className="page">
          <Routes>
            <Route path="/" element={<Navigate to="/networks" replace />} />
            <Route path="/networks" element={<NetworksPage />} />
            <Route path="/access" element={<AccessPage />} />
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/diagnostics" element={<DiagnosticsPage />} />
          </Routes>
        </div>
      </main>
    </>
  );
}

/** Top-bar network picker — the selection is shared by every domain page. */
function NetworkSelector() {
  const { networks, loading, selectedId, select } = useNetwork();
  return (
    <select
      className="network-picker"
      aria-label="network"
      value={selectedId ?? ''}
      onChange={(e) => select(e.target.value || null)}
      disabled={loading || networks.length === 0}
    >
      <option value="" disabled>
        {loading ? 'loading…' : 'select network'}
      </option>
      {networks.map((n) => (
        <option key={n.id} value={n.id}>
          {n.name} ({n.overlay_cidr})
        </option>
      ))}
    </select>
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


export default App;
