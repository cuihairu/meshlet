import { useEffect, useState } from 'react';
import { ConfigProvider } from 'antd';
import enUS from 'antd/locale/en_US';
import zhCN from 'antd/locale/zh_CN';
import {
  HashRouter,
  Navigate,
  NavLink,
  Route,
  Routes,
} from 'react-router-dom';
import { api, ApiError, type SessionUser } from './api';
import { useNetwork } from './network-context';
import { NetworkProvider } from './network-provider';
import { useLanguage } from './i18n/language-context';
import { LanguageSwitch } from './i18n/LanguageSwitch';
import { useTheme } from './theme/theme-context';
import { antdThemeConfig } from './theme/antd-theme';
import { ThemeSwitch } from './theme/ThemeSwitch';
import { AccessPage } from './pages/access/AccessPage';
import { DevicesPage } from './pages/devices/DevicesPage';
import { DiagnosticsPage } from './pages/diagnostics/DiagnosticsPage';
import { NetworksPage } from './pages/networks/NetworksPage';
import './theme.css';
import './App.css';

type AuthState =
  | { kind: 'checking' }
  | { kind: 'signed-out' }
  | { kind: 'signed-in'; user: SessionUser };

function App() {
  const [auth, setAuth] = useState<AuthState>({ kind: 'checking' });
  const { lang, t } = useLanguage();
  const { theme } = useTheme();

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
    <ConfigProvider
      locale={lang === 'zh' ? zhCN : enUS}
      theme={antdThemeConfig(theme)}
    >
      <HashRouter>
        <div className="app">
          {auth.kind === 'signed-in' && (
            <NetworkProvider>
              <ConsoleLayout user={auth.user} onLogout={onLogout} />
            </NetworkProvider>
          )}
          <main>
            {auth.kind === 'checking' && <p className="muted">{t('app.loading')}</p>}
            {auth.kind === 'signed-out' && <AuthGate onSignedIn={onSignedIn} />}
          </main>
        </div>
      </HashRouter>
    </ConfigProvider>
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
  const { t } = useLanguage();
  return (
    <>
      <header className="topbar">
        <span className="brand">meshlet</span>
        <NetworkSelector />
        <span className="user">
          <LanguageSwitch />
          <ThemeSwitch />
          {user.email}
          <button type="button" onClick={onLogout}>
            {t('shell.signOut')}
          </button>
        </span>
      </header>
      <main className="shell">
        <nav className="sidenav" aria-label={t('shell.consoleDomains')}>
          <NavLink to="/networks">{t('nav.networks')}</NavLink>
          <NavLink to="/access">{t('nav.access')}</NavLink>
          <NavLink to="/devices">{t('nav.devices')}</NavLink>
          <NavLink to="/diagnostics">{t('nav.diagnostics')}</NavLink>
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
  const { t } = useLanguage();
  return (
    <select
      className="network-picker"
      aria-label="network"
      value={selectedId ?? ''}
      onChange={(e) => select(e.target.value || null)}
      disabled={loading || networks.length === 0}
    >
      <option value="" disabled>
        {loading ? t('shell.networkLoading') : t('shell.networkPlaceholder')}
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
  const { t } = useLanguage();

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
      <h1>{mode === 'login' ? t('auth.signIn') : t('auth.createFirstAdmin')}</h1>
      {mode === 'bootstrap' && (
        <p className="muted">{t('auth.noAdminHint')}</p>
      )}
      <label>
        {t('auth.email')}
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
        />
      </label>
      <label>
        {t('auth.password')}
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
        {mode === 'login' ? t('auth.signIn') : t('auth.createAdmin')}
      </button>
      <button
        type="button"
        className="link"
        onClick={() => {
          setMode(mode === 'login' ? 'bootstrap' : 'login');
          setError(null);
        }}
      >
        {mode === 'login' ? t('auth.firstRun') : t('auth.backToSignIn')}
      </button>
    </form>
  );
}


export default App;
