import { useEffect, useState } from 'react';
import { Button, ConfigProvider, Form, Input, Select } from 'antd';
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
          <Button type="text" onClick={onLogout}>
            {t('shell.signOut')}
          </Button>
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
    <Select
      className="network-picker"
      aria-label="network"
      value={selectedId ?? undefined}
      onChange={(value) => select(value ?? null)}
      loading={loading}
      disabled={!loading && networks.length === 0}
      placeholder={
        loading ? t('shell.networkLoading') : t('shell.networkPlaceholder')
      }
      options={networks.map((n) => ({
        value: n.id,
        label: `${n.name} (${n.overlay_cidr})`,
      }))}
    />
  );
}

function AuthGate({ onSignedIn }: { onSignedIn: (user: SessionUser) => void }) {
  const [mode, setMode] = useState<'login' | 'bootstrap'>('login');
  const [step, setStep] = useState<'credentials' | 'code'>('credentials');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

  const submit = async (values: { email: string; password: string; code?: string }) => {
    setBusy(true);
    setError(null);
    try {
      if (step === 'code') {
        // 第二步：带 TOTP 码重新提交登录。
        const user = await api.login(values.email, values.password, values.code);
        if (user.two_factor_required) {
          setError(t('auth.verifyCodeInvalid'));
        } else {
          onSignedIn(user);
        }
      } else {
        const user =
          mode === 'login'
            ? await api.login(values.email, values.password)
            : await api.bootstrap(values.email, values.password);
        if (mode === 'login' && user.two_factor_required) {
          // 服务端要求 TOTP 第二步（未种会话）——进入验证码步骤。
          setStep('code');
          return;
        }
        onSignedIn(user);
      }
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
    <Form className="auth" layout="vertical" onFinish={submit}>
      <h1>
        {step === 'code'
          ? t('auth.verifyCode')
          : mode === 'login'
            ? t('auth.signIn')
            : t('auth.createFirstAdmin')}
      </h1>
      {step === 'code' && <p className="muted">{t('auth.codeHint')}</p>}
      {mode === 'bootstrap' && step === 'credentials' && (
        <p className="muted">{t('auth.noAdminHint')}</p>
      )}
      <Form.Item
        label={t('auth.email')}
        name="email"
        rules={[{ required: true, message: t('auth.required') }]}
      >
        <Input type="email" autoComplete="username" disabled={step === 'code'} />
      </Form.Item>
      <Form.Item
        label={t('auth.password')}
        name="password"
        rules={[
          { required: true, message: t('auth.required') },
          ...(mode === 'bootstrap'
            ? [{ min: 12, message: t('auth.passwordMin') }]
            : []),
        ]}
      >
        <Input.Password
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          disabled={step === 'code'}
        />
      </Form.Item>
      {step === 'code' && (
        <Form.Item
          label={t('auth.code')}
          name="code"
          rules={[{ required: true, message: t('auth.required') }]}
        >
          <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
        </Form.Item>
      )}
      {error && <p className="error">{error}</p>}
      <Button type="primary" htmlType="submit" loading={busy} block>
        {step === 'code'
          ? t('auth.verify')
          : mode === 'login'
            ? t('auth.signIn')
            : t('auth.createAdmin')}
      </Button>
      <Button
        type="link"
        block
        onClick={() => {
          if (step === 'code') {
            // 返回凭据步骤（保持登录模式）。
            setStep('credentials');
          } else {
            setMode(mode === 'login' ? 'bootstrap' : 'login');
          }
          setError(null);
        }}
      >
        {step === 'code'
          ? t('auth.backToSignIn')
          : mode === 'login'
            ? t('auth.firstRun')
            : t('auth.backToSignIn')}
      </Button>
    </Form>
  );
}


export default App;
