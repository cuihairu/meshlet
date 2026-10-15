import { useCallback, useEffect, useState } from 'react';
import {
  api,
  ApiError,
  type ConfigRevision,
  type DataplaneEvidence,
  type Network,
  type SessionUser,
} from './api';
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

      {current && (
        <NetworkDetail network={current} onClose={() => setSelected(null)} onChanged={onChanged} />
      )}
    </div>
  );
}

function NetworkDetail({
  network,
  onClose,
  onChanged,
}: {
  network: Network;
  onClose: () => void;
  onChanged?: () => void;
}) {
  // Approving or denying a registration promotes/drops a pending device — the
  // devices list must reload alongside the registrations queue, so sibling
  // sections bump this key instead of reaching into each other's state.
  const [deviceListKey, setDeviceListKey] = useState(0);
  const bumpDeviceList = useCallback(() => setDeviceListKey((v) => v + 1), []);

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
          {network.apply_status}
        </span>
      </p>
      <DevicesSection
        networkId={network.id}
        onChanged={onChanged}
        refreshKey={deviceListKey}
      />
      <RegistrationsSection
        networkId={network.id}
        onChanged={onChanged}
        onDevicesChanged={bumpDeviceList}
      />
      <RoutesSection networkId={network.id} overlayCidr={network.overlay_cidr} onChanged={onChanged} />
      <AliasesSection networkId={network.id} onChanged={onChanged} />
      <DiagnosticsSection networkId={network.id} />
      <InvitesSection networkId={network.id} />
      <BootstrapTokensSection networkId={network.id} />
      <RevisionsSection networkId={network.id} />
    </section>
  );
}

function DevicesSection({
  networkId,
  onChanged,
  refreshKey = 0,
}: {
  networkId: string;
  onChanged?: () => void;
  /** Bumped by sibling sections (approve/deny) to force a reload. */
  refreshKey?: number;
}) {
  const [devices, setDevices] = useState<import('./api').Device[] | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [revoked, setRevoked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.listDevices(networkId).then(setDevices).catch(() => setDevices([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const revoke = async (deviceId: string) => {
    setBusy(true);
    setError(null);
    try {
      const ref = await api.revokeDevice(networkId, deviceId);
      setConfirming(null);
      setRevoked(`Device ${deviceId} revoked → revision #${ref.revision_id} (${ref.apply_status}).`);
      load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

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
              <th>Tunnel</th>
              <th>Fingerprint</th>
              <th></th>
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
                  <span className="muted" title="dataplane readings from the device's last heartbeat">
                    {d.dataplane_evidence ? (
                      [
                        `mtu ${d.dataplane_evidence.tunnel_mtu ?? '?'}`,
                        `probe ${d.dataplane_evidence.mtu_probe_payload ?? '—'}`,
                        d.dataplane_evidence.nat_rules_present != null
                          ? [
                              `nat ${d.dataplane_evidence.nat_rules_present ? '✓' : '✗'}`,
                              d.dataplane_evidence.nat_rules_present &&
                              d.dataplane_evidence.nat_snat_rules_present != null
                                ? `snat ${d.dataplane_evidence.nat_snat_rules_present ? '✓' : '✗'}`
                                : null,
                            ]
                          : null,
                      ]
                        .filter(Boolean)
                        .join(' · ')
                    ) : (
                      'no evidence'
                    )}
                  </span>
                </td>
                <td>
                  <code className="fingerprint">{d.fingerprint.slice(0, 16)}…</code>
                </td>
                <td>
                  {/* Defensive: only approved devices (never "pending" — that
                     state lives in the registrations queue) can be revoked. */}
                  {d.status === 'revoked' || d.status === 'pending' ? (
                    <span className="muted">—</span>
                  ) : confirming === d.id ? (
                    <>
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => revoke(d.id)}
                      >
                        Confirm revoke
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
                        setConfirming(d.id);
                        setRevoked(null);
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {revoked && <p className="muted">{revoked}</p>}
      {error && <p className="error">{error}</p>}
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

/**
 * Pending device self-registrations (ZeroTier-style bootstrap entry). Approve
 * allocates the overlay IP and records a revision; deny drops the request and
 * the device may re-register. No credential is re-issued either way — the
 * device keeps the agent token it received at registration.
 */
function RegistrationsSection({
  networkId,
  onChanged,
  onDevicesChanged,
}: {
  networkId: string;
  onChanged?: () => void;
  onDevicesChanged?: () => void;
}) {
  const [registrations, setRegistrations] = useState<
    import('./api').DeviceRegistration[] | null
  >(null);
  const [confirming, setConfirming] = useState<{
    id: string;
    action: 'approve' | 'deny';
  } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .listRegistrations(networkId)
      .then(setRegistrations)
      .catch(() => setRegistrations([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const act = async (
    deviceId: string,
    name: string,
    action: 'approve' | 'deny',
  ) => {
    setBusy(true);
    setError(null);
    try {
      if (action === 'approve') {
        const res = await api.approveRegistration(networkId, deviceId);
        setNotice(`已批准 ${name}：虚拟地址 ${res.virtual_ipv4} · 修订 #${res.revision_id}`);
      } else {
        await api.denyRegistration(networkId, deviceId);
        setNotice(`已拒绝 ${name} 的注册申请。`);
      }
      setConfirming(null);
      load();
      onDevicesChanged?.();
      onChanged?.();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h3>待审批设备</h3>
      <p className="muted">
        设备用自举码自助注册后在此排队，批准前不参与数据面。批准即分配
        overlay 地址并记入新修订；拒绝则丢弃申请（设备可重新注册）。设备
        继续沿用注册时领取的凭证。
      </p>
      {registrations === null ? (
        <p className="muted">加载中…</p>
      ) : registrations.length === 0 ? (
        <p className="muted">无待审批申请</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>名称</th>
              <th>平台</th>
              <th>ID</th>
              <th>申请时间</th>
              <th>最后上报</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {registrations.map((r) => {
              const confirmingRow =
                confirming && confirming.id === r.id ? confirming : null;
              return (
                <tr key={r.id} title={r.public_key}>
                  <td>{r.name}</td>
                  <td>{r.platform}</td>
                  <td>
                    <code>{r.id}</code>
                  </td>
                  <td>{formatTime(r.requested_at)}</td>
                  <td>
                    {r.last_report_at ? (
                      formatTime(r.last_report_at)
                    ) : (
                      <span className="muted">未上报</span>
                    )}
                  </td>
                  <td>
                    {confirmingRow ? (
                      <>
                        <button
                          type="button"
                          className={confirmingRow.action === 'deny' ? 'danger' : undefined}
                          disabled={busy}
                          onClick={() => act(r.id, r.name, confirmingRow.action)}
                        >
                          {confirmingRow.action === 'approve' ? '确认批准' : '确认拒绝'}
                        </button>{' '}
                        <button
                          type="button"
                          className="link"
                          onClick={() => setConfirming(null)}
                        >
                          取消
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          className="link"
                          onClick={() => {
                            setConfirming({ id: r.id, action: 'approve' });
                            setNotice(null);
                            setError(null);
                          }}
                        >
                          批准
                        </button>{' '}
                        <button
                          type="button"
                          className="link"
                          onClick={() => {
                            setConfirming({ id: r.id, action: 'deny' });
                            setNotice(null);
                            setError(null);
                          }}
                        >
                          拒绝
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {notice && <p className="muted">{notice}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

/**
 * LAN routes (ADR-005). A rejected create is never silent: the server answers
 * 409 naming the conflicting route, and the console surfaces it with the
 * Alias suggestion (archive §8.3 — never install a conflicting plain route).
 */
function RoutesSection({
  networkId,
  overlayCidr,
  onChanged,
}: {
  networkId: string;
  overlayCidr: string;
  onChanged?: () => void;
}) {
  const [routes, setRoutes] = useState<import('./api').LanRoute[] | null>(null);
  const [devices, setDevices] = useState<import('./api').Device[]>([]);
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

function formatTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/**
 * The gateway's kernel-verified dataplane reading, as reported by its agent
 * (§7.5 evidence). The ownership scan is per device, not per route — one
 * reading covers every route and alias the gateway serves — so this is a
 * row-level pointer, never a per-route verdict.
 */
function natReading(evidence: DataplaneEvidence | null): string {
  if (!evidence || evidence.nat_rules_present == null) {
    return 'not reported';
  }
  if (!evidence.nat_rules_present) {
    return 'rules absent';
  }
  if (evidence.nat_snat_rules_present == null) {
    return 'nat';
  }
  return evidence.nat_snat_rules_present ? 'nat + snat' : 'nat (sources kept)';
}

/**
 * Alias mappings (ADR-006/§12.6). Creating one publishes an alias-mode route
 * and binds the mapping to it — the target is derived server-side and shown
 * back. Deleting removes the mapping AND its route in one revision; the
 * confirm step says so explicitly.
 */
function AliasesSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [aliases, setAliases] = useState<import('./api').AliasMapping[] | null>(null);
  const [devices, setDevices] = useState<import('./api').Device[]>([]);
  const [routes, setRoutes] = useState<import('./api').LanRoute[]>([]);
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
  const gatewayEvidenceOf = (mapping: import('./api').AliasMapping): DataplaneEvidence | null => {
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

/**
 * Bootstrap tokens: long-lived, reusable self-registration credentials, unlike
 * one-shot invites. The raw token is revealed exactly once at creation (the
 * server stores only its SHA-256 digest), so the one-time reveal box is the
 * only chance to copy it. Revocation is immediate — already-registered devices
 * keep their own agent credential.
 */
function BootstrapTokensSection({ networkId }: { networkId: string }) {
  const [tokens, setTokens] = useState<import('./api').BootstrapToken[] | null>(null);
  // Unchecked limit = unlimited: max_uses is omitted from the body entirely.
  const [unlimited, setUnlimited] = useState(true);
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<import('./api').BootstrapTokenCreated | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .listBootstrapTokens(networkId)
      .then(setTokens)
      .catch(() => setTokens([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setCreated(
        await api.createBootstrapToken(networkId, unlimited ? undefined : maxUses),
      );
      load();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (tokenId: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.revokeBootstrapToken(networkId, tokenId);
      setConfirming(null);
      if (created?.token_id === tokenId) setCreated(null);
      load();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h3>自举码</h3>
      <p className="muted">
        设备自助注册的长期入口凭据（区别于一次性邀请）。原始自举码仅在创建时
        显示一次，服务端只存其 SHA-256 摘要；撤销立即生效。
      </p>
      {created && (
        <div className="token-box">
          <p>自举码（复制保存，仅显示一次）：</p>
          <code>{created.token}</code>
        </div>
      )}
      {tokens === null ? (
        <p className="muted">加载中…</p>
      ) : tokens.length === 0 ? (
        <p className="muted">尚无自举码。</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>使用上限</th>
              <th>已用</th>
              <th>创建时间</th>
              <th>状态</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td>
                  <code>{t.id}</code>
                </td>
                <td>{t.max_uses === null ? '不限' : t.max_uses}</td>
                <td>{t.used_count}</td>
                <td>{formatTime(t.created_at)}</td>
                <td>
                  {t.revoked_at ? <span className="muted">已撤销</span> : '有效'}
                </td>
                <td>
                  {t.revoked_at ? (
                    <span className="muted">—</span>
                  ) : confirming === t.id ? (
                    <>
                      <button
                        type="button"
                        className="danger"
                        disabled={busy}
                        onClick={() => revoke(t.id)}
                      >
                        确认撤销
                      </button>{' '}
                      <button
                        type="button"
                        className="link"
                        onClick={() => setConfirming(null)}
                      >
                        取消
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="link"
                      onClick={() => {
                        setConfirming(t.id);
                        setError(null);
                      }}
                    >
                      撤销
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form
        className="inline"
        onSubmit={(e) => {
          e.preventDefault();
          create();
        }}
      >
        <label>
          使用次数上限
          <input
            type="number"
            min={1}
            value={unlimited ? '' : maxUses}
            disabled={unlimited}
            required={!unlimited}
            placeholder="不限"
            onChange={(e) => setMaxUses(Number(e.target.value))}
          />
        </label>
        <label>
          不限次
          <input
            type="checkbox"
            checked={unlimited}
            onChange={(e) => setUnlimited(e.target.checked)}
          />
        </label>
        <button type="submit" disabled={busy}>
          创建自举码
        </button>
      </form>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function RevisionsSection({ networkId }: { networkId: string }) {
  const [revisions, setRevisions] = useState<ConfigRevision[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  const load = useCallback(() => {
    api
      .listRevisions(networkId)
      // The API returns ascending order; the console shows the newest first.
      .then((rows) => setRevisions([...rows].reverse()))
      .catch(() => setRevisions([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  // Newest first, so the head of the list is the current desired config — the
  // only revision the server accepts a rollback for.
  const currentRevision = revisions?.[0]?.revision;

  const act = async (action: 'apply' | 'rollback', revision: number) => {
    setBusy(revision);
    setError(null);
    try {
      if (action === 'apply') await api.applyRevision(networkId, revision);
      else await api.rollbackRevision(networkId, revision);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(null);
      load();
    }
  };

  return (
    <div>
      <h3>Config revisions</h3>
      <p className="muted">
        A new revision is recorded for every config change (network, device join,
        route, revoke). A database write is not an apply: the status below is
        the verdict. Apply targets the current desired config; rollback is only
        for the current failed revision — a superseded failure is refused rather
        than rolled back across the newer revision.
      </p>
      {revisions === null ? (
        <p className="muted">Loading…</p>
      ) : revisions.length === 0 ? (
        <p className="muted">No config revisions yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Revision</th>
              <th>Created</th>
              <th>Status</th>
              <th>Desired config hash</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {revisions.map((r) => (
              <tr key={r.revision}>
                <td>#{r.revision}</td>
                <td>{formatTime(r.created_at)}</td>
                <td>
                  <span className={`status status-${r.apply_status}`}>
                    {r.apply_status}
                  </span>
                  {r.error_summary && (
                    <span className="muted"> · {r.error_summary}</span>
                  )}
                </td>
                <td>
                  <code className="hash">{r.desired_config_hash.slice(0, 16)}…</code>
                </td>
                <td>
                  {r.revision === currentRevision && (
                    <button
                      type="button"
                      disabled={busy === r.revision}
                      onClick={() => act('apply', r.revision)}
                    >
                      Apply
                    </button>
                  )}
                  {(r.apply_status === 'failed' ||
                    r.apply_status === 'rollback_pending') &&
                    r.revision === currentRevision && (
                      <button
                        type="button"
                        className="link"
                        disabled={busy === r.revision}
                        onClick={() => act('rollback', r.revision)}
                      >
                        Rollback
                      </button>
                    )}
                  {(r.apply_status === 'failed' ||
                    r.apply_status === 'rollback_pending') &&
                    r.revision !== currentRevision && (
                      <span
                        className="muted"
                        title="Superseded by revision #{currentRevision}. Rolling this back would cross-touch objects the newer revision owns, so the server refuses it (409). Record a new revision instead."
                      >
                        superseded
                      </span>
                    )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

// §12.7 diagnostics: fixed layer order for grouping; status vocabulary is the
// API contract (pass / fail / warning / unavailable / not_applicable).
const LAYER_ORDER = ['tunnel', 'routing', 'forwarding', 'alias', 'control_plane'];
const LAYER_LABELS: Record<string, string> = {
  tunnel: 'Tunnel',
  routing: 'Routing',
  forwarding: 'Forwarding',
  alias: 'Alias',
  control_plane: 'Control plane',
};
const STATUS_LABELS: Record<string, string> = {
  pass: 'pass',
  fail: 'fail',
  warning: 'warning',
  unavailable: 'unavailable',
  not_applicable: 'not applicable',
};
const STATUS_COUNT_ORDER = ['pass', 'fail', 'warning', 'unavailable', 'not_applicable'];

function DiagnosticsSection({ networkId }: { networkId: string }) {
  const [report, setReport] = useState<import('./api').DiagnosticsReport | null>(null);
  const [notRun, setNotRun] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getDiagnostics(networkId)
      .then(setReport)
      .catch((e) => {
        // Never run: not an error state, just an empty page with a hint.
        if (e instanceof ApiError && e.status === 404) setNotRun(true);
        else setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      });
  }, [networkId]);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setReport(await api.runDiagnostics(networkId));
      setNotRun(false);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const counts = (report?.checks ?? []).reduce<Record<string, number>>((acc, c) => {
    acc[c.status] = (acc[c.status] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      <h3>
        Diagnostics{' '}
        <button type="button" onClick={run} disabled={busy}>
          Run checks
        </button>
      </h3>
      <p className="muted">
        13 checks across fault layers. <strong>unavailable</strong> means the
        control plane cannot observe a host-local fact — it is not a pass; run
        the given command on the device itself.
      </p>
      {notRun && !report && (
        <p className="muted">No diagnostics run yet — run the checks to take a snapshot.</p>
      )}
      {error && <p className="error">{error}</p>}
      {report && (
        <>
          <p className="muted">
            Checked {formatTime(report.checked_at)} ·{' '}
            {STATUS_COUNT_ORDER.filter((s) => counts[s])
              .map((s) => `${counts[s]} ${STATUS_LABELS[s]}`)
              .join(' · ')}
          </p>
          {LAYER_ORDER.map((layer) => {
            const items = report.checks.filter((c) => c.layer === layer);
            if (items.length === 0) return null;
            return (
              <div key={layer} className="diag-layer">
                <h4>{LAYER_LABELS[layer] ?? layer}</h4>
                <ul className="diag-list">
                  {items.map((c) => (
                    <li key={c.id}>
                      <span className={`diag diag-${c.status}`}>
                        {STATUS_LABELS[c.status] ?? c.status}
                      </span>{' '}
                      <strong>{c.name}</strong>
                      <div className="muted">{c.detail}</div>
                      {c.suggestion && <div className="diag-suggestion">{c.suggestion}</div>}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}

export default App;
