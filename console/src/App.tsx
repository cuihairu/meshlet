import { useCallback, useEffect, useRef, useState } from 'react';
import {
  api,
  ApiError,
  type ConfigRevision,
  type DataplaneEvidence,
  type Device,
  type Network,
  type PublishDnsRecord,
  type PublishForward,
  type PublishHttpRoute,
  type PublishProbe,
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
          Hub: {network.apply_status}
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
      <SegmentGrantsSection networkId={network.id} onChanged={onChanged} />
      <HostForwardsSection networkId={network.id} onChanged={onChanged} />
      <PublishSection networkId={network.id} onChanged={onChanged} />
      <DiagnosticsSection networkId={network.id} />
      <InvitesSection networkId={network.id} />
      <BootstrapTokensSection networkId={network.id} />
      <RevisionsSection key={network.id} networkId={network.id} />
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
  const [segments, setSegments] = useState<import('./api').Segment[] | null>(null);
  const [grants, setGrants] = useState<import('./api').SegmentGrant[] | null>(null);
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

function HostForwardsSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [forwards, setForwards] = useState<import('./api').HostForward[] | null>(null);
  const [devices, setDevices] = useState<import('./api').Device[]>([]);
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

export function RevisionsSection({ networkId }: { networkId: string }) {
  const [revisions, setRevisions] = useState<ConfigRevision[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const requestRef = useRef<AbortController | null>(null);

  const load = useCallback(() => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    api
      .listRevisions(networkId, controller.signal)
      // The API returns ascending order; the console shows the newest first.
      .then((rows) => {
        if (requestRef.current !== controller || controller.signal.aborted) return;
        setRevisions([...rows].reverse());
        setError(null);
      })
      .catch((e) => {
        if (
          requestRef.current !== controller ||
          (e instanceof DOMException && e.name === 'AbortError')
        ) {
          return;
        }
        setError(e instanceof ApiError ? `${e.status} ${e.code}: ${e.message}` : String(e));
      });
  }, [networkId]);

  useEffect(() => {
    load();
    return () => requestRef.current?.abort();
  }, [load]);

  const waitingForDevices =
    revisions?.[0]?.convergence?.device_apply_status === 'pending';

  useEffect(() => {
    if (!waitingForDevices) return;
    const timer = window.setInterval(() => {
      void load();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [load, waitingForDevices]);

  const act = async (action: 'apply' | 'rollback', revision: number) => {
    setBusy(revision);
    setError(null);
    try {
      if (action === 'apply') await api.applyRevision(networkId, revision);
      else await api.rollbackRevision(networkId, revision);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.status} ${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(null);
      load();
    }
  };

  // Newest first, so the head of the list is the current desired config — the
  // only revision the server accepts a rollback for.
  const currentRevision = revisions?.[0]?.revision;

  return (
    <div>
      <h3>Config revisions</h3>
      <p className="muted">
        A new revision is recorded for every config change (network, device join,
        route, revoke). Apply publishes the current revision to the hub. Device
        receipts are tracked separately; business connectivity requires a probe.
        Rollback restores the last successful hub plan for the current failed revision.
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
                    Hub: {r.apply_status}
                  </span>
                  {r.convergence && (
                    <div className="muted">
                      <div>Devices: {({ pending: 'Waiting for receipts', applied: 'All devices applied', failed: 'Apply failed', not_configured: 'Data plane not configured' } as Record<string, string>)[r.convergence.device_apply_status] ?? r.convergence.device_apply_status}</div>
                      {r.convergence.pending_device_ids.length > 0 && (
                        <div>Waiting for: {r.convergence.pending_device_ids.join(', ')}</div>
                      )}
                      {Object.entries(r.convergence.device_errors).map(([device, error]) => (
                        <div key={device}>{device}: {error}</div>
                      ))}
                      {r.convergence.hub_recovery_error && <div>Hub recovery: {r.convergence.hub_recovery_error}</div>}
                      <div>Connectivity: {r.convergence.business_health === 'not_probed' ? 'Not probed' : r.convergence.business_health}</div>
                    </div>
                  )}
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
      {error && (
        <p className="error">
          Failed to load config revisions: {error}.{' '}
          <button type="button" className="link" onClick={load}>
            Retry
          </button>
        </p>
      )}
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

/** Two-step inline delete confirm — shared by the publish tables. */
function DeleteButton({
  busy,
  onDelete,
}: {
  busy: boolean;
  onDelete: () => Promise<void>;
}) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return (
      <button type="button" className="link" onClick={() => setConfirming(true)}>
        Delete
      </button>
    );
  }
  return (
    <>
      <button
        type="button"
        className="danger"
        disabled={busy}
        onClick={() => {
          onDelete().then(() => setConfirming(false));
        }}
      >
        Confirm delete
      </button>{' '}
      <button type="button" className="link" onClick={() => setConfirming(false)}>
        Cancel
      </button>
    </>
  );
}

/**
 * R-06 service publishing: desired-state objects an agent reconciles on a
 * device — L4 forwards, HTTP(S) routes, health probes and split-horizon DNS
 * answers. The row vocabulary (protocol / published port → target port) copies
 * Portainer's service "Port publishing" editor and Dokploy's per-app port
 * table; conflicts surface in the same nothing-was-published card as host
 * forwarding. Raw bearer tokens appear only on the create form — the read view
 * keeps a count.
 */
export function PublishSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [forwards, setForwards] = useState<PublishForward[] | null>(null);
  const [routes, setRoutes] = useState<PublishHttpRoute[] | null>(null);
  const [probes, setProbes] = useState<PublishProbe[] | null>(null);
  const [dns, setDns] = useState<PublishDnsRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // One shared device selector drives all four create forms.
  const [device, setDevice] = useState('');
  // L4 forward form (listener/backend split into host + port like Portainer).
  const [protocol, setProtocol] = useState('tcp');
  const [listenerHost, setListenerHost] = useState('0.0.0.0');
  const [listenerPort, setListenerPort] = useState('');
  const [backendHost, setBackendHost] = useState('127.0.0.1');
  const [backendPort, setBackendPort] = useState('');
  const [cidrs, setCidrs] = useState('0.0.0.0/0');
  const [bearer, setBearer] = useState('');
  // HTTP route form (own backend/CIDR/token fields — not shared with L4).
  const [hostname, setHostname] = useState('');
  const [pathPrefix, setPathPrefix] = useState('/');
  const [routeBackendHost, setRouteBackendHost] = useState('127.0.0.1');
  const [routeBackendPort, setRouteBackendPort] = useState('');
  const [routeListenerHost, setRouteListenerHost] = useState('0.0.0.0');
  const [routeListenerPort, setRouteListenerPort] = useState('');
  const [routeCidrs, setRouteCidrs] = useState('0.0.0.0/0');
  const [routeBearer, setRouteBearer] = useState('');
  const [tlsPassthrough, setTlsPassthrough] = useState(false);
  // Probe form.
  const [probeKind, setProbeKind] = useState('tcp');
  const [probeAddress, setProbeAddress] = useState('');
  const [probePath, setProbePath] = useState('/');
  const [probeStatus, setProbeStatus] = useState('200');
  const [probeTimeout, setProbeTimeout] = useState('3');
  const [probeInterval, setProbeInterval] = useState('30');
  // DNS record form.
  const [dnsName, setDnsName] = useState('');
  const [dnsAddress, setDnsAddress] = useState('');
  const [dnsTtl, setDnsTtl] = useState('300');
  const [dnsSuffix, setDnsSuffix] = useState('mesh.internal');
  const [dnsBindHost, setDnsBindHost] = useState('0.0.0.0');
  const [dnsBindPort, setDnsBindPort] = useState('');

  const load = useCallback(() => {
    api
      .listDevices(networkId)
      .then((rows) => setDevices(rows.filter((d) => d.status === 'active')))
      .catch(() => setDevices([]));
    api.listPublishForwards(networkId).then(setForwards).catch(() => setForwards([]));
    api.listPublishHttpRoutes(networkId).then(setRoutes).catch(() => setRoutes([]));
    api.listPublishProbes(networkId).then(setProbes).catch(() => setProbes([]));
    api.listPublishDnsRecords(networkId).then(setDns).catch(() => setDns([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const deviceName = (id: string) =>
    devices.find((d) => d.id === id)?.name ?? id;

  const splitList = (value: string) =>
    value
      .split(',')
      .map((part) => part.trim())
      .filter((part) => part.length > 0);

  const socket = (host: string, rawPort: string) => {
    const parsed = Number(rawPort);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) return null;
    return `${host.trim()}:${parsed}`;
  };

  const positiveInt = (value: string) => {
    const parsed = Number(value);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  };

  const fail = (e: unknown) => {
    if (e instanceof ApiError && e.status === 409) setConflict(e.message);
    else setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
  };

  const createForward = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setConflict(null);
    const listener = socket(listenerHost, listenerPort);
    const backend = socket(backendHost, backendPort);
    if (!listener || !backend) {
      setError('Listener and backend must each be a host plus a port 1-65535.');
      return;
    }
    setBusy(true);
    try {
      await api.createPublishForward(networkId, {
        device_id: device,
        protocol,
        listener_address: listener,
        backend_address: backend,
        allowed_source_cidrs: splitList(cidrs),
        allowed_bearer_tokens: bearer.trim() === '' ? [] : [bearer.trim()],
        enabled: true,
      });
      setListenerPort('');
      setBackendPort('');
      setBearer('');
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const createRoute = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setConflict(null);
    const backend = socket(routeBackendHost, routeBackendPort);
    const listener = socket(routeListenerHost, routeListenerPort);
    if (!backend || !listener) {
      setError('Backend and listener must each be a host plus a port 1-65535.');
      return;
    }
    setBusy(true);
    try {
      await api.createPublishHttpRoute(networkId, {
        device_id: device,
        hostname: hostname.trim(),
        path_prefix: pathPrefix.trim() === '' ? '/' : pathPrefix.trim(),
        backend_address: backend,
        listener_address: listener,
        allowed_source_cidrs: splitList(routeCidrs),
        allowed_bearer_tokens:
          routeBearer.trim() === '' ? [] : [routeBearer.trim()],
        tls_passthrough: tlsPassthrough,
      });
      setHostname('');
      setRouteBackendPort('');
      setRouteListenerPort('');
      setRouteBearer('');
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const createProbe = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setConflict(null);
    const timeout = Number(probeTimeout);
    const interval = positiveInt(probeInterval);
    if (!(timeout > 0) || interval === null) {
      setError('Probe timeout and interval must be positive seconds.');
      return;
    }
    if (probeKind === 'http' && positiveInt(probeStatus) === null) {
      setError('HTTP probes need a numeric expected status (e.g. 200).');
      return;
    }
    setBusy(true);
    try {
      await api.createPublishProbe(networkId, {
        device_id: device,
        target_kind: probeKind,
        address: probeAddress.trim(),
        path: probeKind === 'http' ? probePath.trim() : null,
        expected_status:
          probeKind === 'http' ? (positiveInt(probeStatus) as number) : null,
        timeout_secs: timeout,
        interval_secs: interval,
        enabled: true,
      });
      setProbeAddress('');
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const createDnsRecord = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setConflict(null);
    const ttl = positiveInt(dnsTtl);
    const bind = socket(dnsBindHost, dnsBindPort);
    if (ttl === null || !bind) {
      setError('DNS TTL must be positive and the bind must be host plus port 1-65535.');
      return;
    }
    setBusy(true);
    try {
      await api.createPublishDnsRecord(networkId, {
        device_id: device,
        name: dnsName.trim(),
        address: dnsAddress.trim(),
        ttl,
        priority: 1,
        bind_address: bind,
        internal_suffix: dnsSuffix.trim(),
      });
      setDnsName('');
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (
    kind: 'forward' | 'route' | 'probe' | 'dns',
    id: string,
  ) => {
    setError(null);
    setConflict(null);
    try {
      if (kind === 'forward') await api.deletePublishForward(networkId, id);
      if (kind === 'route') await api.deletePublishHttpRoute(networkId, id);
      if (kind === 'probe') await api.deletePublishProbe(networkId, id);
      if (kind === 'dns') await api.deletePublishDnsRecord(networkId, id);
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    }
  };

  return (
    <div>
      <h3>Service publishing</h3>
      <p className="muted">
        Publish services running on a device: L4 port forwards, HTTP(S) routes,
        health probes and internal DNS answers. Objects are desired state — the
        agent binds and re-binds the sockets on its next reconciliation.
      </p>

      <h4>Port forwards</h4>
      {forwards === null ? (
        <p className="muted">Loading…</p>
      ) : forwards.length === 0 ? (
        <p className="muted">No published ports.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Published on</th>
              <th>Forwards to</th>
              <th>Allowed from</th>
              <th>Tokens</th>
              <th>Device</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {forwards.map((forward) => (
              <tr key={forward.id}>
                <td>{forward.protocol}</td>
                <td>
                  <code>{forward.listener_address}</code>
                </td>
                <td>
                  <code>{forward.backend_address}</code>
                </td>
                <td className="muted">
                  {forward.allowed_source_cidrs.join(', ') || '—'}
                </td>
                <td>{forward.allowed_bearer_token_count}</td>
                <td>{deviceName(forward.device_id)}</td>
                <td>
                  <DeleteButton
                    busy={busy}
                    onDelete={() => remove('forward', forward.id)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="inline" onSubmit={createForward}>
        <select
          required
          value={device}
          onChange={(e) => setDevice(e.target.value)}
          aria-label="publish device"
        >
          <option value="" disabled>
            device
          </option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </select>
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value)}
          aria-label="forward protocol"
        >
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
        </select>
        <input
          placeholder="listener host"
          required
          value={listenerHost}
          onChange={(e) => setListenerHost(e.target.value)}
          aria-label="forward listener host"
        />
        <input
          placeholder="listener port"
          required
          inputMode="numeric"
          value={listenerPort}
          onChange={(e) => setListenerPort(e.target.value)}
          aria-label="forward listener port"
        />
        <input
          placeholder="backend host"
          required
          value={backendHost}
          onChange={(e) => setBackendHost(e.target.value)}
          aria-label="forward backend host"
        />
        <input
          placeholder="backend port"
          required
          inputMode="numeric"
          value={backendPort}
          onChange={(e) => setBackendPort(e.target.value)}
          aria-label="forward backend port"
        />
        <input
          placeholder="allowed source CIDRs"
          value={cidrs}
          onChange={(e) => setCidrs(e.target.value)}
          aria-label="forward allowed source CIDRs"
        />
        <input
          placeholder="bearer token (optional)"
          value={bearer}
          aria-label="forward bearer token"
          onChange={(e) => setBearer(e.target.value)}
        />
        <button type="submit" disabled={busy || devices.length === 0}>
          Publish port
        </button>
      </form>

      <h4>HTTP routes</h4>
      {routes === null ? (
        <p className="muted">Loading…</p>
      ) : routes.length === 0 ? (
        <p className="muted">No HTTP routes.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Path</th>
              <th>Forwards to</th>
              <th>Listener</th>
              <th>TLS</th>
              <th>Allowed from</th>
              <th>Device</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {routes.map((route) => (
              <tr key={route.id}>
                <td>
                  <code>{route.hostname}</code>
                </td>
                <td>
                  <code>{route.path_prefix}</code>
                </td>
                <td>
                  <code>{route.backend_address}</code>
                </td>
                <td>
                  <code>{route.listener_address}</code>
                </td>
                <td>{route.tls_passthrough ? 'SNI pass-through' : 'plain'}</td>
                <td className="muted">
                  {route.allowed_source_cidrs.join(', ') || '—'}
                </td>
                <td>{deviceName(route.device_id)}</td>
                <td>
                  <DeleteButton
                    busy={busy}
                    onDelete={() => remove('route', route.id)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="inline" onSubmit={createRoute}>
        <select
          required
          value={device}
          onChange={(e) => setDevice(e.target.value)}
          aria-label="http route device"
        >
          <option value="" disabled>
            device
          </option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </select>
        <input
          placeholder="hostname"
          required
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
        />
        <input
          placeholder="path prefix"
          value={pathPrefix}
          onChange={(e) => setPathPrefix(e.target.value)}
          aria-label="path prefix"
        />
        <input
          placeholder="route backend host"
          required
          value={routeBackendHost}
          onChange={(e) => setRouteBackendHost(e.target.value)}
          aria-label="route backend host"
        />
        <input
          placeholder="route backend port"
          required
          inputMode="numeric"
          value={routeBackendPort}
          onChange={(e) => setRouteBackendPort(e.target.value)}
          aria-label="route backend port"
        />
        <input
          placeholder="route listener host"
          required
          value={routeListenerHost}
          onChange={(e) => setRouteListenerHost(e.target.value)}
          aria-label="route listener host"
        />
        <input
          placeholder="route listener port"
          required
          inputMode="numeric"
          value={routeListenerPort}
          onChange={(e) => setRouteListenerPort(e.target.value)}
          aria-label="route listener port"
        />
        <input
          placeholder="allowed source CIDRs"
          value={routeCidrs}
          onChange={(e) => setRouteCidrs(e.target.value)}
          aria-label="route allowed source CIDRs"
        />
        <input
          placeholder="bearer token (optional)"
          value={routeBearer}
          onChange={(e) => setRouteBearer(e.target.value)}
          aria-label="route bearer token"
        />
        <label>
          <input
            type="checkbox"
            checked={tlsPassthrough}
            onChange={(e) => setTlsPassthrough(e.target.checked)}
          />{' '}
          TLS pass-through
        </label>
        <button type="submit" disabled={busy || devices.length === 0}>
          Publish route
        </button>
      </form>

      <h4>Health probes</h4>
      {probes === null ? (
        <p className="muted">Loading…</p>
      ) : probes.length === 0 ? (
        <p className="muted">No probes.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Kind</th>
              <th>Target</th>
              <th>Every</th>
              <th>Last state</th>
              <th>Last checked</th>
              <th>Detail</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {probes.map((probe) => (
              <tr key={probe.id}>
                <td>{probe.target_kind}</td>
                <td>
                  <code>
                    {probe.address}
                    {probe.path ?? ''}
                  </code>
                </td>
                <td className="muted">{probe.interval_secs}s</td>
                <td>{probe.last_state ?? 'pending'}</td>
                <td className="muted">{formatTime(probe.last_checked_at)}</td>
                <td className="muted">{probe.last_detail ?? ''}</td>
                <td>
                  <DeleteButton
                    busy={busy}
                    onDelete={() => remove('probe', probe.id)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="inline" onSubmit={createProbe}>
        <select
          required
          value={device}
          onChange={(e) => setDevice(e.target.value)}
          aria-label="probe device"
        >
          <option value="" disabled>
            device
          </option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </select>
        <select
          value={probeKind}
          onChange={(e) => setProbeKind(e.target.value)}
          aria-label="probe kind"
        >
          <option value="tcp">tcp</option>
          <option value="http">http</option>
        </select>
        <input
          placeholder="host:port"
          required
          value={probeAddress}
          onChange={(e) => setProbeAddress(e.target.value)}
        />
        <input
          placeholder="path"
          value={probePath}
          onChange={(e) => setProbePath(e.target.value)}
          aria-label="http probe path"
        />
        <input
          placeholder="status"
          inputMode="numeric"
          value={probeStatus}
          onChange={(e) => setProbeStatus(e.target.value)}
          aria-label="expected status"
        />
        <input
          placeholder="timeout s"
          inputMode="decimal"
          value={probeTimeout}
          onChange={(e) => setProbeTimeout(e.target.value)}
          aria-label="probe timeout seconds"
        />
        <input
          placeholder="interval s"
          inputMode="numeric"
          value={probeInterval}
          onChange={(e) => setProbeInterval(e.target.value)}
          aria-label="probe interval seconds"
        />
        <button type="submit" disabled={busy || devices.length === 0}>
          Add probe
        </button>
      </form>

      <h4>Internal DNS</h4>
      {dns === null ? (
        <p className="muted">Loading…</p>
      ) : dns.length === 0 ? (
        <p className="muted">No internal DNS records.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Address</th>
              <th>TTL</th>
              <th>Suffix</th>
              <th>Listener</th>
              <th>Device</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {dns.map((record) => (
              <tr key={record.id}>
                <td>
                  <code>{record.name}</code>
                </td>
                <td>
                  <code>{record.address}</code>
                </td>
                <td className="muted">{record.ttl}</td>
                <td>{record.internal_suffix}</td>
                <td>
                  <code>{record.bind_address}</code>
                </td>
                <td>{deviceName(record.device_id)}</td>
                <td>
                  <DeleteButton
                    busy={busy}
                    onDelete={() => remove('dns', record.id)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form className="inline" onSubmit={createDnsRecord}>
        <select
          required
          value={device}
          onChange={(e) => setDevice(e.target.value)}
          aria-label="dns device"
        >
          <option value="" disabled>
            device
          </option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name}
            </option>
          ))}
        </select>
        <input
          placeholder="service name"
          required
          value={dnsName}
          onChange={(e) => setDnsName(e.target.value)}
        />
        <input
          placeholder="IPv4 address"
          required
          value={dnsAddress}
          onChange={(e) => setDnsAddress(e.target.value)}
        />
        <input
          placeholder="ttl"
          inputMode="numeric"
          value={dnsTtl}
          onChange={(e) => setDnsTtl(e.target.value)}
          aria-label="dns ttl"
        />
        <input
          placeholder="internal suffix"
          required
          value={dnsSuffix}
          onChange={(e) => setDnsSuffix(e.target.value)}
          aria-label="internal dns suffix"
        />
        <input
          placeholder="bind host"
          required
          value={dnsBindHost}
          onChange={(e) => setDnsBindHost(e.target.value)}
        />
        <input
          placeholder="bind port"
          required
          inputMode="numeric"
          value={dnsBindPort}
          onChange={(e) => setDnsBindPort(e.target.value)}
          aria-label="dns bind port"
        />
        <button type="submit" disabled={busy || devices.length === 0}>
          Add record
        </button>
      </form>

      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>Publishing conflict — nothing was published.</strong>
          </p>
          <p>{conflict}</p>
        </div>
      )}
      {devices.length === 0 && (
        <p className="muted">Enroll an active device first — it publishes.</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

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
