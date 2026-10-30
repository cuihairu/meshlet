import { useCallback, useEffect, useState } from 'react';
import {
  api,
  ApiError,
  type Device,
  type PublishDnsRecord,
  type PublishForward,
  type PublishHttpRoute,
  type PublishProbe,
} from '../../api';
import { formatTime } from '../../lib/format';
import { DeleteButton } from './DeleteButton';

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
