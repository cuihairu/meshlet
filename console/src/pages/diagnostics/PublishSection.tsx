import { useCallback, useEffect, useState } from 'react';
import { Button, Checkbox, Form, Input, Select, Table } from 'antd';
import type { TableProps } from 'antd';
import {
  api,
  ApiError,
  type Device,
  type PublishDnsRecord,
  type PublishForward,
  type PublishHttpRoute,
  type PublishProbe,
} from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { formatTime } from '../../lib/format';
import { DeleteButton } from './DeleteButton';

interface ForwardFormValues {
  device?: string;
  protocol?: string;
  listenerHost?: string;
  listenerPort?: string;
  backendHost?: string;
  backendPort?: string;
  cidrs?: string;
  bearer?: string;
}

interface RouteFormValues {
  device?: string;
  hostname?: string;
  pathPrefix?: string;
  backendHost?: string;
  backendPort?: string;
  listenerHost?: string;
  listenerPort?: string;
  cidrs?: string;
  bearer?: string;
  tlsPassthrough?: boolean;
}

interface ProbeFormValues {
  device?: string;
  kind?: string;
  address?: string;
  path?: string;
  status?: string;
  timeout?: string;
  interval?: string;
}

interface DnsFormValues {
  device?: string;
  name?: string;
  address?: string;
  ttl?: string;
  suffix?: string;
  bindHost?: string;
  bindPort?: string;
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
  const { t } = useLanguage();

  const [forwardForm] = Form.useForm();
  const [routeForm] = Form.useForm();
  const [probeForm] = Form.useForm();
  const [dnsForm] = Form.useForm();

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

  const createForward = async (values: ForwardFormValues) => {
    setError(null);
    setConflict(null);
    const listener = socket(values.listenerHost ?? '', values.listenerPort ?? '');
    const backend = socket(values.backendHost ?? '', values.backendPort ?? '');
    if (!listener || !backend) {
      setError(t('publish.invalidSocket'));
      return;
    }
    setBusy(true);
    try {
      await api.createPublishForward(networkId, {
        device_id: values.device ?? '',
        protocol: values.protocol ?? 'tcp',
        listener_address: listener,
        backend_address: backend,
        allowed_source_cidrs: splitList(values.cidrs ?? ''),
        allowed_bearer_tokens:
          (values.bearer ?? '').trim() === '' ? [] : [(values.bearer ?? '').trim()],
        enabled: true,
      });
      forwardForm.setFieldsValue({
        listenerPort: '',
        backendPort: '',
        bearer: '',
      });
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const createRoute = async (values: RouteFormValues) => {
    setError(null);
    setConflict(null);
    const backend = socket(values.backendHost ?? '', values.backendPort ?? '');
    const listener = socket(values.listenerHost ?? '', values.listenerPort ?? '');
    if (!backend || !listener) {
      setError(t('publish.invalidRouteSocket'));
      return;
    }
    setBusy(true);
    try {
      await api.createPublishHttpRoute(networkId, {
        device_id: values.device ?? '',
        hostname: (values.hostname ?? '').trim(),
        path_prefix: (values.pathPrefix ?? '').trim() === '' ? '/' : values.pathPrefix!.trim(),
        backend_address: backend,
        listener_address: listener,
        allowed_source_cidrs: splitList(values.cidrs ?? ''),
        allowed_bearer_tokens:
          (values.bearer ?? '').trim() === '' ? [] : [(values.bearer ?? '').trim()],
        tls_passthrough: values.tlsPassthrough ?? false,
      });
      routeForm.setFieldsValue({
        hostname: '',
        backendPort: '',
        listenerPort: '',
        bearer: '',
      });
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const createProbe = async (values: ProbeFormValues) => {
    setError(null);
    setConflict(null);
    const timeout = Number(values.timeout ?? '');
    const interval = positiveInt(values.interval ?? '');
    if (!(timeout > 0) || interval === null) {
      setError(t('publish.invalidProbe'));
      return;
    }
    const kind = values.kind ?? 'tcp';
    if (kind === 'http' && positiveInt(values.status ?? '') === null) {
      setError(t('publish.invalidProbeStatus'));
      return;
    }
    setBusy(true);
    try {
      await api.createPublishProbe(networkId, {
        device_id: values.device ?? '',
        target_kind: kind,
        address: (values.address ?? '').trim(),
        path: kind === 'http' ? (values.path ?? '').trim() : null,
        expected_status: kind === 'http' ? (positiveInt(values.status ?? '') as number) : null,
        timeout_secs: timeout,
        interval_secs: interval,
        enabled: true,
      });
      probeForm.setFieldsValue({ address: '' });
      load();
      onChanged?.();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  };

  const createDnsRecord = async (values: DnsFormValues) => {
    setError(null);
    setConflict(null);
    const ttl = positiveInt(values.ttl ?? '');
    const bind = socket(values.bindHost ?? '', values.bindPort ?? '');
    if (ttl === null || !bind) {
      setError(t('publish.invalidDns'));
      return;
    }
    setBusy(true);
    try {
      await api.createPublishDnsRecord(networkId, {
        device_id: values.device ?? '',
        name: (values.name ?? '').trim(),
        address: (values.address ?? '').trim(),
        ttl,
        priority: 1,
        bind_address: bind,
        internal_suffix: (values.suffix ?? '').trim(),
      });
      dnsForm.setFieldsValue({ name: '' });
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

  const deviceOptions = devices.map((d) => ({ value: d.id, label: d.name }));

  const forwardColumns: TableProps<PublishForward>['columns'] = [
    { title: t('publish.colProtocol'), key: 'protocol', render: (_, f) => f.protocol },
    {
      title: t('publish.colPublishedOn'),
      key: 'listener_address',
      render: (_, f) => <code>{f.listener_address}</code>,
    },
    {
      title: t('publish.colForwardsTo'),
      key: 'backend_address',
      render: (_, f) => <code>{f.backend_address}</code>,
    },
    {
      title: t('publish.colAllowedFrom'),
      key: 'allowed_source_cidrs',
      render: (_, f) => (
        <span className="muted">{f.allowed_source_cidrs.join(', ') || '—'}</span>
      ),
    },
    {
      title: t('publish.colTokens'),
      key: 'allowed_bearer_token_count',
      render: (_, f) => f.allowed_bearer_token_count,
    },
    {
      title: t('publish.colDevice'),
      key: 'device',
      render: (_, f) => deviceName(f.device_id),
    },
    {
      title: '',
      key: 'actions',
      render: (_, f) => (
        <DeleteButton busy={busy} onDelete={() => remove('forward', f.id)} />
      ),
    },
  ];

  const routeColumns: TableProps<PublishHttpRoute>['columns'] = [
    { title: t('publish.colHost'), key: 'hostname', render: (_, r) => <code>{r.hostname}</code> },
    { title: t('publish.colPath'), key: 'path_prefix', render: (_, r) => <code>{r.path_prefix}</code> },
    { title: t('publish.colForwardsTo'), key: 'backend_address', render: (_, r) => <code>{r.backend_address}</code> },
    { title: t('publish.colListener'), key: 'listener_address', render: (_, r) => <code>{r.listener_address}</code> },
    {
      title: t('publish.colTls'),
      key: 'tls',
      render: (_, r) => (r.tls_passthrough ? t('publish.sniPassthrough') : t('publish.plain')),
    },
    {
      title: t('publish.colAllowedFrom'),
      key: 'allowed_source_cidrs',
      render: (_, r) => (
        <span className="muted">{r.allowed_source_cidrs.join(', ') || '—'}</span>
      ),
    },
    { title: t('publish.colDevice'), key: 'device', render: (_, r) => deviceName(r.device_id) },
    {
      title: '',
      key: 'actions',
      render: (_, r) => (
        <DeleteButton busy={busy} onDelete={() => remove('route', r.id)} />
      ),
    },
  ];

  const probeColumns: TableProps<PublishProbe>['columns'] = [
    { title: t('publish.colKind'), key: 'target_kind', render: (_, p) => p.target_kind },
    {
      title: t('publish.colTarget'),
      key: 'address',
      render: (_, p) => (
        <code>
          {p.address}
          {p.path ?? ''}
        </code>
      ),
    },
    {
      title: t('publish.colEvery'),
      key: 'interval_secs',
      render: (_, p) => <span className="muted">{p.interval_secs}s</span>,
    },
    {
      title: t('publish.colLastState'),
      key: 'last_state',
      render: (_, p) => p.last_state ?? t('publish.pending'),
    },
    {
      title: t('publish.colLastChecked'),
      key: 'last_checked_at',
      render: (_, p) => <span className="muted">{formatTime(p.last_checked_at)}</span>,
    },
    {
      title: t('publish.colDetail'),
      key: 'last_detail',
      render: (_, p) => <span className="muted">{p.last_detail ?? ''}</span>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, p) => (
        <DeleteButton busy={busy} onDelete={() => remove('probe', p.id)} />
      ),
    },
  ];

  const dnsColumns: TableProps<PublishDnsRecord>['columns'] = [
    { title: t('publish.colName'), key: 'name', render: (_, r) => <code>{r.name}</code> },
    { title: t('publish.colAddress'), key: 'address', render: (_, r) => <code>{r.address}</code> },
    { title: t('publish.colTtl'), key: 'ttl', render: (_, r) => <span className="muted">{r.ttl}</span> },
    { title: t('publish.colSuffix'), key: 'internal_suffix', render: (_, r) => r.internal_suffix },
    { title: t('publish.colListener'), key: 'bind_address', render: (_, r) => <code>{r.bind_address}</code> },
    { title: t('publish.colDevice'), key: 'device', render: (_, r) => deviceName(r.device_id) },
    {
      title: '',
      key: 'actions',
      render: (_, r) => (
        <DeleteButton busy={busy} onDelete={() => remove('dns', r.id)} />
      ),
    },
  ];

  return (
    <div>
      <h3>{t('publish.title')}</h3>
      <p className="muted">{t('publish.intro')}</p>

      <h4>{t('publish.forwardTitle')}</h4>
      {forwards === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : forwards.length === 0 ? (
        <p className="muted">{t('publish.noneForwards')}</p>
      ) : (
        <Table<PublishForward>
          rowKey="id"
          columns={forwardColumns}
          dataSource={forwards}
          size="middle"
          pagination={false}
        />
      )}
      <Form
        form={forwardForm}
        name="publishForward"
        layout="inline"
        onFinish={createForward}
        className="create-form"
        initialValues={{
          protocol: 'tcp',
          listenerHost: '0.0.0.0',
          backendHost: '127.0.0.1',
          cidrs: '0.0.0.0/0',
          bearer: '',
        }}
      >
        <Form.Item name="device" label={t('publish.deviceLabel')}>
          <Select
            placeholder={t('publish.devicePlaceholder')}
            options={deviceOptions}
            style={{ minWidth: 160 }}
          />
        </Form.Item>
        <Form.Item name="protocol" label={t('publish.protocolLabel')}>
          <Select
            options={[
              { value: 'tcp', label: 'tcp' },
              { value: 'udp', label: 'udp' },
            ]}
            style={{ minWidth: 90 }}
          />
        </Form.Item>
        <Form.Item name="listenerHost" label={t('publish.listenerHostLabel')}>
          <Input placeholder={t('publish.listenerHostPlaceholder')} />
        </Form.Item>
        <Form.Item name="listenerPort" label={t('publish.listenerPortLabel')}>
          <Input placeholder={t('publish.listenerPortPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item name="backendHost" label={t('publish.backendHostLabel')}>
          <Input placeholder={t('publish.backendHostPlaceholder')} />
        </Form.Item>
        <Form.Item name="backendPort" label={t('publish.backendPortLabel')}>
          <Input placeholder={t('publish.backendPortPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item name="cidrs" label={t('publish.cidrsLabel')}>
          <Input placeholder={t('publish.cidrsPlaceholder')} />
        </Form.Item>
        <Form.Item name="bearer" label={t('publish.bearerLabel')}>
          <Input placeholder={t('publish.bearerPlaceholder')} />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" disabled={busy || devices.length === 0}>
            {t('publish.publishPort')}
          </Button>
        </Form.Item>
      </Form>

      <h4>{t('publish.routeTitle')}</h4>
      {routes === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : routes.length === 0 ? (
        <p className="muted">{t('publish.noneRoutes')}</p>
      ) : (
        <Table<PublishHttpRoute>
          rowKey="id"
          columns={routeColumns}
          dataSource={routes}
          size="middle"
          pagination={false}
        />
      )}
      <Form
        form={routeForm}
        name="publishRoute"
        layout="inline"
        onFinish={createRoute}
        className="create-form"
        initialValues={{
          pathPrefix: '/',
          backendHost: '127.0.0.1',
          listenerHost: '0.0.0.0',
          cidrs: '0.0.0.0/0',
          bearer: '',
          tlsPassthrough: false,
        }}
      >
        <Form.Item name="device" label={t('publish.routeDeviceLabel')}>
          <Select
            placeholder={t('publish.devicePlaceholder')}
            options={deviceOptions}
            style={{ minWidth: 160 }}
          />
        </Form.Item>
        <Form.Item name="hostname" label={t('publish.hostnameLabel')}>
          <Input placeholder={t('publish.hostnamePlaceholder')} />
        </Form.Item>
        <Form.Item name="pathPrefix" label={t('publish.pathPrefixLabel')}>
          <Input placeholder={t('publish.pathPrefixPlaceholder')} />
        </Form.Item>
        <Form.Item name="backendHost" label={t('publish.routeBackendHostLabel')}>
          <Input placeholder={t('publish.routeBackendHostPlaceholder')} />
        </Form.Item>
        <Form.Item name="backendPort" label={t('publish.routeBackendPortLabel')}>
          <Input placeholder={t('publish.routeBackendPortPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item name="listenerHost" label={t('publish.routeListenerHostLabel')}>
          <Input placeholder={t('publish.routeListenerHostPlaceholder')} />
        </Form.Item>
        <Form.Item name="listenerPort" label={t('publish.routeListenerPortLabel')}>
          <Input placeholder={t('publish.routeListenerPortPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item name="cidrs" label={t('publish.routeCidrsLabel')}>
          <Input placeholder={t('publish.cidrsPlaceholder')} />
        </Form.Item>
        <Form.Item name="bearer" label={t('publish.routeBearerLabel')}>
          <Input placeholder={t('publish.bearerPlaceholder')} />
        </Form.Item>
        <Form.Item name="tlsPassthrough" label={t('publish.tlsPassthroughLabel')} valuePropName="checked">
          <Checkbox />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" disabled={busy || devices.length === 0}>
            {t('publish.publishRoute')}
          </Button>
        </Form.Item>
      </Form>

      <h4>{t('publish.probeTitle')}</h4>
      {probes === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : probes.length === 0 ? (
        <p className="muted">{t('publish.noneProbes')}</p>
      ) : (
        <Table<PublishProbe>
          rowKey="id"
          columns={probeColumns}
          dataSource={probes}
          size="middle"
          pagination={false}
        />
      )}
      <Form
        form={probeForm}
        name="publishProbe"
        layout="inline"
        onFinish={createProbe}
        className="create-form"
        initialValues={{
          kind: 'tcp',
          path: '/',
          status: '200',
          timeout: '3',
          interval: '30',
        }}
      >
        <Form.Item name="device" label={t('publish.probeDeviceLabel')}>
          <Select
            placeholder={t('publish.devicePlaceholder')}
            options={deviceOptions}
            style={{ minWidth: 160 }}
          />
        </Form.Item>
        <Form.Item name="kind" label={t('publish.probeKindLabel')}>
          <Select
            options={[
              { value: 'tcp', label: 'tcp' },
              { value: 'http', label: 'http' },
            ]}
            style={{ minWidth: 90 }}
          />
        </Form.Item>
        <Form.Item name="address" label={t('publish.probeAddressLabel')}>
          <Input placeholder={t('publish.probeAddressPlaceholder')} />
        </Form.Item>
        <Form.Item name="path" label={t('publish.probePathLabel')}>
          <Input placeholder={t('publish.probePathPlaceholder')} />
        </Form.Item>
        <Form.Item name="status" label={t('publish.probeStatusLabel')}>
          <Input placeholder={t('publish.probeStatusPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item name="timeout" label={t('publish.probeTimeoutLabel')}>
          <Input placeholder={t('publish.probeTimeoutPlaceholder')} inputMode="decimal" />
        </Form.Item>
        <Form.Item name="interval" label={t('publish.probeIntervalLabel')}>
          <Input placeholder={t('publish.probeIntervalPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" disabled={busy || devices.length === 0}>
            {t('publish.addProbe')}
          </Button>
        </Form.Item>
      </Form>

      <h4>{t('publish.dnsTitle')}</h4>
      {dns === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : dns.length === 0 ? (
        <p className="muted">{t('publish.noneDns')}</p>
      ) : (
        <Table<PublishDnsRecord>
          rowKey="id"
          columns={dnsColumns}
          dataSource={dns}
          size="middle"
          pagination={false}
        />
      )}
      <Form
        form={dnsForm}
        name="publishDns"
        layout="inline"
        onFinish={createDnsRecord}
        className="create-form"
        initialValues={{
          ttl: '300',
          suffix: 'mesh.internal',
          bindHost: '0.0.0.0',
        }}
      >
        <Form.Item name="device" label={t('publish.dnsDeviceLabel')}>
          <Select
            placeholder={t('publish.devicePlaceholder')}
            options={deviceOptions}
            style={{ minWidth: 160 }}
          />
        </Form.Item>
        <Form.Item name="name" label={t('publish.dnsNameLabel')}>
          <Input placeholder={t('publish.dnsNamePlaceholder')} />
        </Form.Item>
        <Form.Item name="address" label={t('publish.dnsAddressLabel')}>
          <Input placeholder={t('publish.dnsAddressPlaceholder')} />
        </Form.Item>
        <Form.Item name="ttl" label={t('publish.dnsTtlLabel')}>
          <Input placeholder={t('publish.dnsTtlPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item name="suffix" label={t('publish.dnsSuffixLabel')}>
          <Input placeholder={t('publish.dnsSuffixPlaceholder')} />
        </Form.Item>
        <Form.Item name="bindHost" label={t('publish.dnsBindHostLabel')}>
          <Input placeholder={t('publish.dnsBindHostPlaceholder')} />
        </Form.Item>
        <Form.Item name="bindPort" label={t('publish.dnsBindPortLabel')}>
          <Input placeholder={t('publish.dnsBindPortPlaceholder')} inputMode="numeric" />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" disabled={busy || devices.length === 0}>
            {t('publish.addRecord')}
          </Button>
        </Form.Item>
      </Form>

      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>{t('publish.conflictTitle')}</strong>
          </p>
          <p>{conflict}</p>
        </div>
      )}
      {devices.length === 0 && (
        <p className="muted">{t('publish.enrollFirst')}</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
