import { useCallback, useEffect, useState } from 'react';
import { Button, Form, Input, Select, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError, type Device, type LanRoute } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { natReading } from '../../lib/nat';
import { tagColor } from '../../lib/status-tag';

/**
 * LAN routes (ADR-005). A rejected create is never silent: the server answers
 * 409 naming the conflicting route, and the console surfaces it with the
 * Alias suggestion (archive §8.3 — never install a conflicting plain route).
 */
export function RoutesSection({
  networkId,
  overlayCidr,
  onChanged,
}: {
  networkId: string;
  overlayCidr: string;
  onChanged?: () => void;
}) {
  const [routes, setRoutes] = useState<LanRoute[] | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [gateway, setGateway] = useState('');
  const [destination, setDestination] = useState('');
  const [returnPath, setReturnPath] = useState('dual_route');
  const [conflict, setConflict] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

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

  const submit = async () => {
    if (!gateway || !destination) return;
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

  const columns: TableProps<LanRoute>['columns'] = [
    {
      title: t('routes.colRoute'),
      key: 'id',
      render: (_, r) => <code>{r.id}</code>,
    },
    {
      title: t('routes.colGateway'),
      key: 'gateway',
      render: (_, r) =>
        devices.find((d) => d.id === r.gateway_device_id)?.name ??
        r.gateway_device_id,
    },
    {
      title: t('routes.colDestination'),
      key: 'destination',
      render: (_, r) => <code>{r.destination_cidr}</code>,
    },
    {
      title: t('routes.colReturnPath'),
      key: 'return_path',
      render: (_, r) => r.return_path_mode,
    },
    {
      title: t('routes.colKernel'),
      key: 'kernel',
      render: (_, r) => (
        <span className="muted">
          {natReading(
            devices.find((d) => d.id === r.gateway_device_id)
              ?.dataplane_evidence ?? null,
            t,
          )}
        </span>
      ),
    },
    {
      title: t('routes.colStatus'),
      key: 'status',
      render: (_, r) => <Tag color={tagColor(r.status)}>{r.status}</Tag>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, r) => (
        <Button size="small" type="link" disabled={busy} onClick={() => remove(r.id)}>
          {t('routes.remove')}
        </Button>
      ),
    },
  ];

  return (
    <div>
      <h3>{t('routes.title')}</h3>
      <p className="muted">
        {t('routes.intro1')}
        <code>{overlayCidr}</code>
        {t('routes.intro2')}
        <strong>{t('routes.gatewayKernel')}</strong>
        {t('routes.intro3')}
      </p>
      {routes === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : routes.length === 0 ? (
        <p className="muted">{t('routes.none')}</p>
      ) : (
        <Table<LanRoute>
          rowKey="id"
          columns={columns}
          dataSource={routes}
          size="middle"
          pagination={false}
          scroll={{ x: true }}
        />
      )}
      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>{t('routes.conflictTitle')}</strong>
          </p>
          <p>{conflict}</p>
          <p className="muted">{t('routes.conflictHint')}</p>
        </div>
      )}
      <Form layout="inline" onFinish={submit} className="create-form">
        <Form.Item>
          <Select
            aria-label={t('routes.gatewayLabel')}
            placeholder={t('routes.gatewayLabel')}
            value={gateway || undefined}
            onChange={(v) => setGateway(v)}
            options={devices.map((d) => ({ value: d.id, label: d.name }))}
            style={{ minWidth: 180 }}
          />
        </Form.Item>
        <Form.Item>
          <Input
            placeholder={t('routes.destPlaceholder')}
            value={destination}
            onChange={(e) => setDestination(e.target.value)}
          />
        </Form.Item>
        <Form.Item>
          <Select
            aria-label={t('routes.returnPathLabel')}
            value={returnPath}
            onChange={(v) => setReturnPath(v)}
            options={[
              { value: 'dual_route', label: 'dual_route' },
              { value: 'controlled_snat', label: 'controlled_snat' },
            ]}
            style={{ minWidth: 150 }}
          />
        </Form.Item>
        <Form.Item>
          <Button
            type="primary"
            htmlType="submit"
            loading={busy}
            disabled={devices.length === 0}
          >
            {t('routes.publish')}
          </Button>
        </Form.Item>
      </Form>
      {devices.length === 0 && (
        <p className="muted">{t('routes.enrollFirst')}</p>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
