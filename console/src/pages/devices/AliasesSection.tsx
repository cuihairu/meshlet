import { useCallback, useEffect, useState } from 'react';
import { Button, Form, Input, Select, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError, type DataplaneEvidence } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { natReading } from '../../lib/nat';
import { tagColor } from '../../lib/status-tag';

/**
 * Alias mappings (ADR-006/§12.6). Creating one publishes an alias-mode route
 * and binds the mapping to it — the target is derived server-side and shown
 * back. Deleting removes the mapping AND its route in one revision; the
 * confirm step says so explicitly.
 */
export function AliasesSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [aliases, setAliases] = useState<import('../../api').AliasMapping[] | null>(null);
  const [devices, setDevices] = useState<import('../../api').Device[]>([]);
  const [routes, setRoutes] = useState<import('../../api').LanRoute[]>([]);
  const [gateway, setGateway] = useState<string | undefined>(undefined);
  const [target, setTarget] = useState('');
  const [aliasCidr, setAliasCidr] = useState('');
  const [mode, setMode] = useState('dnat_snat');
  const [conflict, setConflict] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const { t } = useLanguage();

  const load = useCallback(() => {
    api.listAliases(networkId).then(setAliases).catch(() => setAliases([]));
    api
      .listDevices(networkId)
      .then((rows) => setDevices(rows.filter((d) => d.status === 'active')))
      .catch(() => setDevices([]));
    api.listRoutes(networkId).then(setRoutes).catch(() => setRoutes([]));
  }, [networkId]);

  /** The mapping's bound route decides which gateway must carry its rules. */
  const gatewayEvidenceOf = (mapping: import('../../api').AliasMapping): DataplaneEvidence | null => {
    const route = routes.find((r) => r.id === mapping.lan_route_id);
    if (!route) return null;
    return devices.find((d) => d.id === route.gateway_device_id)
      ?.dataplane_evidence ?? null;
  };

  useEffect(() => {
    load();
  }, [load]);

  const submit = async () => {
    if (!gateway) return;
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

  const columns: TableProps<import('../../api').AliasMapping>['columns'] = [
    {
      title: t('aliases.colAlias'),
      key: 'alias_cidr',
      render: (_, a) => <code>{a.alias_cidr}</code>,
    },
    {
      title: t('aliases.colTarget'),
      key: 'target_cidr',
      render: (_, a) => <code>{a.target_cidr}</code>,
    },
    {
      title: t('aliases.colNatMode'),
      key: 'translation_mode',
      render: (_, a) => a.translation_mode,
    },
    {
      title: t('aliases.colGatewayKernel'),
      key: 'gateway_kernel',
      render: (_, a) => (
        <span className="muted">{natReading(gatewayEvidenceOf(a), t)}</span>
      ),
    },
    {
      title: t('aliases.colStatus'),
      key: 'status',
      render: (_, a) => <Tag color={tagColor(a.status)}>{a.status}</Tag>,
    },
    {
      title: t('aliases.colRoute'),
      key: 'lan_route_id',
      render: (_, a) => <code>{a.lan_route_id}</code>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, a) =>
        confirming === a.id ? (
          <>
            <Button size="small" danger loading={busy} onClick={() => remove(a.id)}>
              {t('aliases.confirmDelete')}
            </Button>{' '}
            <Button size="small" type="link" onClick={() => setConfirming(null)}>
              {t('aliases.cancel')}
            </Button>
          </>
        ) : (
          <Button
            size="small"
            type="link"
            onClick={() => {
              setConfirming(a.id);
              setConflict(null);
              setError(null);
            }}
          >
            {t('aliases.delete')}
          </Button>
        ),
    },
  ];

  return (
    <div>
      <h3>{t('aliases.title')}</h3>
      <p className="muted">
        {t('aliases.intro1')}
        <strong>{t('aliases.gatewayKernel')}</strong>
        {t('aliases.intro2')}
      </p>
      {aliases === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : aliases.length === 0 ? (
        <p className="muted">{t('aliases.none')}</p>
      ) : (
        <Table<import('../../api').AliasMapping>
          rowKey="id"
          columns={columns}
          dataSource={aliases}
          size="middle"
          pagination={false}
        />
      )}
      {confirming && <p className="muted">{t('aliases.deleteHint')}</p>}
      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>{t('aliases.conflictTitle')}</strong>
          </p>
          <p>{conflict}</p>
        </div>
      )}
      <Form layout="inline" onFinish={submit} className="create-form">
        <Form.Item label={t('aliases.gatewayLabel')}>
          <Select
            value={gateway}
            onChange={setGateway}
            placeholder={t('aliases.gatewayLabel')}
            options={devices.map((d) => ({ value: d.id, label: d.name }))}
            style={{ minWidth: 180 }}
          />
        </Form.Item>
        <Form.Item>
          <Input
            placeholder={t('aliases.targetPlaceholder')}
            required
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </Form.Item>
        <Form.Item>
          <Input
            placeholder={t('aliases.aliasPlaceholder')}
            required
            value={aliasCidr}
            onChange={(e) => setAliasCidr(e.target.value)}
          />
        </Form.Item>
        <Form.Item label={t('aliases.modeLabel')}>
          <Select
            value={mode}
            onChange={setMode}
            options={[
              { value: 'dnat_snat', label: 'dnat_snat' },
              { value: 'dnat_only', label: 'dnat_only' },
            ]}
            style={{ minWidth: 140 }}
          />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" disabled={busy || devices.length === 0 || !gateway}>
            {t('aliases.create')}
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
