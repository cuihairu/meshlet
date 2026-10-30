import { useCallback, useEffect, useState } from 'react';
import { Button, Form, Input, Select, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { natReading } from '../../lib/nat';
import { tagColor } from '../../lib/status-tag';

export function HostForwardsSection({
  networkId,
  onChanged,
}: {
  networkId: string;
  onChanged?: () => void;
}) {
  const [forwards, setForwards] = useState<import('../../api').HostForward[] | null>(null);
  const [devices, setDevices] = useState<import('../../api').Device[]>([]);
  const [gateway, setGateway] = useState<string | undefined>(undefined);
  const [target, setTarget] = useState('');
  const [aliasIp, setAliasIp] = useState('');
  const [mode, setMode] = useState('dnat_snat');
  const [conflict, setConflict] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const { t } = useLanguage();

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

  const submit = async () => {
    if (!gateway) return;
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

  const columns: TableProps<import('../../api').HostForward>['columns'] = [
    {
      title: t('forwards.colVirtualHost'),
      key: 'alias_ipv4',
      render: (_, f) => <code>{f.alias_ipv4}</code>,
    },
    {
      title: t('forwards.colRealHost'),
      key: 'target_ipv4',
      render: (_, f) => <code>{f.target_ipv4}</code>,
    },
    {
      title: t('forwards.colGateway'),
      key: 'gateway',
      render: (_, f) =>
        devices.find((d) => d.id === f.gateway_device_id)?.name ?? f.gateway_device_id,
    },
    {
      title: t('forwards.colNatMode'),
      key: 'translation_mode',
      render: (_, f) => f.translation_mode,
    },
    {
      title: t('forwards.colGatewayKernel'),
      key: 'gateway_kernel',
      render: (_, f) => (
        <span className="muted">
          {natReading(
            devices.find((d) => d.id === f.gateway_device_id)
              ?.dataplane_evidence ?? null,
            t,
          )}
        </span>
      ),
    },
    {
      title: t('forwards.colStatus'),
      key: 'status',
      render: (_, f) => <Tag color={tagColor(f.status)}>{f.status}</Tag>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, f) =>
        confirming === f.id ? (
          <>
            <Button size="small" danger loading={busy} onClick={() => remove(f.id)}>
              {t('forwards.confirmDelete')}
            </Button>{' '}
            <Button size="small" type="link" onClick={() => setConfirming(null)}>
              {t('forwards.cancel')}
            </Button>
          </>
        ) : (
          <Button
            size="small"
            type="link"
            onClick={() => {
              setConfirming(f.id);
              setConflict(null);
              setError(null);
            }}
          >
            {t('forwards.delete')}
          </Button>
        ),
    },
  ];

  return (
    <div>
      <h3>{t('forwards.title')}</h3>
      <p className="muted">
        {t('forwards.intro1')}
        <code>/32</code>
        {t('forwards.intro2')}
      </p>
      {forwards === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : forwards.length === 0 ? (
        <p className="muted">{t('forwards.none')}</p>
      ) : (
        <Table<import('../../api').HostForward>
          rowKey="id"
          columns={columns}
          dataSource={forwards}
          size="middle"
          pagination={false}
        />
      )}
      {conflict && (
        <div className="conflict" role="alert">
          <p>
            <strong>{t('forwards.conflictTitle')}</strong>
          </p>
          <p>{conflict}</p>
        </div>
      )}
      <Form layout="inline" onFinish={submit} className="create-form">
        <Form.Item label={t('forwards.gatewayLabel')}>
          <Select
            value={gateway}
            onChange={setGateway}
            placeholder={t('forwards.gatewayPlaceholder')}
            options={devices.map((d) => ({ value: d.id, label: d.name }))}
            style={{ minWidth: 180 }}
          />
        </Form.Item>
        <Form.Item>
          <Input
            placeholder={t('forwards.targetPlaceholder')}
            required
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </Form.Item>
        <Form.Item>
          <Input
            placeholder={t('forwards.aliasPlaceholder')}
            required
            value={aliasIp}
            onChange={(e) => setAliasIp(e.target.value)}
          />
        </Form.Item>
        <Form.Item label={t('forwards.modeLabel')}>
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
            {t('forwards.create')}
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
