import { useState } from 'react';
import { Button, Form, Input, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError, type Network } from '../../api';
import { useNetwork } from '../../network-context';
import { useLanguage } from '../../i18n/language-context';
import { tagColor } from '../../lib/status-tag';

export function NetworksPanel() {
  const { networks, loading, error, select, refresh } = useNetwork();
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('10.240.0.0/16');
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

  const create = async () => {
    setBusy(true);
    setFormError(null);
    try {
      await api.createNetwork(name, cidr);
      setName('');
      refresh();
    } catch (e) {
      setFormError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const columns: TableProps<Network>['columns'] = [
    { title: t('networks.name'), dataIndex: 'name', key: 'name' },
    {
      title: t('networks.overlay'),
      dataIndex: 'overlay_cidr',
      key: 'overlay',
      render: (v: string) => <code>{v}</code>,
    },
    {
      title: t('networks.status'),
      dataIndex: 'status',
      key: 'status',
      render: (v: string) => <Tag color={tagColor(v)}>{v}</Tag>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, n) => (
        <Button size="small" onClick={() => select(n.id)}>
          {t('networks.open')}
        </Button>
      ),
    },
  ];

  return (
    <div className="panel">
      <section>
        <h2>{t('networks.title')}</h2>
        {loading ? (
          <p className="muted">{t('app.loading')}</p>
        ) : networks.length === 0 ? (
          <p className="muted">{t('networks.none')}</p>
        ) : (
          <Table<Network>
            rowKey="id"
            columns={columns}
            dataSource={networks}
            size="middle"
            pagination={false}
          />
        )}

        <Form layout="inline" onFinish={create} className="create-form">
          <Form.Item>
            <Input
              placeholder={t('networks.namePlaceholder')}
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </Form.Item>
          <Form.Item>
            <Input
              placeholder={t('networks.cidrPlaceholder')}
              required
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
            />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={busy}>
              {t('networks.create')}
            </Button>
          </Form.Item>
        </Form>
        {error && <p className="error">{error}</p>}
        {formError && <p className="error">{formError}</p>}
      </section>
    </div>
  );
}
