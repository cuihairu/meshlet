import { useCallback, useEffect, useState } from 'react';
import { Button, Form, Input, Select, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { tagColor } from '../../lib/status-tag';

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
  const [segments, setSegments] = useState<import('../../api').Segment[] | null>(null);
  const [grants, setGrants] = useState<import('../../api').SegmentGrant[] | null>(null);
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [source, setSource] = useState<string | undefined>(undefined);
  const [destination, setDestination] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

  const load = useCallback(() => {
    api.listSegments(networkId).then(setSegments).catch(() => setSegments([]));
    api.listSegmentGrants(networkId).then(setGrants).catch(() => setGrants([]));
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load]);

  const report = (e: unknown) =>
    setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));

  const createSegment = async () => {
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

  const createGrant = async () => {
    if (!source || !destination) return;
    setBusy(true);
    setError(null);
    try {
      await api.createSegmentGrant(networkId, source, destination);
      setSource(undefined);
      setDestination(undefined);
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

  const segmentColumns: TableProps<import('../../api').Segment>['columns'] = [
    { title: t('segments.colName'), key: 'name', render: (_, s) => s.name },
    {
      title: t('segments.colCidr'),
      key: 'cidr',
      render: (_, s) => <code>{s.cidr}</code>,
    },
    {
      title: t('segments.colStatus'),
      key: 'status',
      render: (_, s) => <Tag color={tagColor(s.status)}>{s.status}</Tag>,
    },
  ];

  const grantColumns: TableProps<import('../../api').SegmentGrant>['columns'] = [
    {
      title: t('segments.colGrant'),
      key: 'id',
      render: (_, g) => <code>{g.id}</code>,
    },
    {
      title: t('segments.colDirection'),
      key: 'direction',
      render: (_, g) => (
        <code>
          {g.source_segment_id} → {g.destination_segment_id}
        </code>
      ),
    },
    {
      title: t('segments.colStatus'),
      key: 'status',
      render: (_, g) => <Tag color={tagColor(g.status)}>{g.status}</Tag>,
    },
    {
      title: '',
      key: 'actions',
      render: (_, g) => (
        <>
          {g.status === 'pending' && (
            <Button
              size="small"
              type="link"
              disabled={busy}
              onClick={() => transition('apply', g.id)}
            >
              {t('segments.apply')}
            </Button>
          )}
          {g.status !== 'revoked' && (
            <Button
              size="small"
              type="link"
              danger
              disabled={busy}
              onClick={() => transition('revoke', g.id)}
            >
              {t('segments.revoke')}
            </Button>
          )}
        </>
      ),
    },
  ];

  return (
    <div>
      <h3>{t('segments.title')}</h3>
      <p className="muted">{t('segments.intro')}</p>
      {segments === null || grants === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : (
        <>
          <Table<import('../../api').Segment>
            rowKey="id"
            columns={segmentColumns}
            dataSource={segments}
            size="middle"
            pagination={false}
          />
          {grants.length === 0 ? (
            <p className="muted">{t('segments.none')}</p>
          ) : (
            <Table<import('../../api').SegmentGrant>
              rowKey="id"
              columns={grantColumns}
              dataSource={grants}
              size="middle"
              pagination={false}
            />
          )}
          <Form layout="inline" onFinish={createSegment} className="create-form">
            <Form.Item>
              <Input
                placeholder={t('segments.namePlaceholder')}
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Form.Item>
            <Form.Item>
              <Input
                placeholder={t('segments.cidrPlaceholder')}
                required
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
              />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" disabled={busy}>
                {t('segments.createSegment')}
              </Button>
            </Form.Item>
          </Form>
          <Form layout="inline" onFinish={createGrant} className="create-form">
            <Form.Item label={t('segments.sourceLabel')}>
              <Select
                value={source}
                onChange={setSource}
                placeholder={t('segments.sourceLabel')}
                options={segments.map((s) => ({ value: s.id, label: s.name }))}
                style={{ minWidth: 160 }}
              />
            </Form.Item>
            <Form.Item label={t('segments.destinationLabel')}>
              <Select
                value={destination}
                onChange={setDestination}
                placeholder={t('segments.destinationLabel')}
                options={segments.map((s) => ({ value: s.id, label: s.name }))}
                style={{ minWidth: 160 }}
              />
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                disabled={busy || !source || !destination || segments.length < 2}
              >
                {t('segments.createGrant')}
              </Button>
            </Form.Item>
          </Form>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
