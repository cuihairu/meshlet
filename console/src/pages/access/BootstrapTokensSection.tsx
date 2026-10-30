import { useCallback, useEffect, useState } from 'react';
import { Button, Checkbox, Form, InputNumber, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import {
  api,
  ApiError,
  type BootstrapToken,
  type BootstrapTokenCreated,
} from '../../api';
import { useLanguage } from '../../i18n/language-context';
import { formatTime } from '../../lib/format';

/**
 * Bootstrap tokens: long-lived, reusable self-registration credentials, unlike
 * one-shot invites. The raw token is revealed exactly once at creation (the
 * server stores only its SHA-256 digest), so the one-time reveal box is the
 * only chance to copy it. Revocation is immediate — already-registered devices
 * keep their own agent credential.
 */
export function BootstrapTokensSection({ networkId }: { networkId: string }) {
  const [tokens, setTokens] = useState<BootstrapToken[] | null>(null);
  // Unchecked limit = unlimited: max_uses is omitted from the body entirely.
  const [unlimited, setUnlimited] = useState(true);
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<BootstrapTokenCreated | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

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

  const columns: TableProps<BootstrapToken>['columns'] = [
    {
      title: t('bootstrap.colId'),
      key: 'id',
      render: (_, tk) => <code>{tk.id}</code>,
    },
    {
      title: t('bootstrap.colMaxUses'),
      key: 'max_uses',
      render: (_, tk) => (tk.max_uses === null ? t('bootstrap.unlimited') : tk.max_uses),
    },
    {
      title: t('bootstrap.colUsed'),
      key: 'used_count',
      render: (_, tk) => tk.used_count,
    },
    {
      title: t('bootstrap.colCreated'),
      key: 'created_at',
      render: (_, tk) => formatTime(tk.created_at),
    },
    {
      title: t('bootstrap.colStatus'),
      key: 'status',
      render: (_, tk) =>
        tk.revoked_at ? (
          <Tag color="error">{t('bootstrap.revoked')}</Tag>
        ) : (
          <Tag color="success">{t('bootstrap.active')}</Tag>
        ),
    },
    {
      title: '',
      key: 'actions',
      render: (_, tk) =>
        tk.revoked_at ? (
          <span className="muted">—</span>
        ) : confirming === tk.id ? (
          <>
            <Button size="small" danger loading={busy} onClick={() => revoke(tk.id)}>
              {t('bootstrap.confirmRevoke')}
            </Button>{' '}
            <Button size="small" type="link" onClick={() => setConfirming(null)}>
              {t('bootstrap.cancel')}
            </Button>
          </>
        ) : (
          <Button
            size="small"
            type="link"
            onClick={() => {
              setConfirming(tk.id);
              setError(null);
            }}
          >
            {t('bootstrap.revoke')}
          </Button>
        ),
    },
  ];

  return (
    <div>
      <h3>{t('bootstrap.title')}</h3>
      <p className="muted">{t('bootstrap.intro')}</p>
      {created && (
        <div className="token-box">
          <p>{t('bootstrap.reveal')}</p>
          <code>{created.token}</code>
        </div>
      )}
      {tokens === null ? (
        <p className="muted">{t('app.loading')}</p>
      ) : tokens.length === 0 ? (
        <p className="muted">{t('bootstrap.none')}</p>
      ) : (
        <Table<BootstrapToken>
          rowKey="id"
          columns={columns}
          dataSource={tokens}
          size="middle"
          pagination={false}
        />
      )}
      <Form layout="inline" onFinish={create} className="create-form">
        <Form.Item label={t('bootstrap.maxUsesLabel')}>
          <InputNumber
            min={1}
            value={unlimited ? null : maxUses}
            disabled={unlimited}
            onChange={(v) => setMaxUses(v ?? 1)}
          />
        </Form.Item>
        <Form.Item>
          <Checkbox
            checked={unlimited}
            onChange={(e) => setUnlimited(e.target.checked)}
          >
            {t('bootstrap.unlimitedLabel')}
          </Checkbox>
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={busy}>
            {t('bootstrap.create')}
          </Button>
        </Form.Item>
      </Form>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
