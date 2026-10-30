import { useState } from 'react';
import { Button, Form, InputNumber } from 'antd';
import { api, ApiError } from '../../api';
import { useLanguage } from '../../i18n/language-context';

export function InvitesSection({ networkId }: { networkId: string }) {
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<import('../../api').InviteCreated | null>(null);
  const [revoked, setRevoked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { t } = useLanguage();

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
      <h3>{t('invites.title')}</h3>
      <p className="muted">{t('invites.intro')}</p>
      {created && (
        <div className="token-box">
          <p>{t('invites.reveal')}</p>
          <code>{created.token}</code>
          {created.invite_id && (
            <div>
              <Button size="small" onClick={() => revoke(created.invite_id!)}>
                {t('invites.revokeThis')}
              </Button>
            </div>
          )}
        </div>
      )}
      {revoked && <p className="muted">{t('invites.revoked', { id: revoked })}</p>}
      <Form layout="inline" onFinish={create} className="create-form">
        <Form.Item label={t('invites.maxUsesLabel')}>
          <InputNumber
            min={1}
            value={maxUses}
            onChange={(v) => setMaxUses(v ?? 1)}
          />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={busy}>
            {t('invites.create')}
          </Button>
        </Form.Item>
      </Form>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
