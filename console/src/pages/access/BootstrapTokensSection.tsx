import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../../api';
import { formatTime } from '../../lib/format';


/**
 * Bootstrap tokens: long-lived, reusable self-registration credentials, unlike
 * one-shot invites. The raw token is revealed exactly once at creation (the
 * server stores only its SHA-256 digest), so the one-time reveal box is the
 * only chance to copy it. Revocation is immediate — already-registered devices
 * keep their own agent credential.
 */
export function BootstrapTokensSection({ networkId }: { networkId: string }) {
  const [tokens, setTokens] = useState<import('../../api').BootstrapToken[] | null>(null);
  // Unchecked limit = unlimited: max_uses is omitted from the body entirely.
  const [unlimited, setUnlimited] = useState(true);
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<import('../../api').BootstrapTokenCreated | null>(null);
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
