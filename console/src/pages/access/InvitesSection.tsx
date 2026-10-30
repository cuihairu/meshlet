import { useState } from 'react';
import { api, ApiError } from '../../api';

export function InvitesSection({ networkId }: { networkId: string }) {
  const [maxUses, setMaxUses] = useState(1);
  const [created, setCreated] = useState<import('../../api').InviteCreated | null>(null);
  const [revoked, setRevoked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
      <h3>Invites</h3>
      <p className="muted">
        The raw token is shown once at creation; the server stores only its SHA-256 digest.
      </p>
      {created && (
        <div className="token-box">
          <p>Invite token (copy now, shown once):</p>
          <code>{created.token}</code>
          {created.invite_id && (
            <button type="button" onClick={() => revoke(created.invite_id)}>
              Revoke this invite
            </button>
          )}
        </div>
      )}
      {revoked && <p className="muted">Invite {revoked} revoked.</p>}
      <div className="inline">
        <label>
          Max uses
          <input
            type="number"
            min={1}
            value={maxUses}
            onChange={(e) => setMaxUses(Number(e.target.value))}
          />
        </label>
        <button type="button" onClick={create} disabled={busy}>
          Create invite
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
