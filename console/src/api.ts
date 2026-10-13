// Meshlet console API client.
// - Cookie session (same-origin); mutating requests carry X-Requested-With (CSRF guard).
// - Errors surface the unified envelope { error: { code, message } }.

export interface Network {
  id: string;
  name: string;
  overlay_cidr: string;
  status: string;
  created_at: string;
}

export interface Device {
  id: string;
  network_id: string;
  name: string;
  virtual_ipv4: string;
  public_key: string;
  fingerprint: string;
  status: string;
  created_at: string;
}

export interface InviteCreated {
  invite_id: string;
  /** Raw token: shown exactly once, the server stores only its digest (§11.3). */
  token: string;
  expires_at: string | null;
}

export interface SessionUser {
  user_id: string;
  email: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      'x-requested-with': 'XMLHttpRequest',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) {
    return undefined as T;
  }
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    throw new ApiError(
      res.status,
      json?.error?.code ?? 'internal',
      json?.error?.message ?? res.statusText,
    );
  }
  return json as T;
}

export const api = {
  me: () => request<SessionUser>('GET', '/auth/me'),
  login: (email: string, password: string) =>
    request<SessionUser>('POST', '/auth/login', { email, password }),
  logout: () => request<void>('POST', '/auth/logout', {}),
  bootstrap: (email: string, password: string) =>
    request<SessionUser>('POST', '/auth/bootstrap', { email, password }),
  listNetworks: () => request<Network[]>('GET', '/networks'),
  createNetwork: (name: string, overlay_cidr: string) =>
    request<Network>('POST', '/networks', { name, overlay_cidr }),
  listDevices: (networkId: string) =>
    request<Device[]>('GET', `/networks/${networkId}/devices`),
  createInvite: (networkId: string, maxUses: number) =>
    request<InviteCreated>('POST', `/networks/${networkId}/invites`, { max_uses: maxUses }),
  revokeInvite: (networkId: string, inviteId: string) =>
    request<void>('DELETE', `/networks/${networkId}/invites/${inviteId}`),
};
