// Meshlet console API client.
// - Cookie session (same-origin); mutating requests carry X-Requested-With (CSRF guard).
// - Errors surface the unified envelope { error: { code, message } }.

export interface Network {
  id: string;
  name: string;
  overlay_cidr: string;
  status: string;
  created_at: string;
  /** Number of the latest recorded config revision (0 = none yet). */
  revision_id: number;
  /** pending | applying | applied | failed | rollback_pending | rolled_back. */
  apply_status: string;
}

export interface ConfigRevision {
  network_id: string;
  revision: number;
  desired_config_hash: string;
  /** pending | applying | applied | failed | rollback_pending | rolled_back. */
  apply_status: string;
  created_at: string;
  /** Set only after a successful apply; null otherwise. */
  applied_at: string | null;
  /** Failure diagnostics (null on success) — a failed apply returns 200, not an error. */
  error_summary: string | null;
}

/** Device-side dataplane readings reported via heartbeat (§7.5); null fields = not read. */
export interface DataplaneEvidence {
  /** Interface MTU reading from `ip link show`. */
  tunnel_mtu: number | null;
  /** Whether ownership-commented meshlet NAT rules exist in the kernel (gateway devices). */
  nat_rules_present: boolean | null;
  /** Whether meshlet SNAT rules exist in the kernel (POSTROUTING chain; distinguishes dnat_snat from dnat_only). */
  nat_snat_rules_present: boolean | null;
  /** Payload size of the successful DF probe (`ping -M do`); null = not verified. */
  mtu_probe_payload: number | null;
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
  /** Last evidence timestamp (enroll / heartbeat / report arrival). */
  last_seen_at: string | null;
  /** online | tunnel_only | offline — a fresh handshake alone is not "online". */
  online_state: string;
  /** agent_report | handshake | enrollment | none — the data source behind the state. */
  presence_source: string;
  /** Last heartbeat dataplane evidence; null = no agent has reported yet. */
  dataplane_evidence: DataplaneEvidence | null;
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

/** Reference to the config revision an operation recorded (server: RevisionRef). */
export interface RevisionRef {
  revision_id: number;
  apply_status: string;
}

export interface LanRoute {
  id: string;
  network_id: string;
  gateway_device_id: string;
  destination_cidr: string;
  /** direct | alias */
  route_mode: string;
  /** dual_route | controlled_snat */
  return_path_mode: string;
  /** pending | applied | failed — desired-state marker, not a live route. */
  status: string;
  revision_id: number;
  apply_status: string;
}

/** Alias mapping (ADR-006): equal-prefix virtual translation of a LAN route. */
export interface AliasMapping {
  id: string;
  network_id: string;
  /** Bound alias-mode route — alias and route are one ownership unit (§12.6). */
  lan_route_id: string;
  /** Virtual prefix (same length as target). */
  alias_cidr: string;
  /** Real LAN prefix — derived server-side from the bound route, never set by the client. */
  target_cidr: string;
  /** dnat_snat | dnat_only. */
  translation_mode: string;
  /** pending | applied | failed — desired-state marker. */
  status: string;
  revision_id: number;
  apply_status: string;
}

/** One of the 13 network diagnostics checks (§12.7). */
export interface DiagnosticCheck {
  id: string;
  name: string;
  /** control_plane | tunnel | routing | forwarding | alias — fault layer. */
  layer: string;
  /** pass | fail | warning | unavailable | not_applicable. */
  status: string;
  detail: string;
  /** Actionable local step (empty when the server cannot act on this check). */
  suggestion: string;
}

/** Latest persisted diagnostics snapshot for a network (§12.7). */
export interface DiagnosticsReport {
  network_id: string;
  checked_at: string;
  checks: DiagnosticCheck[];
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
  revokeDevice: (networkId: string, deviceId: string) =>
    request<RevisionRef>(
      'POST',
      `/networks/${networkId}/devices/${deviceId}/revoke`,
    ),
  listRevisions: (networkId: string) =>
    request<ConfigRevision[]>('GET', `/networks/${networkId}/config-revisions`),
  applyRevision: (networkId: string, revision: number) =>
    request<ConfigRevision>(
      'POST',
      `/networks/${networkId}/config-revisions/${revision}/apply`,
    ),
  rollbackRevision: (networkId: string, revision: number) =>
    request<ConfigRevision>(
      'POST',
      `/networks/${networkId}/config-revisions/${revision}/rollback`,
    ),
  listRoutes: (networkId: string) =>
    request<LanRoute[]>('GET', `/networks/${networkId}/routes`),
  createRoute: (
    networkId: string,
    gateway_device_id: string,
    destination_cidr: string,
    return_path_mode: string,
    /** direct (default) | alias — alias mode marks the route as translated (§5). */
    route_mode?: string,
  ) =>
    request<LanRoute>('POST', `/networks/${networkId}/routes`, {
      gateway_device_id,
      destination_cidr,
      return_path_mode,
      ...(route_mode ? { route_mode } : {}),
    }),
  deleteRoute: (networkId: string, routeId: string) =>
    request<void>('DELETE', `/networks/${networkId}/routes/${routeId}`),
  listAliases: (networkId: string) =>
    request<AliasMapping[]>('GET', `/networks/${networkId}/aliases`),
  createAlias: (
    networkId: string,
    lan_route_id: string,
    alias_cidr: string,
    translation_mode?: string,
  ) =>
    request<AliasMapping>('POST', `/networks/${networkId}/aliases`, {
      lan_route_id,
      alias_cidr,
      ...(translation_mode ? { translation_mode } : {}),
    }),
  /** Removes the mapping AND its bound route in one revision (§12.6). */
  deleteAlias: (networkId: string, aliasId: string) =>
    request<void>('DELETE', `/networks/${networkId}/aliases/${aliasId}`),
  /** Latest persisted diagnostics snapshot; 404 when never run. */
  getDiagnostics: (networkId: string) =>
    request<DiagnosticsReport>('GET', `/networks/${networkId}/diagnostics`),
  /** Run the 13 checks now and persist the snapshot. */
  runDiagnostics: (networkId: string) =>
    request<DiagnosticsReport>('POST', `/networks/${networkId}/diagnostics`, {}),
};
