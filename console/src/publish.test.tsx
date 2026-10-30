import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { PublishSection } from './pages/diagnostics/PublishSection';

const device: api.Device = {
  id: 'dev-1',
  network_id: 'net-1',
  name: 'vps-agent',
  virtual_ipv4: '10.240.0.2',
  public_key: 'pk',
  fingerprint: 'fp',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  last_seen_at: null,
  online_state: 'online',
  presence_source: 'agent_report',
  dataplane_evidence: null,
  approved_at: '2026-01-01T00:00:00Z',
};

const published: api.PublishForward = {
  id: 'pf-1',
  network_id: 'net-1',
  device_id: 'dev-1',
  protocol: 'tcp',
  listener_address: '0.0.0.0:18080',
  backend_address: '127.0.0.1:18081',
  allowed_source_cidrs: ['10.0.0.0/8'],
  allowed_bearer_token_count: 1,
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
  revision_id: 1,
};

/** Devices plus the four publish lists, all resolved; per-test overrides win. */
function mockLists(overrides: {
  forwards?: api.PublishForward[];
  routes?: api.PublishHttpRoute[];
  probes?: api.PublishProbe[];
  dns?: api.PublishDnsRecord[];
} = {}) {
  return {
    listDevices: vi.spyOn(api.api, 'listDevices').mockResolvedValue([device]),
    listPublishForwards: vi
      .spyOn(api.api, 'listPublishForwards')
      .mockResolvedValue(overrides.forwards ?? []),
    listPublishHttpRoutes: vi
      .spyOn(api.api, 'listPublishHttpRoutes')
      .mockResolvedValue(overrides.routes ?? []),
    listPublishProbes: vi
      .spyOn(api.api, 'listPublishProbes')
      .mockResolvedValue(overrides.probes ?? []),
    listPublishDnsRecords: vi
      .spyOn(api.api, 'listPublishDnsRecords')
      .mockResolvedValue(overrides.dns ?? []),
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/** antd Select is a combobox: open it (mousedown) then click the option. */
async function selectAntd(label: string, optionTitle: string) {
  fireEvent.mouseDown(screen.getByLabelText(label));
  const option = await screen.findByTitle(optionTitle);
  fireEvent.click(option);
}

describe('PublishSection', () => {
  it('renders an empty publish section as four explicit empty states', async () => {
    mockLists();

    render(<PublishSection networkId="net-1" />);

    expect(await screen.findByText('No published ports.')).toBeTruthy();
    expect(screen.getByText('No HTTP routes.')).toBeTruthy();
    expect(screen.getByText('No probes.')).toBeTruthy();
    expect(screen.getByText('No internal DNS records.')).toBeTruthy();
  });

  it('publishes a port forward from the form and never echoes the token', async () => {
    mockLists();
    // First load sees nothing; the reload after the create sees the row.
    vi.mocked(api.api.listPublishForwards)
      .mockResolvedValueOnce([])
      .mockResolvedValue([published]);
    const create = vi
      .spyOn(api.api, 'createPublishForward')
      .mockResolvedValue(published);

    render(<PublishSection networkId="net-1" />);
    await screen.findByText('No published ports.');

    await selectAntd('publish device', 'vps-agent');
    fireEvent.change(screen.getByLabelText('forward listener port'), {
      target: { value: '18080' },
    });
    fireEvent.change(screen.getByLabelText('forward backend port'), {
      target: { value: '18081' },
    });
    fireEvent.change(screen.getByLabelText('forward allowed source CIDRs'), {
      target: { value: '10.0.0.0/8, 172.16.0.0/12' },
    });
    fireEvent.change(screen.getByLabelText('forward bearer token'), {
      target: { value: 'sekret' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Publish port' }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        'net-1',
        expect.objectContaining({
          device_id: 'dev-1',
          protocol: 'tcp',
          listener_address: '0.0.0.0:18080',
          backend_address: '127.0.0.1:18081',
          allowed_source_cidrs: ['10.0.0.0/8', '172.16.0.0/12'],
          allowed_bearer_tokens: ['sekret'],
          enabled: true,
        }),
      ),
    );

    // The reload renders the row with the token COUNT only — the raw token
    // stays on the create form and never reaches the list view.
    const row = await screen.findByText('0.0.0.0:18080');
    expect(row).toBeTruthy();
    expect(create.mock.results.length).toBe(1);
    expect(screen.queryByText('sekret')).toBeNull();
    expect(screen.getAllByText('1').length).toBeGreaterThan(0);
  });

  it('blocks the submit locally when a port is not a number', async () => {
    mockLists();
    const create = vi.spyOn(api.api, 'createPublishForward').mockResolvedValue(
      published,
    );

    render(<PublishSection networkId="net-1" />);
    await screen.findByText('No published ports.');

    await selectAntd('publish device', 'vps-agent');
    fireEvent.change(screen.getByLabelText('forward listener port'), {
      target: { value: 'not-a-port' },
    });
    fireEvent.change(screen.getByLabelText('forward backend port'), {
      target: { value: '18081' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Publish port' }));

    // antd Form fires onFinish asynchronously (after field validation), so
    // wait for the locally-rendered validation error instead of asserting sync.
    expect(
      await screen.findByText(
        'Listener and backend must each be a host plus a port 1-65535.',
      ),
    ).toBeTruthy();
    expect(create).not.toHaveBeenCalled();
  });

  it('surfaces a duplicate route as a conflict without claiming success', async () => {
    mockLists();
    vi.spyOn(api.api, 'createPublishHttpRoute').mockRejectedValue(
      new api.ApiError(409, 'conflict', 'duplicate http route'),
    );

    render(<PublishSection networkId="net-1" />);
    await screen.findByText('No HTTP routes.');

    await selectAntd('http route device', 'vps-agent');
    fireEvent.change(screen.getByPlaceholderText('hostname'), {
      target: { value: 'app.mesh.internal' },
    });
    fireEvent.change(screen.getByLabelText('route backend port'), {
      target: { value: '18082' },
    });
    fireEvent.change(screen.getByLabelText('route listener port'), {
      target: { value: '18090' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Publish route' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Publishing conflict — nothing was published.');
    expect(alert.textContent).toContain('duplicate http route');
  });

  it('records an HTTP probe with path and expected status', async () => {
    mockLists();
    const create = vi
      .spyOn(api.api, 'createPublishProbe')
      .mockResolvedValue({
        id: 'pb-1',
        network_id: 'net-1',
        device_id: 'dev-1',
        target_kind: 'http',
        address: '127.0.0.1:18082',
        path: '/',
        expected_status: 200,
        timeout_secs: 3,
        interval_secs: 30,
        enabled: true,
        last_state: null,
        last_checked_at: null,
        last_detail: null,
        created_at: '2026-01-01T00:00:00Z',
        revision_id: 2,
      });

    render(<PublishSection networkId="net-1" />);
    await screen.findByText('No probes.');

    await selectAntd('probe device', 'vps-agent');
    await selectAntd('probe kind', 'http');
    fireEvent.change(screen.getByPlaceholderText('host:port'), {
      target: { value: '127.0.0.1:18082' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add probe' }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        'net-1',
        expect.objectContaining({
          device_id: 'dev-1',
          target_kind: 'http',
          address: '127.0.0.1:18082',
          path: '/',
          expected_status: 200,
          timeout_secs: 3,
          interval_secs: 30,
        }),
      ),
    );
  });

  it('records a TCP probe with no path and no expected status', async () => {
    mockLists();
    const create = vi.spyOn(api.api, 'createPublishProbe').mockResolvedValue({
      id: 'pb-2',
      network_id: 'net-1',
      device_id: 'dev-1',
      target_kind: 'tcp',
      address: '127.0.0.1:18081',
      path: null,
      expected_status: null,
      timeout_secs: 3,
      interval_secs: 15,
      enabled: true,
      last_state: null,
      last_checked_at: null,
      last_detail: null,
      created_at: '2026-01-01T00:00:00Z',
      revision_id: 3,
    });

    render(<PublishSection networkId="net-1" />);
    await screen.findByText('No probes.');

    await selectAntd('probe device', 'vps-agent');
    fireEvent.change(screen.getByPlaceholderText('host:port'), {
      target: { value: '127.0.0.1:18081' },
    });
    fireEvent.change(screen.getByLabelText('probe interval seconds'), {
      target: { value: '15' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add probe' }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        'net-1',
        expect.objectContaining({
          target_kind: 'tcp',
          path: null,
          expected_status: null,
        }),
      ),
    );
  });

  it('adds an internal DNS answer for the requested suffix', async () => {
    mockLists();
    const create = vi.spyOn(api.api, 'createPublishDnsRecord').mockResolvedValue({
      id: 'dn-1',
      network_id: 'net-1',
      device_id: 'dev-1',
      name: 'app.mesh.internal',
      address: '10.240.0.5',
      ttl: 300,
      priority: 1,
      bind_address: '0.0.0.0:15353',
      internal_suffix: 'mesh.internal',
      created_at: '2026-01-01T00:00:00Z',
      revision_id: 4,
    });

    render(<PublishSection networkId="net-1" />);
    await screen.findByText('No internal DNS records.');

    await selectAntd('dns device', 'vps-agent');
    fireEvent.change(screen.getByPlaceholderText('service name'), {
      target: { value: 'app' },
    });
    fireEvent.change(screen.getByPlaceholderText('IPv4 address'), {
      target: { value: '10.240.0.5' },
    });
    fireEvent.change(screen.getByLabelText('dns bind port'), {
      target: { value: '15353' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add record' }));

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith(
        'net-1',
        expect.objectContaining({
          name: 'app',
          address: '10.240.0.5',
          ttl: 300,
          priority: 1,
          bind_address: '0.0.0.0:15353',
          internal_suffix: 'mesh.internal',
        }),
      ),
    );
  });

  it('deletes a forward only after the confirm step', async () => {
    mockLists({ forwards: [published] });
    const remove = vi.spyOn(api.api, 'deletePublishForward').mockResolvedValue(
      undefined,
    );

    render(<PublishSection networkId="net-1" />);
    const row = await screen.findByText('0.0.0.0:18080');
    expect(row).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(remove).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith('net-1', 'pf-1'));
  });
});
