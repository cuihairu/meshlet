import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from './api';
import { RevisionsSection } from './App';
import * as api from './api';

const revision = {
  network_id: 'network-1',
  revision: 1,
  desired_config_hash: 'a'.repeat(64),
  apply_status: 'applied',
  created_at: '2026-01-01T00:00:00Z',
  applied_at: null,
  error_summary: null,
} satisfies api.ConfigRevision;

function convergence(deviceApplyStatus: string) {
  const deviceErrors: Record<string, string> = {};
  if (deviceApplyStatus === 'failed') {
    deviceErrors['device-1'] = 'route rejected';
  }
  return {
    device_apply_status: deviceApplyStatus,
    pending_device_ids: deviceApplyStatus === 'pending' ? ['device-1'] : [],
    device_errors: deviceErrors,
    hub_recovery_error: null,
    business_health: 'not_probed',
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('RevisionsSection', () => {
  it.each([
    [401, 'unauthorized', 'session expired'],
    [500, 'internal', 'database unavailable'],
  ])('renders %i load failures instead of an empty list', async (status, code, message) => {
    vi.spyOn(api.api, 'listRevisions').mockRejectedValue(
      new ApiError(status, code, message),
    );

    render(<RevisionsSection networkId="network-1" />);

    const retry = await screen.findByRole('button', { name: 'Retry' });
    expect(retry).toBeTruthy();
    expect(screen.getByText(new RegExp(`${status} ${code}`))).toBeTruthy();
    expect(screen.queryByText('No config revisions yet.')).toBeNull();
  });

  it('renders a successful empty list as empty', async () => {
    vi.spyOn(api.api, 'listRevisions').mockResolvedValue([]);

    render(<RevisionsSection networkId="network-1" />);

    expect(await screen.findByText('No config revisions yet.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  it('renders device failure without claiming success', async () => {
    vi.spyOn(api.api, 'listRevisions').mockResolvedValue([
      { ...revision, apply_status: 'failed', convergence: convergence('failed') },
    ]);

    render(<RevisionsSection networkId="network-1" />);

    expect(
      await screen.findByText(
        (_, element) => element?.textContent === 'Devices: Apply failed',
      ),
    ).toBeTruthy();
    expect(screen.getByText('device-1: route rejected')).toBeTruthy();
    expect(screen.queryByText('All devices applied')).toBeNull();
  });

  it('polls while devices are pending and stops after convergence', async () => {
    const setInterval = window.setInterval;
    const clearInterval = window.clearInterval;
    let intervalCallback: (() => void) | null = null;
    let intervalCleared = false;
    vi.spyOn(window, 'setInterval').mockImplementation(((callback: () => void) => {
      intervalCallback = callback;
      return 1 as unknown as ReturnType<typeof setInterval>;
    }) as typeof setInterval);
    vi.spyOn(window, 'clearInterval').mockImplementation(((handle: number) => {
      if (handle === 1) intervalCleared = true;
      intervalCallback = null;
      clearInterval(handle);
    }) as typeof clearInterval);

    let pending = true;
    const listRevisions = vi.spyOn(api.api, 'listRevisions').mockImplementation(
      async () => [
        {
          ...revision,
          apply_status: 'applying',
          convergence: convergence(pending ? 'pending' : 'applied'),
        },
      ],
    );

    render(<RevisionsSection networkId="network-1" />);

    await screen.findByText(
      (_, element) => element?.textContent === 'Devices: Waiting for receipts',
    );
    expect(intervalCallback).not.toBeNull();

    expect(listRevisions.mock.calls.length).toBe(1);

    pending = false;
    await act(async () => {
      intervalCallback!();
    });
    expect(listRevisions.mock.calls.length).toBe(2);
    await screen.findByText(
      (_, element) => element?.textContent === 'Devices: All devices applied',
    );
    expect(intervalCleared).toBe(true);
    expect(intervalCallback).toBeNull();
    expect(listRevisions.mock.calls.length).toBe(2);
  });

  it('remounts when the network key changes and ignores the old network response', async () => {
    let resolveNetwork1: (rows: api.ConfigRevision[]) => void = () => {};
    const listRevisions = vi
      .spyOn(api.api, 'listRevisions')
      .mockImplementation((networkId) =>
        networkId === 'network-1'
          ? new Promise((resolve) => {
              resolveNetwork1 = resolve;
            })
          : Promise.resolve([{ ...revision, network_id: 'network-2', revision: 2 }]),
      );

    const { rerender } = render(
      <RevisionsSection key="network-1" networkId="network-1" />,
    );

    rerender(<RevisionsSection key="network-2" networkId="network-2" />);
    await waitFor(() =>
      expect(listRevisions).toHaveBeenNthCalledWith(
        2,
        'network-2',
        expect.any(AbortSignal),
      ),
    );
    const network1Signal = listRevisions.mock.calls[0]?.[1] as AbortSignal;
    expect(network1Signal.aborted).toBe(true);

    await act(async () => {
      resolveNetwork1([{ ...revision, network_id: 'network-1', revision: 1 }]);
      await Promise.resolve();
    });

    expect(await screen.findByText('#2')).toBeTruthy();
    expect(screen.queryByText('#1')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });
});
