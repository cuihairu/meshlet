import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { SegmentGrantsSection } from './pages/access/SegmentGrantsSection';

const segments: api.Segment[] = [
  {
    id: 'segment-1',
    network_id: 'network-1',
    name: 'default',
    cidr: '10.240.0.0/16',
    status: 'active',
    created_at: '2026-01-01T00:00:00Z',
    revision_id: 1,
  },
  {
    id: 'segment-2',
    network_id: 'network-1',
    name: 'lab',
    cidr: '10.240.1.0/24',
    status: 'active',
    created_at: '2026-01-01T00:00:00Z',
    revision_id: 2,
  },
];

const grants: api.SegmentGrant[] = [
  {
    id: 'grant-1',
    network_id: 'network-1',
    source_segment_id: 'segment-1',
    destination_segment_id: 'segment-2',
    status: 'pending',
    created_at: '2026-01-01T00:00:00Z',
    revoked_at: null,
    revision_id: 3,
    apply_status: 'pending',
  },
];

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('SegmentGrantsSection', () => {
  it('renders segment rows and pending grant actions', async () => {
    vi.spyOn(api.api, 'listSegments').mockResolvedValue(segments);
    vi.spyOn(api.api, 'listSegmentGrants').mockResolvedValue(grants);

    render(<SegmentGrantsSection networkId="network-1" />);

    expect((await screen.findAllByText('lab')).length).toBeGreaterThan(0);
    expect(screen.getByText(/segment-1 → segment-2/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Apply' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeTruthy();
  });

  it('renders successful empty grant state separately from load errors', async () => {
    vi.spyOn(api.api, 'listSegments').mockResolvedValue(segments);
    vi.spyOn(api.api, 'listSegmentGrants').mockResolvedValue([]);

    render(<SegmentGrantsSection networkId="network-1" />);

    expect(await screen.findByText('No segment grants.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Apply' })).toBeNull();
  });
});
